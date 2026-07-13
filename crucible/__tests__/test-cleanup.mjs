import fs from "node:fs";
import path from "node:path";

const TRANSIENT_WINDOWS_REMOVE_CODES = new Set([
    "EACCES",
    "EBUSY",
    "ENOTEMPTY",
    "EPERM",
]);

function wait(delayMs) {
    return new Promise((resolve) => setTimeout(resolve, delayMs));
}

function makeTreeWritable(root) {
    const directories = [];
    const stack = [root];
    while (stack.length > 0) {
        const current = stack.pop();
        let stat;
        try {
            stat = fs.lstatSync(current);
        } catch {
            continue;
        }
        if (!stat.isDirectory() || stat.isSymbolicLink()) {
            try {
                fs.chmodSync(current, 0o600);
            } catch {
                // The retry loop retains the original removal error.
            }
            continue;
        }
        directories.push(current);
        let names = [];
        try {
            names = fs.readdirSync(current);
        } catch {
            // The directory chmod below may make the next retry succeed.
        }
        for (const name of names) {
            stack.push(path.join(current, name));
        }
    }
    for (const directory of directories.reverse()) {
        try {
            fs.chmodSync(directory, 0o700);
        } catch {
            // Best effort before the bounded retry.
        }
    }
}

export async function removeTreeRobust(
    root,
    {
        label = "test root",
        timeoutMs = 15_000,
    } = {},
) {
    if (!root || !fs.existsSync(root)) return;
    const deadline = Date.now() + timeoutMs;
    let delayMs = 25;
    let lastError = null;
    while (Date.now() <= deadline) {
        try {
            fs.rmSync(root, {
                recursive: true,
                force: true,
                maxRetries: 8,
                retryDelay: 25,
            });
            if (!fs.existsSync(root)) return;
            const error = new Error(`${label} still exists after recursive removal`);
            error.code = "ENOTEMPTY";
            throw error;
        } catch (error) {
            lastError = error;
            if (!TRANSIENT_WINDOWS_REMOVE_CODES.has(error?.code)
                || Date.now() >= deadline) {
                break;
            }
            makeTreeWritable(root);
            await wait(delayMs);
            delayMs = Math.min(delayMs * 2, 500);
        }

    }
    throw new Error(
        `${label} cleanup failed and the path remains on disk: ${root}`,
        { cause: lastError },
    );
}

export async function removeStaleTestRoots(
    parent,
    prefixes,
    {
        label = "stale test root",
        olderThanMs = 5 * 60_000,
        timeoutMs = 30_000,
    } = {},
) {
    if (!fs.existsSync(parent)) return;
    const normalizedPrefixes = Array.isArray(prefixes)
        ? prefixes
        : [prefixes];
    const cutoff = Date.now() - olderThanMs;
    const stale = fs.readdirSync(parent, { withFileTypes: true })
        .filter((entry) =>
            entry.isDirectory()
            && normalizedPrefixes.some((prefix) =>
                entry.name.startsWith(prefix)))
        .map((entry) => path.join(parent, entry.name))
        .filter((root) => {
            try {
                return fs.statSync(root).mtimeMs <= cutoff;
            } catch {
                return false;
            }
        });
    const failures = [];
    for (const root of stale) {
        try {
            await removeTreeRobust(root, { label, timeoutMs });
        } catch (error) {
            failures.push(error);
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            `${label} cleanup failed`,
        );
    }
}

export async function removeTrackedRoots(
    roots,
    {
        label = "test root",
        timeoutMs = 15_000,
    } = {},
) {
    const failures = [];
    for (const root of roots.splice(0)) {
        try {
            await removeTreeRobust(root, { label, timeoutMs });
        } catch (error) {
            failures.push(error);
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, `${label} cleanup failed`);
    }
}
