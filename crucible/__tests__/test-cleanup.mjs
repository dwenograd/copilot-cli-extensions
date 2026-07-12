import fs from "node:fs";

const TRANSIENT_WINDOWS_REMOVE_CODES = new Set([
    "EACCES",
    "EBUSY",
    "ENOTEMPTY",
    "EPERM",
]);

function wait(delayMs) {
    return new Promise((resolve) => setTimeout(resolve, delayMs));
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
            await wait(delayMs);
            delayMs = Math.min(delayMs * 2, 500);
        }
    }
    throw new Error(
        `${label} cleanup failed and the path remains on disk: ${root}`,
        { cause: lastError },
    );
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
