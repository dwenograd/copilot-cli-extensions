import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    recoveryDaemonPublicSummary,
    runRecoveryDaemon,
} from "./recovery-daemon.mjs";

const HASH_RE = /^sha256:[a-f0-9]{64}$/u;
const SELF_PATH = fileURLToPath(import.meta.url);

function parseInteger(value, flag) {
    if (!/^[0-9]+$/u.test(value ?? "")) {
        throw new TypeError(`${flag} requires a positive integer`);
    }
    return Number(value);
}

export function parseRecoveryDaemonArgv(argv) {
    const options = {
        once: false,
        stateRoot: null,
        intervalMs: undefined,
        leaseTtlMs: undefined,
        heartbeatMs: undefined,
        expectedNodeSha256: null,
        expectedDaemonSha256: null,
    };
    for (let index = 0; index < argv.length; index += 1) {
        const flag = argv[index];
        if (flag === "--once") {
            options.once = true;
            continue;
        }
        const value = argv[index + 1];
        if (value === undefined) {
            throw new TypeError(`${flag} requires a value`);
        }
        index += 1;
        if (flag === "--state-root") {
            options.stateRoot = value;
        } else if (flag === "--interval-ms") {
            options.intervalMs = parseInteger(value, flag);
        } else if (flag === "--lease-ttl-ms") {
            options.leaseTtlMs = parseInteger(value, flag);
        } else if (flag === "--heartbeat-ms") {
            options.heartbeatMs = parseInteger(value, flag);
        } else if (flag === "--expected-node-sha256") {
            options.expectedNodeSha256 = value;
        } else if (flag === "--expected-daemon-sha256") {
            options.expectedDaemonSha256 = value;
        } else {
            throw new TypeError(`unknown recovery daemon flag ${flag}`);
        }
    }
    if (typeof options.stateRoot !== "string"
        || !path.isAbsolute(options.stateRoot)) {
        throw new TypeError("--state-root must be an absolute path");
    }
    const hasNodeHash = options.expectedNodeSha256 !== null;
    const hasDaemonHash = options.expectedDaemonSha256 !== null;
    if (hasNodeHash !== hasDaemonHash) {
        throw new TypeError(
            "expected Node and daemon hashes must be supplied together",
        );
    }
    if (!options.once && !hasNodeHash) {
        throw new TypeError(
            "continuous recovery requires expected Node and daemon hashes",
        );
    }
    for (const [field, value] of [
        ["--expected-node-sha256", options.expectedNodeSha256],
        ["--expected-daemon-sha256", options.expectedDaemonSha256],
    ]) {
        if (value !== null && !HASH_RE.test(value)) {
            throw new TypeError(`${field} must be sha256:<64 lowercase hex>`);
        }
    }
    return Object.freeze(options);
}

function sha256File(file) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error("recovery runtime identity must be a regular file");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    const fd = fs.openSync(file, "r");
    try {
        for (;;) {
            const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
            if (bytes === 0) break;
            hash.update(buffer.subarray(0, bytes));
        }
    } finally {
        fs.closeSync(fd);
    }
    return `sha256:${hash.digest("hex")}`;
}

export function verifyRecoveryDaemonRuntime({
    expectedNodeSha256,
    expectedDaemonSha256,
    nodePath = process.execPath,
    daemonPath = SELF_PATH,
} = {}) {
    if (expectedNodeSha256 === null && expectedDaemonSha256 === null) {
        return Object.freeze({ verified: false });
    }
    const actualNodeSha256 = sha256File(nodePath);
    const actualDaemonSha256 = sha256File(daemonPath);
    if (actualNodeSha256 !== expectedNodeSha256
        || actualDaemonSha256 !== expectedDaemonSha256) {
        throw new Error(
            "recovery daemon executable identity differs from the installed task",
        );
    }
    return Object.freeze({
        verified: true,
        nodeSha256: actualNodeSha256,
        daemonSha256: actualDaemonSha256,
    });
}

export async function mainRecoveryDaemonCli(
    argv = process.argv.slice(2),
    dependencies = {},
) {
    try {
        const options = parseRecoveryDaemonArgv(argv);
        verifyRecoveryDaemonRuntime({
            expectedNodeSha256: options.expectedNodeSha256,
            expectedDaemonSha256: options.expectedDaemonSha256,
            nodePath: dependencies.nodePath ?? process.execPath,
            daemonPath: dependencies.daemonPath ?? SELF_PATH,
        });
        const abortController = new AbortController();
        const signalSource = dependencies.signalSource ?? process;
        const handlers = [];
        for (const name of ["SIGINT", "SIGTERM"]) {
            const handler = () => abortController.abort();
            signalSource.on?.(name, handler);
            handlers.push([name, handler]);
        }
        try {
            const result = await (
                dependencies.runRecoveryDaemon ?? runRecoveryDaemon
            )({
                stateRoot: options.stateRoot,
                once: options.once,
                intervalMs: options.intervalMs,
                leaseTtlMs: options.leaseTtlMs,
                heartbeatMs: options.heartbeatMs,
                env: dependencies.env ?? process.env,
                signal: abortController.signal,
            }, dependencies.daemonDependencies ?? {});
            const summary = recoveryDaemonPublicSummary(result);
            if (options.once) {
                dependencies.stdout?.write?.(`${JSON.stringify(summary)}\n`);
            }
            return {
                exitCode: 0,
                summary,
            };
        } finally {
            for (const [name, handler] of handlers) {
                signalSource.off?.(name, handler);
            }
        }
    } catch (error) {
        const failure = {
            ok: false,
            state: "failed",
            code: error?.code ?? "RECOVERY_DAEMON_FAILED",
        };
        dependencies.stderr?.write?.(`${JSON.stringify(failure)}\n`);
        return {
            exitCode: error instanceof TypeError ? 64 : 1,
            summary: failure,
        };
    }
}

const isEntrypoint = process.argv[1] !== undefined
    && path.resolve(process.argv[1]) === SELF_PATH;

if (isEntrypoint) {
    const { exitCode } = await mainRecoveryDaemonCli(
        process.argv.slice(2),
        {
            stdout: process.stdout,
            stderr: process.stderr,
        },
    );
    process.exitCode = exitCode;
}
