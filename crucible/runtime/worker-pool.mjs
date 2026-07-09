import path from "node:path";
import { pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";

import { hashCanonical, immutableCanonical } from "../domain/index.mjs";
import { assertLocalDatabasePath } from "../persistence/index.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    WorkerProtocolError,
} from "./errors.mjs";
import {
    ensureDirectory,
    requireAbsolutePath,
    requireIdentifier,
    requirePlainObject,
    requireString,
} from "./utils.mjs";

export const SUBMIT_CANDIDATE_TOOL_NAME = "crucible_submit_candidate";

export const DEFAULT_CANDIDATE_LIMITS = Object.freeze({
    maxFiles: 32,
    maxPathBytes: 512,
    maxMechanismBytes: 16 * 1024,
    maxFileBytes: 256 * 1024,
    maxTotalBytes: 1024 * 1024,
});

const WINDOWS_RESERVED_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;
const PATH_CONTROL = /[\u0000-\u001f\u007f]/u;

function protocolError(code, message, details) {
    return new WorkerProtocolError(code, message, details);
}

function hasUnpairedSurrogate(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) {
                return true;
            }
            index += 1;
        } else if (code >= 0xdc00 && code <= 0xdfff) {
            return true;
        }
    }
    return false;
}

function normalizeLimits(input = {}) {
    requirePlainObject(input, "candidateLimits");
    const output = { ...DEFAULT_CANDIDATE_LIMITS };
    for (const key of Object.keys(input)) {
        if (!Object.hasOwn(output, key)) {
            throw new RuntimeConfigError(`candidateLimits has unknown key ${JSON.stringify(key)}`);
        }
        const hardMaximum = DEFAULT_CANDIDATE_LIMITS[key];
        if (!Number.isSafeInteger(input[key]) || input[key] < 1 || input[key] > hardMaximum) {
            throw new RuntimeConfigError(
                `candidateLimits.${key} must be a positive safe integer <= ${hardMaximum}`,
            );
        }
        output[key] = input[key];
    }
    if (output.maxFileBytes > output.maxTotalBytes) {
        throw new RuntimeConfigError("candidateLimits.maxFileBytes cannot exceed maxTotalBytes");
    }
    return Object.freeze(output);
}

function normalizeRelativeFilePath(rawPath, limits) {
    if (typeof rawPath !== "string"
        || rawPath.length === 0
        || Buffer.byteLength(rawPath, "utf8") > limits.maxPathBytes
        || PATH_CONTROL.test(rawPath)
        || hasUnpairedSurrogate(rawPath)) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            "Candidate file path is empty, oversized, or contains control characters",
            { path: typeof rawPath === "string" ? rawPath : null },
        );
    }
    if (path.isAbsolute(rawPath)
        || /^[A-Za-z]:/u.test(rawPath)
        || rawPath.startsWith("\\\\")
        || rawPath.startsWith("//")
        || rawPath.includes(":")) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            "Candidate file paths must be relative and cannot contain drive, UNC, or ADS syntax",
            { path: rawPath },
        );
    }
    const normalized = rawPath.replaceAll("\\", "/").normalize("NFC");
    if (Buffer.byteLength(normalized, "utf8") > limits.maxPathBytes) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            "Normalized candidate file path exceeds the path byte cap",
            { path: rawPath },
        );
    }
    const segments = normalized.split("/");
    if (segments.some((segment) =>
        segment.length === 0
        || segment === "."
        || segment === ".."
        || /[<>:"|?*]/u.test(segment)
        || segment.endsWith(".")
        || segment.endsWith(" ")
        || WINDOWS_RESERVED_NAME.test(segment))) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            "Candidate file path contains an unsafe segment",
            { path: rawPath },
        );
    }
    return segments.join("/");
}

export function validateCandidateSubmission(args, options = {}) {
    const limits = normalizeLimits(options.limits ?? {});
    const expectedChallenge = requireString(options.challengeNonce, "challengeNonce", { max: 512 });
    const allowedCandidateIds = new Set(options.allowedCandidateIds ?? []);
    if (allowedCandidateIds.size === 0) {
        throw new RuntimeConfigError("allowedCandidateIds must contain at least one candidate id");
    }

    if (args === null || typeof args !== "object" || Array.isArray(args)) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            "crucible_submit_candidate arguments must be an object",
        );
    }
    const allowedKeys = new Set(["challenge", "candidateId", "mechanism", "files"]);
    for (const key of Object.keys(args)) {
        if (!allowedKeys.has(key)) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                `crucible_submit_candidate has unknown field ${JSON.stringify(key)}`,
            );
        }
    }
    if (args.challenge !== expectedChallenge) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_WRONG_NONCE,
            "Candidate submission challenge nonce does not match",
        );
    }
    let candidateId;
    try {
        candidateId = requireIdentifier(args.candidateId, "candidateId");
    } catch (error) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            error.message,
            error.details,
        );
    }
    if (!allowedCandidateIds.has(candidateId)) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            "Candidate id is outside the worker's assigned set",
            { candidateId, allowedCandidateIds: [...allowedCandidateIds] },
        );
    }
    if (typeof args.mechanism !== "string"
        || args.mechanism.trim().length === 0
        || Buffer.byteLength(args.mechanism, "utf8") > limits.maxMechanismBytes
        || args.mechanism.includes("\u0000")
        || hasUnpairedSurrogate(args.mechanism)) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            "Candidate mechanism must be non-empty, bounded text without NUL",
        );
    }
    if (!Array.isArray(args.files)
        || args.files.length === 0
        || args.files.length > limits.maxFiles) {
        throw protocolError(
            RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            `Candidate files must contain 1..${limits.maxFiles} entries`,
        );
    }

    const seenPaths = new Set();
    const files = [];
    let totalBytes = Buffer.byteLength(candidateId, "utf8")
        + Buffer.byteLength(args.mechanism, "utf8")
        + Buffer.byteLength(args.challenge, "utf8");
    for (const [index, file] of args.files.entries()) {
        if (file === null || typeof file !== "object" || Array.isArray(file)) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                `files[${index}] must be an object`,
            );
        }
        const keys = Object.keys(file).sort();
        if (keys.length !== 2 || keys[0] !== "content" || keys[1] !== "path") {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                `files[${index}] must contain exactly path and content`,
            );
        }
        const normalizedPath = normalizeRelativeFilePath(file.path, limits);
        const pathKey = normalizedPath.toLocaleLowerCase("en-US");
        if (seenPaths.has(pathKey)) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                "Candidate contains duplicate file paths",
                { path: normalizedPath },
            );
        }
        seenPaths.add(pathKey);
        if (typeof file.content !== "string"
            || file.content.includes("\u0000")
            || hasUnpairedSurrogate(file.content)) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                `files[${index}].content must be text without NUL`,
            );
        }
        const fileBytes = Buffer.byteLength(file.content, "utf8");
        if (fileBytes > limits.maxFileBytes) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                `files[${index}] exceeds the per-file byte cap`,
                { path: normalizedPath, bytes: fileBytes, cap: limits.maxFileBytes },
            );
        }
        totalBytes += Buffer.byteLength(normalizedPath, "utf8") + fileBytes;
        if (totalBytes > limits.maxTotalBytes) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                "Candidate payload exceeds the total byte cap",
                { bytes: totalBytes, cap: limits.maxTotalBytes },
            );
        }
        files.push({ path: normalizedPath, content: file.content });
    }

    files.sort((left, right) => left.path.localeCompare(right.path));
    return immutableCanonical({
        candidateId,
        mechanism: args.mechanism,
        files,
    });
}

function toolSchema(limits) {
    return {
        type: "object",
        additionalProperties: false,
        properties: {
            challenge: {
                type: "string",
                minLength: 1,
                maxLength: 512,
                description: "Exact challenge nonce from the prompt.",
            },
            candidateId: {
                type: "string",
                minLength: 1,
                maxLength: 128,
            },
            mechanism: {
                type: "string",
                minLength: 1,
                maxLength: limits.maxMechanismBytes,
            },
            files: {
                type: "array",
                minItems: 1,
                maxItems: limits.maxFiles,
                items: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                        path: { type: "string", minLength: 1, maxLength: limits.maxPathBytes },
                        content: { type: "string", maxLength: limits.maxFileBytes },
                    },
                    required: ["path", "content"],
                },
            },
        },
        required: ["challenge", "candidateId", "mechanism", "files"],
    };
}

export function buildProposalPrompt({
    objective,
    candidateId,
    challengeNonce,
    round,
    model,
    additionalContext = null,
}) {
    const context = additionalContext === null ? "" : `\nSearch context:\n${additionalContext}\n`;
    return [
        "You are an Crucible search/diversity worker.",
        "You propose source files only. You never decide whether a candidate passes, is verified,",
        "is unreachable, is terminal, or is a result. The trusted harness makes every such determination.",
        `Objective: ${objective}`,
        `Round: ${round}`,
        `Configured model: ${model}`,
        `Your assigned candidateId is exactly: ${candidateId}`,
        `Your challenge nonce is exactly: ${challengeNonce}`,
        context,
        `Call ${SUBMIT_CANDIDATE_TOOL_NAME} exactly once with the exact challenge and candidateId.`,
        "Submit a concise mechanism description and the complete bounded file map.",
        "Do not return a prose-only candidate. After the tool call, stop.",
    ].join("\n");
}

async function defaultSdkLoader(sdkPath) {
    const moduleUrl = pathToFileURL(path.join(sdkPath, "index.js")).href;
    return import(moduleUrl);
}

function localAbsolutePath(value, field) {
    const absolute = requireAbsolutePath(value, field);
    try {
        return assertLocalDatabasePath(absolute);
    } catch (error) {
        throw new RuntimeConfigError(`${field} must be on a trusted local filesystem`, {
            field,
            path: absolute,
            cause: error?.code ?? null,
            reason: error?.details?.reason ?? null,
        });
    }
}

export class SdkWorkerPool {
    #options;
    #client = null;
    #sdk = null;
    #startPromise = null;
    #claimedCandidateIds;

    constructor(options = {}) {
        const client = options.client ?? null;
        const sdkPath = client === null
            ? localAbsolutePath(options.sdkPath ?? process.env.COPILOT_SDK_PATH, "sdkPath")
            : options.sdkPath ?? null;
        const cliPath = client === null
            ? localAbsolutePath(options.cliPath ?? process.env.COPILOT_CLI_PATH, "cliPath")
            : options.cliPath ?? null;
        const baseDirectory = ensureDirectory(
            localAbsolutePath(options.baseDirectory, "baseDirectory"),
        );
        const workingDirectory = ensureDirectory(
            localAbsolutePath(options.workingDirectory ?? baseDirectory, "workingDirectory"),
        );
        this.#options = {
            client,
            sdkPath,
            cliPath,
            baseDirectory,
            workingDirectory,
            sdkLoader: options.sdkLoader ?? defaultSdkLoader,
            clientFactory: options.clientFactory ?? null,
            idFactory: options.idFactory ?? (() => randomUUID()),
            candidateLimits: normalizeLimits(options.candidateLimits ?? {}),
            sessionTimeoutMs: options.sessionTimeoutMs ?? 120_000,
        };
        if (!Number.isSafeInteger(this.#options.sessionTimeoutMs)
            || this.#options.sessionTimeoutMs < 1
            || this.#options.sessionTimeoutMs > 60 * 60 * 1000) {
            throw new RuntimeConfigError("sessionTimeoutMs must be a positive integer <= 3600000");
        }
        this.#claimedCandidateIds = new Set(options.existingCandidateIds ?? []);
    }

    get candidateLimits() {
        return this.#options.candidateLimits;
    }

    releaseCandidateId(candidateId) {
        this.#claimedCandidateIds.delete(candidateId);
    }

    async start() {
        if (this.#client !== null) {
            return this;
        }
        if (this.#startPromise !== null) {
            await this.#startPromise;
            return this;
        }
        this.#startPromise = (async () => {
            let client = null;
            let sdk = null;
            try {
                if (this.#options.client !== null) {
                    client = this.#options.client;
                } else {
                    sdk = await this.#options.sdkLoader(this.#options.sdkPath);
                    const { CopilotClient, RuntimeConnection } = sdk;
                    if (typeof CopilotClient !== "function"
                        || typeof RuntimeConnection?.forStdio !== "function") {
                        throw new RuntimeConfigError(
                            "COPILOT_SDK_PATH does not export CopilotClient and RuntimeConnection",
                            { sdkPath: this.#options.sdkPath },
                        );
                    }
                    const clientOptions = {
                        connection: RuntimeConnection.forStdio({ path: this.#options.cliPath }),
                        mode: "empty",
                        baseDirectory: this.#options.baseDirectory,
                        workingDirectory: this.#options.workingDirectory,
                        logLevel: "error",
                    };
                    client = this.#options.clientFactory === null
                        ? new CopilotClient(clientOptions)
                        : await this.#options.clientFactory({
                            CopilotClient,
                            RuntimeConnection,
                            clientOptions,
                        });
                }
                if (typeof client?.createSession !== "function") {
                    throw new RuntimeConfigError("SDK client must expose createSession()");
                }
                if (typeof client.start === "function") {
                    await client.start();
                }
                // Publish only after the SDK has fully started. Concurrent
                // propose() calls await this same promise and cannot observe a
                // half-started client.
                this.#sdk = sdk;
                this.#client = client;
            } catch (error) {
                if (client !== null && typeof client.stop === "function") {
                    try {
                        await client.stop();
                    } catch {
                        // Preserve the startup failure.
                    }
                }
                if (error instanceof CrucibleRuntimeError) {
                    throw error;
                }
                throw new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.WORKER_STARTUP,
                    `SDK worker pool startup failed: ${error?.message ?? String(error)}`,
                    { cause: error?.code ?? null },
                    { cause: error },
                );
            }
        })();
        try {
            await this.#startPromise;
        } finally {
            this.#startPromise = null;
        }
        return this;
    }

    async close() {
        if (this.#startPromise !== null) {
            try {
                await this.#startPromise;
            } catch {
                // Failed startup already cleaned up its unpublished client.
            }
        }
        const client = this.#client;
        this.#client = null;
        if (client !== null && typeof client.stop === "function") {
            await client.stop();
        }
    }

    async propose(input) {
        await this.start();
        requirePlainObject(input, "proposal request");
        const model = requireString(input.model, "model", { max: 128 });
        const sessionId = requireString(
            input.sessionId ?? this.#options.idFactory(),
            "sessionId",
            { max: 256 },
        );
        const challengeNonce = requireString(input.challengeNonce, "challengeNonce", { max: 512 });
        const prompt = requireString(input.prompt, "prompt", {
            max: 256 * 1024,
            allowLineBreaks: true,
        });
        if (!Array.isArray(input.allowedCandidateIds) || input.allowedCandidateIds.length === 0) {
            throw new RuntimeConfigError("allowedCandidateIds must be a non-empty array");
        }
        const allowedCandidateIds = input.allowedCandidateIds.map((candidateId, index) =>
            requireIdentifier(candidateId, `allowedCandidateIds[${index}]`));
        if (new Set(allowedCandidateIds).size !== allowedCandidateIds.length) {
            throw new RuntimeConfigError("allowedCandidateIds must be unique");
        }
        const promptHash = hashCanonical(
            { prompt },
            "sha256:crucible-runtime-worker-prompt-v1",
        );

        let submission = null;
        let protocolFailure = null;
        let callCount = 0;
        let claimedByThisSession = null;

        const recordFailure = (error) => {
            if (protocolFailure === null) {
                protocolFailure = error;
            }
            return {
                resultType: "rejected",
                textResultForLlm: "Candidate submission rejected by the Crucible runtime protocol.",
                error: error.message,
            };
        };

        const tool = {
            name: SUBMIT_CANDIDATE_TOOL_NAME,
            description: "Submit exactly one bounded candidate file map for trusted harness measurement.",
            defer: "never",
            skipPermission: true,
            parameters: toolSchema(this.#options.candidateLimits),
            handler: async (args, invocation) => {
                callCount += 1;
                if (callCount > 1) {
                    return recordFailure(protocolError(
                        RUNTIME_ERROR_CODES.WORKER_MULTIPLE_SUBMISSIONS,
                        "A proposal session may submit exactly one candidate",
                        { sessionId, callCount },
                    ));
                }
                if (invocation?.sessionId !== sessionId) {
                    return recordFailure(protocolError(
                        RUNTIME_ERROR_CODES.WORKER_SESSION_MISMATCH,
                        "SDK invocation.sessionId does not match the requested proposal session",
                        { requested: sessionId, invocation: invocation?.sessionId ?? null },
                    ));
                }
                let candidate;
                try {
                    candidate = validateCandidateSubmission(args, {
                        challengeNonce,
                        allowedCandidateIds,
                        limits: this.#options.candidateLimits,
                    });
                } catch (error) {
                    return recordFailure(error);
                }
                if (this.#claimedCandidateIds.has(candidate.candidateId)) {
                    return recordFailure(protocolError(
                        RUNTIME_ERROR_CODES.WORKER_DUPLICATE_CANDIDATE,
                        "Candidate id has already been submitted",
                        { candidateId: candidate.candidateId },
                    ));
                }
                this.#claimedCandidateIds.add(candidate.candidateId);
                claimedByThisSession = candidate.candidateId;
                const payloadHash = hashCanonical(
                    candidate,
                    "sha256:crucible-runtime-candidate-payload-v1",
                );
                submission = immutableCanonical({
                    ...candidate,
                    identity: {
                        invocationSessionId: invocation.sessionId,
                        configuredModel: model,
                        challengeNonce,
                        promptHash,
                        payloadHash,
                    },
                });
                return {
                    resultType: "success",
                    textResultForLlm: "Candidate accepted for trusted measurement. No verdict was produced.",
                };
            },
        };

        let session;
        let sessionError = null;
        let disconnectError = null;
        try {
            const sessionConfig = {
                sessionId,
                clientName: "crucible-autonomous-runtime",
                model,
                tools: [tool],
                availableTools: [`custom:${SUBMIT_CANDIDATE_TOOL_NAME}`],
                enableConfigDiscovery: false,
                enableSessionTelemetry: false,
                skipCustomInstructions: true,
                enableOnDemandInstructionDiscovery: false,
                enableFileHooks: false,
                enableHostGitOperations: false,
                enableSessionStore: false,
                enableSkills: false,
                skipEmbeddingRetrieval: true,
                embeddingCacheStorage: "in-memory",
                remoteSession: "off",
                requestExtensions: false,
                requestCanvasRenderer: false,
                infiniteSessions: { enabled: false },
            };
            if (input.reasoningEffort !== null && input.reasoningEffort !== undefined) {
                sessionConfig.reasoningEffort = requireString(
                    input.reasoningEffort,
                    "reasoningEffort",
                    { max: 32 },
                );
            }
            session = await this.#client.createSession(sessionConfig);
            await session.sendAndWait({ prompt }, this.#options.sessionTimeoutMs);
        } catch (error) {
            sessionError = error;
            if (session !== undefined && typeof session.abort === "function") {
                try {
                    await session.abort();
                } catch {
                    // Preserve the original session failure.
                }
            }
        } finally {
            if (session !== undefined && typeof session.disconnect === "function") {
                try {
                    await session.disconnect();
                } catch (error) {
                    disconnectError = error;
                }
            }
        }

        if (sessionError !== null || disconnectError !== null) {
            if (claimedByThisSession !== null) {
                this.#claimedCandidateIds.delete(claimedByThisSession);
            }
            throw sessionError ?? disconnectError;
        }

        if (protocolFailure !== null) {
            if (claimedByThisSession !== null) {
                this.#claimedCandidateIds.delete(claimedByThisSession);
            }
            throw protocolFailure;
        }
        if (callCount === 0 || submission === null) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_NO_SUBMISSION,
                "Proposal session returned without calling crucible_submit_candidate",
                { sessionId, model },
            );
        }
        if (callCount !== 1) {
            throw protocolError(
                RUNTIME_ERROR_CODES.WORKER_MULTIPLE_SUBMISSIONS,
                "Proposal session called crucible_submit_candidate more than once",
                { sessionId, callCount },
            );
        }
        return submission;
    }

    async proposeBatch(requests) {
        if (!Array.isArray(requests) || requests.length === 0) {
            throw new RuntimeConfigError("proposeBatch requires a non-empty request array");
        }
        return Promise.all(requests.map((request) => this.propose(request)));
    }
}

export function createSdkWorkerPool(options) {
    return new SdkWorkerPool(options);
}

export function assertWorkerSessionsAreNonTerminal(proposal) {
    if (proposal?.identity === null || typeof proposal?.identity !== "object") {
        throw new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.WORKER_PROTOCOL,
            "Worker proposal is missing code-stamped identity",
        );
    }
    return true;
}
