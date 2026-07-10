// crucible/measurement/sandbox.mjs
//
// This module defines the trust-bearing SandboxProvider authoring boundary.
// Successful admission does not return an advisory object. A registered
// provider must use the per-admission issuer it receives to mint one opaque,
// attempt-bound SandboxLaunchCapability. The capability class and its brand
// are module-private; copied properties, symbols, and host process adapters
// cannot impersonate one.

import fs from "node:fs";
import path from "node:path";

import {
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
    SandboxCapabilityError,
} from "./errors.mjs";

const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const HASH_TAG = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const CAPABILITY_KEYS = Object.freeze([
    "capabilityId",
    "cleanup",
    "launch",
    "permittedStagedRoots",
    "policyDigest",
    "policyId",
    "terminate",
]);
const CAPABILITY_CONSTRUCTION_KEY = Object.freeze({});
const PROVIDER_RECORDS = new WeakMap();
const CAPABILITY_RECORDS = new WeakMap();
const CAPABILITY_INSTANCES = new WeakSet();

class SandboxLaunchCapability {
    constructor(key, record) {
        if (key !== CAPABILITY_CONSTRUCTION_KEY) {
            throw new TypeError("SandboxLaunchCapability is not publicly constructible");
        }
        CAPABILITY_INSTANCES.add(this);
        CAPABILITY_RECORDS.set(this, record);
        Object.freeze(this);
    }
}

function capabilityError(code, message, details = null) {
    return new SandboxCapabilityError(code, message, details);
}

function validateSafeId(value, field, code = MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT) {
    if (typeof value !== "string" || !SAFE_ID.test(value)) {
        const ErrorType = code === MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT
            ? MeasurementError
            : SandboxCapabilityError;
        throw new ErrorType(
            code,
            `${field} must be a safe identifier`,
            { field, value: value ?? null },
        );
    }
    return value;
}

function validateTaggedHash(value, field) {
    if (typeof value !== "string" || !HASH_TAG.test(value)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            `${field} must be an algorithm-tagged SHA-256`,
            { field, value: value ?? null },
        );
    }
    return value;
}

function normalizeExistingRoot(value, field) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            `${field} must be an absolute staged root`,
            { field, value: value ?? null },
        );
    }
    try {
        const lst = fs.lstatSync(value);
        if (!lst.isDirectory() || lst.isSymbolicLink()) {
            throw new Error("root is not a regular directory");
        }
        return fs.realpathSync.native(value);
    } catch (error) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            `${field} is not an existing regular directory`,
            { field, value, cause: error?.code ?? error?.message ?? null },
        );
    }
}

function comparePath(left, right) {
    const a = process.platform === "win32" ? left.toLowerCase() : left;
    const b = process.platform === "win32" ? right.toLowerCase() : right;
    return a < b ? -1 : a > b ? 1 : 0;
}

function samePath(left, right) {
    return comparePath(left, right) === 0;
}

function normalizeRootList(value, field) {
    if (!Array.isArray(value) || value.length === 0) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            `${field} must be a non-empty array`,
        );
    }
    const roots = value.map((item, index) =>
        normalizeExistingRoot(item, `${field}[${index}]`));
    roots.sort(comparePath);
    for (let index = 1; index < roots.length; index += 1) {
        if (samePath(roots[index - 1], roots[index])) {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
                `${field} contains a duplicate staged root`,
                { root: roots[index] },
            );
        }
    }
    return Object.freeze(roots);
}

function normalizeBoundRootList(value, field) {
    if (!Array.isArray(value) || value.length === 0) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            `${field} must be a non-empty array`,
        );
    }
    const roots = value.map((item, index) => {
        if (typeof item !== "string" || !path.isAbsolute(item)) {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
                `${field}[${index}] must be an absolute path`,
            );
        }
        return path.resolve(item);
    }).sort(comparePath);
    for (let index = 1; index < roots.length; index += 1) {
        if (samePath(roots[index - 1], roots[index])) {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
                `${field} contains a duplicate staged root`,
                { root: roots[index] },
            );
        }
    }
    return Object.freeze(roots);
}

function rootsEqual(left, right) {
    return left.length === right.length
        && left.every((root, index) => samePath(root, right[index]));
}

function pathInsideRoot(candidate, root) {
    const relative = path.relative(root, candidate);
    return relative === ""
        || (!path.isAbsolute(relative)
            && relative !== ".."
            && !relative.startsWith(`..${path.sep}`));
}

function requirePathInsideRoots(value, roots, field) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            `${field} must be an absolute staged path`,
            { field, value: value ?? null },
        );
    }
    let resolved;
    try {
        resolved = fs.realpathSync.native(value);
    } catch (error) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            `${field} does not resolve to an existing staged path`,
            { field, value, cause: error?.code ?? null },
        );
    }
    if (!roots.some((root) => pathInsideRoot(resolved, root))) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            `${field} is outside the capability's permitted staged roots`,
            { field, value: resolved, permittedStagedRoots: roots },
        );
    }
    return resolved;
}

function normalizeAdmissionRequest(request) {
    if (request === null || typeof request !== "object" || Array.isArray(request)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "SandboxProvider admission request must be an object",
        );
    }
    const attemptId = validateSafeId(
        request.attemptId,
        "SandboxProvider request.attemptId",
        MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
    );
    const runnerEpochId = validateSafeId(
        request.runnerEpochId,
        "SandboxProvider request.runnerEpochId",
        MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
    );
    const harnessId = validateSafeId(
        request.harnessId,
        "SandboxProvider request.harnessId",
        MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
    );
    if (request.verifiedEntry === null || typeof request.verifiedEntry !== "object") {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "SandboxProvider request.verifiedEntry must be an object",
        );
    }
    if (request.candidateSnapshot === null
        || typeof request.candidateSnapshot !== "object"
        || typeof request.candidateSnapshot.path !== "string"
        || !path.isAbsolute(request.candidateSnapshot.path)
        || typeof request.candidateSnapshot.hash !== "string"
        || !HASH_TAG.test(request.candidateSnapshot.hash)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "SandboxProvider request.candidateSnapshot is malformed",
        );
    }
    const stagedRoots = normalizeRootList(
        request.stagedRoots,
        "SandboxProvider request.stagedRoots",
    );
    return Object.freeze({
        attemptId,
        runnerEpochId,
        harnessId,
        verifiedEntry: request.verifiedEntry,
        candidateSnapshot: request.candidateSnapshot,
        stagedRoots,
        executesCandidateCode: true,
        requestedLaunchPath: "sandbox-capability",
        launch: request.launch,
    });
}

function normalizeCapabilitySpec(spec, provider, providerRecord, request, admissionToken) {
    if (spec === null || typeof spec !== "object" || Array.isArray(spec)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "Sandbox capability issuance requires an object",
        );
    }
    const keys = Object.keys(spec).sort();
    if (keys.length !== CAPABILITY_KEYS.length
        || keys.some((key, index) => key !== CAPABILITY_KEYS[index])) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "Sandbox capability issuance has an invalid shape",
            { expectedKeys: CAPABILITY_KEYS, actualKeys: keys },
        );
    }
    const capabilityId = validateSafeId(
        spec.capabilityId,
        "Sandbox capabilityId",
        MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
    );
    const policyId = validateSafeId(
        spec.policyId,
        "Sandbox policyId",
        MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
    );
    const policyDigest = validateTaggedHash(spec.policyDigest, "Sandbox policyDigest");
    const permittedStagedRoots = normalizeRootList(
        spec.permittedStagedRoots,
        "Sandbox permittedStagedRoots",
    );
    if (!rootsEqual(permittedStagedRoots, request.stagedRoots)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox capability must authorize exactly the staged roots requested for this attempt",
            {
                attemptId: request.attemptId,
                requestedStagedRoots: request.stagedRoots,
                permittedStagedRoots,
            },
        );
    }
    for (const method of ["launch", "terminate", "cleanup"]) {
        if (typeof spec[method] !== "function") {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
                `Sandbox capability ${method} must be a function`,
            );
        }
    }
    return {
        provider,
        providerId: providerRecord.providerId,
        providerVersion: providerRecord.providerVersion,
        admissionToken,
        attemptId: request.attemptId,
        runnerEpochId: request.runnerEpochId,
        harnessId: request.harnessId,
        candidateSnapshotPath: request.candidateSnapshot.path,
        candidateSnapshotHash: request.candidateSnapshot.hash,
        capabilityId,
        policyId,
        policyDigest,
        permittedStagedRoots,
        launchController: spec.launch,
        terminateController: spec.terminate,
        cleanupController: spec.cleanup,
        state: "issued",
        launchUsed: false,
        pid: null,
        terminationPromise: null,
        cleanupPromise: null,
    };
}

function normalizeRefusal(value) {
    if (value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && value.admitted === false) {
        const reason = typeof value.reason === "string" && value.reason.length > 0
            ? value.reason
            : "sandbox refused with no reason";
        return Object.freeze({ admitted: false, reason });
    }
    return null;
}

function getCapabilityRecord(capability) {
    if ((typeof capability !== "object" && typeof capability !== "function")
        || capability === null
        || !CAPABILITY_INSTANCES.has(capability)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "SandboxProvider did not return an opaque SandboxLaunchCapability",
        );
    }
    return CAPABILITY_RECORDS.get(capability);
}

function assertCapabilityBinding(capability, expected) {
    const record = getCapabilityRecord(capability);
    if (record.provider !== expected.provider) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox capability was issued by a different provider",
            {
                expectedProviderId: PROVIDER_RECORDS.get(expected.provider)?.providerId ?? null,
                actualProviderId: record.providerId,
            },
        );
    }
    if (record.attemptId !== expected.attemptId
        || record.runnerEpochId !== expected.runnerEpochId
        || record.harnessId !== expected.harnessId) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox capability is bound to a different attempt",
            {
                expectedAttemptId: expected.attemptId,
                actualAttemptId: record.attemptId,
                expectedRunnerEpochId: expected.runnerEpochId,
                actualRunnerEpochId: record.runnerEpochId,
                expectedHarnessId: expected.harnessId,
                actualHarnessId: record.harnessId,
            },
        );
    }
    const stagedRoots = normalizeBoundRootList(
        expected.stagedRoots,
        "Sandbox expected stagedRoots",
    );
    if (!rootsEqual(record.permittedStagedRoots, stagedRoots)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox capability staged-root binding does not match this attempt",
            {
                attemptId: record.attemptId,
                expectedStagedRoots: stagedRoots,
                permittedStagedRoots: record.permittedStagedRoots,
            },
        );
    }
    return record;
}

async function cleanupIssuedCapability(capability, expected) {
    try {
        await cleanupSandboxCapability(capability, expected);
    } catch {
        // The caller is already rejecting this admission. Best-effort cleanup
        // must not convert an invalid result into a successful capability.
    }
}

async function invokeProvider(provider, rawRequest) {
    const providerRecord = PROVIDER_RECORDS.get(provider);
    const request = normalizeAdmissionRequest(rawRequest);
    const admissionToken = Object.freeze({});
    let issuedCapability = null;
    let issuanceOpen = true;

    const issueLaunchCapability = (spec) => {
        if (!issuanceOpen) {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
                "Sandbox capability issuer is closed",
                { attemptId: request.attemptId },
            );
        }
        if (issuedCapability !== null) {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
                "SandboxProvider may issue only one capability per admission",
                { attemptId: request.attemptId },
            );
        }
        const record = normalizeCapabilitySpec(
            spec,
            provider,
            providerRecord,
            request,
            admissionToken,
        );
        issuedCapability = new SandboxLaunchCapability(
            CAPABILITY_CONSTRUCTION_KEY,
            record,
        );
        return issuedCapability;
    };

    let result;
    try {
        result = await providerRecord.admitAndPrepare(
            request,
            issueLaunchCapability,
        );
    } catch (error) {
        issuanceOpen = false;
        if (issuedCapability !== null) {
            await cleanupIssuedCapability(issuedCapability, {
                provider,
                attemptId: request.attemptId,
                runnerEpochId: request.runnerEpochId,
                harnessId: request.harnessId,
                stagedRoots: request.stagedRoots,
            });
        }
        throw error;
    }
    issuanceOpen = false;

    const refusal = normalizeRefusal(result);
    if (refusal !== null) {
        if (issuedCapability !== null) {
            await cleanupIssuedCapability(issuedCapability, {
                provider,
                attemptId: request.attemptId,
                runnerEpochId: request.runnerEpochId,
                harnessId: request.harnessId,
                stagedRoots: request.stagedRoots,
            });
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
                "SandboxProvider issued a capability and then returned a refusal",
                { attemptId: request.attemptId },
            );
        }
        return refusal;
    }

    if (result !== issuedCapability || issuedCapability === null) {
        if (result !== null
            && typeof result === "object"
            && result.admitted === true) {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
                "Advisory {admitted:true} sandbox objects are not launch capabilities",
                { attemptId: request.attemptId },
            );
        }
        if (CAPABILITY_INSTANCES.has(result)) {
            const returnedRecord = CAPABILITY_RECORDS.get(result);
            if (returnedRecord.state !== "issued") {
                throw capabilityError(
                    MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_REPLAY,
                    "Sandbox capability has already been consumed",
                    {
                        attemptId: request.attemptId,
                        capabilityId: returnedRecord.capabilityId,
                    },
                );
            }
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
                "SandboxProvider returned a capability from another admission",
                {
                    expectedAttemptId: request.attemptId,
                    actualAttemptId: returnedRecord.attemptId,
                    capabilityId: returnedRecord.capabilityId,
                },
            );
        }
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "SandboxProvider admission must return its issued opaque capability or {admitted:false}",
            { attemptId: request.attemptId },
        );
    }

    const record = getCapabilityRecord(result);
    if (record.provider !== provider
        || record.admissionToken !== admissionToken
        || record.attemptId !== request.attemptId) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox capability provider/admission identity did not match",
            { attemptId: request.attemptId, capabilityId: record.capabilityId },
        );
    }
    return result;
}

export function createSandboxProvider(definition) {
    if (definition === null
        || typeof definition !== "object"
        || Array.isArray(definition)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "createSandboxProvider requires a provider definition object",
        );
    }
    const providerId = validateSafeId(definition.providerId, "providerId");
    const providerVersion = validateSafeId(
        definition.providerVersion,
        "providerVersion",
    );
    if (typeof definition.admitAndPrepare !== "function") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "SandboxProvider definition must expose admitAndPrepare(request, issueLaunchCapability)",
        );
    }

    let provider;
    provider = Object.freeze({
        providerId,
        providerVersion,
        describePolicyIdentity() {
            if (typeof definition.describePolicyIdentity !== "function") {
                return null;
            }
            return definition.describePolicyIdentity();
        },
        admitAndPrepare(request) {
            return invokeProvider(provider, request);
        },
    });
    PROVIDER_RECORDS.set(provider, {
        providerId,
        providerVersion,
        describePolicyIdentity: definition.describePolicyIdentity ?? null,
        admitAndPrepare: definition.admitAndPrepare,
    });
    return provider;
}

export function isSandboxProvider(value) {
    return value !== null
        && (typeof value === "object" || typeof value === "function")
        && PROVIDER_RECORDS.has(value);
}

export function isSandboxRefusal(value) {
    return normalizeRefusal(value) !== null;
}

export async function describeSandboxProviderPolicy(provider) {
    if (!isSandboxProvider(provider)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "describeSandboxProviderPolicy requires a registered SandboxProvider",
        );
    }
    const record = PROVIDER_RECORDS.get(provider);
    if (typeof record.describePolicyIdentity !== "function") {
        return null;
    }
    const identity = await record.describePolicyIdentity();
    if (identity === null || typeof identity !== "object" || Array.isArray(identity)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
            "SandboxProvider policy identity must be an object",
        );
    }
    return Object.freeze({ ...identity });
}

export function describeSandboxCapability(capability, expected) {
    const record = assertCapabilityBinding(capability, expected);
    return Object.freeze({
        sandboxId: record.capabilityId,
        environmentHash: record.policyDigest,
        providerId: record.providerId,
        providerVersion: record.providerVersion,
        policyId: record.policyId,
        policyDigest: record.policyDigest,
        capabilityId: record.capabilityId,
        launchPath: "sandbox-capability",
        capabilityLaunchUsed: record.launchUsed,
        permittedStagedRoots: Object.freeze([...record.permittedStagedRoots]),
    });
}

export async function launchSandboxCapability(capability, expected, launchInput) {
    const record = assertCapabilityBinding(capability, expected);
    if (record.state !== "issued") {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_REPLAY,
            "Sandbox capability is one-shot and has already been consumed",
            {
                attemptId: record.attemptId,
                capabilityId: record.capabilityId,
                state: record.state,
            },
        );
    }
    if (launchInput === null
        || typeof launchInput !== "object"
        || Array.isArray(launchInput)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox launch input must be an object",
        );
    }
    const executable = requirePathInsideRoots(
        launchInput.executable,
        record.permittedStagedRoots,
        "Sandbox launch executable",
    );
    const cwd = requirePathInsideRoots(
        launchInput.cwd,
        record.permittedStagedRoots,
        "Sandbox launch cwd",
    );
    if (!Array.isArray(launchInput.argv)
        || launchInput.argv.some((item) => typeof item !== "string")) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox launch argv must be an array of strings",
        );
    }
    if (launchInput.env === null
        || typeof launchInput.env !== "object"
        || Array.isArray(launchInput.env)) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox launch env must be an object",
        );
    }
    if (!Array.isArray(launchInput.stagedPaths)
        || launchInput.stagedPaths.length === 0) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox launch stagedPaths must be a non-empty array",
        );
    }
    const stagedPaths = launchInput.stagedPaths.map((item, index) =>
        requirePathInsideRoots(
            item,
            record.permittedStagedRoots,
            `Sandbox launch stagedPaths[${index}]`,
        ));

    record.state = "launching";
    const request = Object.freeze({
        providerId: record.providerId,
        providerVersion: record.providerVersion,
        policyId: record.policyId,
        policyDigest: record.policyDigest,
        capabilityId: record.capabilityId,
        attemptId: record.attemptId,
        runnerEpochId: record.runnerEpochId,
        harnessId: record.harnessId,
        candidateSnapshotPath: record.candidateSnapshotPath,
        candidateSnapshotHash: record.candidateSnapshotHash,
        permittedStagedRoots: Object.freeze([...record.permittedStagedRoots]),
        stagedPaths: Object.freeze(stagedPaths),
        executable,
        argv: Object.freeze([...launchInput.argv]),
        options: Object.freeze({
            cwd,
            env: Object.freeze({ ...launchInput.env }),
            stdio: Object.freeze(["ignore", "pipe", "pipe"]),
            shell: false,
            windowsHide: true,
            executesCandidateCode: true,
            launchPath: "sandbox-capability",
        }),
    });

    let child;
    try {
        child = await record.launchController(request);
    } catch (error) {
        record.state = "launch-failed";
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
            `Sandbox capability launch failed: ${error?.message ?? String(error)}`,
            {
                attemptId: record.attemptId,
                capabilityId: record.capabilityId,
                cause: error?.code ?? null,
            },
        );
    }
    if (!Number.isInteger(child?.pid)
        || child.pid <= 0
        || typeof child.on !== "function") {
        record.state = "launch-failed";
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
            "Sandbox capability launch did not return a child process handle",
            { attemptId: record.attemptId, capabilityId: record.capabilityId },
        );
    }
    record.pid = child.pid;
    record.launchUsed = true;
    record.state = "launched";
    return child;
}

export function terminateSandboxCapability(
    capability,
    expected,
    { pid, reason },
) {
    const record = assertCapabilityBinding(capability, expected);
    if (record.state !== "launched" && record.state !== "terminating") {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
            "Sandbox capability cannot terminate before a successful launch",
            {
                attemptId: record.attemptId,
                capabilityId: record.capabilityId,
                state: record.state,
            },
        );
    }
    if (!Number.isInteger(pid) || pid <= 0 || pid !== record.pid) {
        throw capabilityError(
            MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
            "Sandbox termination pid does not match the capability-owned process",
            {
                attemptId: record.attemptId,
                capabilityId: record.capabilityId,
                expectedPid: record.pid,
                actualPid: pid ?? null,
            },
        );
    }
    if (record.terminationPromise !== null) {
        return record.terminationPromise;
    }
    record.state = "terminating";
    const request = Object.freeze({
        providerId: record.providerId,
        providerVersion: record.providerVersion,
        policyId: record.policyId,
        policyDigest: record.policyDigest,
        capabilityId: record.capabilityId,
        attemptId: record.attemptId,
        runnerEpochId: record.runnerEpochId,
        harnessId: record.harnessId,
        pid,
        reason: typeof reason === "string" ? reason : "unspecified",
    });
    record.terminationPromise = Promise.resolve()
        .then(() => record.terminateController(request))
        .then((result) => {
            if (result === false) {
                throw new Error("containment provider reported termination failure");
            }
            return result;
        })
        .catch((error) => {
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
                `Sandbox capability termination failed: ${error?.message ?? String(error)}`,
                {
                    attemptId: record.attemptId,
                    capabilityId: record.capabilityId,
                    pid,
                    cause: error?.code ?? null,
                },
            );
        });
    return record.terminationPromise;
}

export function cleanupSandboxCapability(capability, expected) {
    const record = assertCapabilityBinding(capability, expected);
    if (record.cleanupPromise !== null) {
        return record.cleanupPromise;
    }
    const request = Object.freeze({
        providerId: record.providerId,
        providerVersion: record.providerVersion,
        policyId: record.policyId,
        policyDigest: record.policyDigest,
        capabilityId: record.capabilityId,
        attemptId: record.attemptId,
        runnerEpochId: record.runnerEpochId,
        harnessId: record.harnessId,
        pid: record.pid,
        launchUsed: record.launchUsed,
        terminationRequested: record.terminationPromise !== null,
        permittedStagedRoots: Object.freeze([...record.permittedStagedRoots]),
    });
    record.cleanupPromise = Promise.resolve()
        .then(() => record.cleanupController(request))
        .then((result) => {
            if (result === false) {
                throw new Error("containment provider reported cleanup failure");
            }
            record.state = "cleaned";
            return result;
        })
        .catch((error) => {
            record.state = "cleanup-failed";
            throw capabilityError(
                MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
                `Sandbox capability cleanup failed: ${error?.message ?? String(error)}`,
                {
                    attemptId: record.attemptId,
                    capabilityId: record.capabilityId,
                    cause: error?.code ?? null,
                },
            );
        });
    return record.cleanupPromise;
}
