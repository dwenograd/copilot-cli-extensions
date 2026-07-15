// crucible/measurement/harness-suite.mjs
//
// Pure HarnessSuiteV4 normalization and identity rules. This module performs
// no filesystem access and is intentionally independent of the public API so
// the domain contract can adopt the normalized identity in a later change.

import {
    canonicalJson,
    hashCanonical,
    immutableCanonical,
} from "../domain/canonical.mjs";
import {
    IMPOSSIBILITY_PROOF_CHECKER_ROLE,
} from "../domain/constants.mjs";

export const HARNESS_SUITE_V4_VERSION = 4;
export const HARNESS_SUITE_V4_KIND = "HarnessSuiteV4";
export const HARNESS_SUITE_V4_IDENTITY_ALGORITHM =
    "sha256:crucible-harness-suite-v4";
export const HARNESS_SUITE_V4_CORPUS_ALGORITHM =
    "sha256:crucible-harness-operator-corpus-v4";
export const HARNESS_SUITE_V4_CASE_MANIFEST_ALGORITHM =
    "sha256:crucible-harness-case-manifest-v4";
export const HARNESS_SUITE_V4_CONFIG_ALGORITHM =
    "sha256:crucible-harness-role-config-v4";
export const HARNESS_SUITE_V4_OBSERVABLE_SCHEMA_ALGORITHM =
    "sha256:crucible-harness-observable-schema-v4";
export const HARNESS_SUITE_V4_ENVIRONMENT_ALGORITHM =
    "sha256:crucible-harness-environment-v4";

export const HARNESS_SUITE_V4_REQUIRED_ROLES = Object.freeze([
    "calibration",
    "search",
    "confirmation",
    "challenge",
]);
export const HARNESS_SUITE_V4_OPTIONAL_ROLES = Object.freeze([
    "impossibility_verifier",
]);
export const HARNESS_SUITE_V4_ROLES = Object.freeze([
    ...HARNESS_SUITE_V4_REQUIRED_ROLES,
    ...HARNESS_SUITE_V4_OPTIONAL_ROLES,
]);
export const HARNESS_SUITE_V4_HIDDEN_CASE_ROLES = Object.freeze([
    "confirmation",
    "challenge",
    "impossibility_verifier",
]);
export const HARNESS_SUITE_V4_VERIFIER_MODES = Object.freeze([
    "enumerand_reexecution",
    "certificate_validation",
]);
export const HARNESS_SUITE_V4_VERIFIER_INDEPENDENCE_ATTESTATION =
    "operator_attested_separate_implementation";

const ROLE_SET = new Set(HARNESS_SUITE_V4_ROLES);
const HIDDEN_ROLE_SET = new Set(HARNESS_SUITE_V4_HIDDEN_CASE_ROLES);
const SAFE_ID = /^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$/u;
const TAGGED_SHA256 =
    /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const SNAPSHOT_ID = /^sha256:[a-f0-9]{64}$/u;
const EXPECTATIONS = new Set(["accept", "reject"]);
const MAX_IDENTITY_COMPONENT_BYTES = 256 * 1024;
const TOP_LEVEL_KEYS = new Set([
    "version",
    "kind",
    "id",
    "environmentIdentity",
    "sharedPlatformDependencies",
    "roles",
    "operatorCorpus",
]);
const ROLE_KEYS = new Set([
    "harnessId",
    "harnessEntryHash",
    "executableHash",
    "applicationEntrypointHash",
    "parser",
    "dependencies",
    "configHash",
    "observableSchemaHash",
    "caseManifest",
    "caseManifestHash",
    "deterministicSeed",
    "sandboxIdentity",
    "independenceAttestation",
    "verificationPolicy",
]);
const PARSER_KEYS = new Set(["version", "versionHash", "sourceHash"]);
const DEPENDENCY_KEYS = new Set(["role", "sha256", "kind"]);
const SHARED_DEPENDENCY_KEYS = new Set([
    "classification",
    "role",
    "sha256",
]);
const CASE_REF_KEYS = new Set(["id", "snapshotHash"]);
const CORPUS_KEYS = new Set(["version", "cases", "identity"]);
const CORPUS_CASE_KEYS = new Set(["snapshotHash", "expectation"]);
const SANDBOX_KEYS = new Set(["required", "policyDigest"]);
const INDEPENDENCE_ATTESTATION_KEYS = new Set(["kind"]);
const VERIFICATION_POLICY_KEYS = new Set(["certificateFormat", "mode"]);
const CERTIFICATE_FORMAT_KEYS = new Set(["schemaHash", "version"]);
const ROLE_CONFIG_KEYS = new Set([
    "argvTemplate",
    "cwd",
    "allowedEnv",
    "timeoutMs",
    "maxStdoutBytes",
    "maxStderrBytes",
    "executesCandidateCode",
]);

export class HarnessSuiteV4Error extends TypeError {
    constructor(message, details = null) {
        super(message);
        this.name = "HarnessSuiteV4Error";
        this.code = "CRUCIBLE_HARNESS_SUITE_V4_INVALID";
        if (details !== null && details !== undefined) {
            this.details = details;
        }
    }
}

function fail(message, details) {
    throw new HarnessSuiteV4Error(message, details);
}

function requireObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || Object.getPrototypeOf(value) !== Object.prototype) {
        fail(`${field} must be a plain object`);
    }
    return value;
}

function rejectUnknownKeys(value, allowed, field) {
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(`${field} has unknown key ${JSON.stringify(key)}`);
        }
    }
}

function requireString(value, field, maxLength = 4096) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maxLength
        || value.includes("\0")) {
        fail(`${field} must be a non-empty string <= ${maxLength} characters`);
    }
    return value;
}

function requireId(value, field) {
    const id = requireString(value, field, 128);
    if (!SAFE_ID.test(id)) {
        fail(`${field} is not a safe lowercase identifier`);
    }
    return id;
}

function requireTaggedHash(value, field, algorithm = null) {
    if (typeof value !== "string" || !TAGGED_SHA256.test(value)) {
        fail(`${field} must be an algorithm-tagged SHA-256 identity`);
    }
    if (algorithm !== null && !value.startsWith(`${algorithm}:`)) {
        fail(`${field} must use ${algorithm}`, { actual: value });
    }
    return value;
}

function rawSha256Digest(value) {
    if (typeof value !== "string" || !TAGGED_SHA256.test(value)) {
        fail("internal digest comparison received an invalid tagged SHA-256");
    }
    return value.slice(-64);
}

function requireSnapshot(value, field) {
    if (typeof value !== "string" || !SNAPSHOT_ID.test(value)) {
        fail(`${field} must be an ArtifactStore sha256:<64hex> snapshot id`);
    }
    return value;
}

function boundedCanonicalHash(value, field, algorithm) {
    let serialized;
    try {
        serialized = canonicalJson(value);
    } catch (error) {
        fail(`${field} is not canonical JSON: ${error?.message ?? String(error)}`);
    }
    const bytes = Buffer.byteLength(serialized, "utf8");
    if (bytes > MAX_IDENTITY_COMPONENT_BYTES) {
        fail(`${field} exceeds ${MAX_IDENTITY_COMPONENT_BYTES} canonical bytes`, {
            bytes,
        });
    }
    return hashCanonical(JSON.parse(serialized), algorithm);
}

export function normalizeHarnessRoleConfigV4(config) {
    requireObject(config, "config");
    rejectUnknownKeys(config, ROLE_CONFIG_KEYS, "config");
    if (!Array.isArray(config.argvTemplate) || config.argvTemplate.length > 256) {
        fail("config.argvTemplate must be an array with at most 256 entries");
    }
    const argvTemplate = config.argvTemplate.map((item, index) => {
        if (typeof item !== "string"
            || item.length > 4096
            || item.includes("\0")) {
            fail(`config.argvTemplate[${index}] must be a string <= 4096 characters`);
        }
        return item;
    });
    let cwd = null;
    if (config.cwd !== null && config.cwd !== undefined) {
        cwd = requireString(config.cwd, "config.cwd", 4096);
    }
    requireObject(config.allowedEnv, "config.allowedEnv");
    const allowedEnv = {};
    for (const key of Object.keys(config.allowedEnv).sort()) {
        if (!/^[A-Z_][A-Z0-9_]{0,127}$/u.test(key)) {
            fail(`config.allowedEnv key ${JSON.stringify(key)} is invalid`);
        }
        const value = config.allowedEnv[key];
        if (typeof value !== "string"
            || value.length > 32768
            || value.includes("\0")) {
            fail(`config.allowedEnv.${key} must be a string <= 32768 characters`);
        }
        allowedEnv[key] = value;
    }
    const positiveInteger = (value, field, max) => {
        if (!Number.isSafeInteger(value) || value < 1 || value > max) {
            fail(`${field} must be a positive safe integer <= ${max}`);
        }
        return value;
    };
    if (typeof config.executesCandidateCode !== "boolean") {
        fail("config.executesCandidateCode must be boolean");
    }
    return immutableCanonical({
        argvTemplate,
        cwd,
        allowedEnv,
        timeoutMs: positiveInteger(
            config.timeoutMs,
            "config.timeoutMs",
            60 * 60 * 1000,
        ),
        maxStdoutBytes: positiveInteger(
            config.maxStdoutBytes,
            "config.maxStdoutBytes",
            64 * 1024 * 1024,
        ),
        maxStderrBytes: positiveInteger(
            config.maxStderrBytes,
            "config.maxStderrBytes",
            64 * 1024 * 1024,
        ),
        executesCandidateCode: config.executesCandidateCode,
    });
}

export function hashHarnessRoleConfigV4(config) {
    return boundedCanonicalHash(
        normalizeHarnessRoleConfigV4(config),
        "config",
        HARNESS_SUITE_V4_CONFIG_ALGORITHM,
    );
}

export function hashHarnessObservableSchemaV4(schema) {
    requireObject(schema, "observableSchema");
    return boundedCanonicalHash(
        schema,
        "observableSchema",
        HARNESS_SUITE_V4_OBSERVABLE_SCHEMA_ALGORITHM,
    );
}

export function hashHarnessEnvironmentV4(environment) {
    requireObject(environment, "environment");
    return boundedCanonicalHash(
        environment,
        "environment",
        HARNESS_SUITE_V4_ENVIRONMENT_ALGORITHM,
    );
}

function normalizeParser(value, field) {
    requireObject(value, field);
    rejectUnknownKeys(value, PARSER_KEYS, field);
    return {
        version: requireString(value.version, `${field}.version`, 256),
        versionHash: requireTaggedHash(
            value.versionHash,
            `${field}.versionHash`,
        ),
        sourceHash: requireTaggedHash(
            value.sourceHash,
            `${field}.sourceHash`,
        ),
    };
}

function normalizeDependencies(value, field) {
    if (!Array.isArray(value) || value.length > 128) {
        fail(`${field} must be an array with at most 128 entries`);
    }
    const seen = new Set();
    const out = value.map((dependency, index) => {
        const depField = `${field}[${index}]`;
        requireObject(dependency, depField);
        rejectUnknownKeys(dependency, DEPENDENCY_KEYS, depField);
        const role = requireString(dependency.role, `${depField}.role`, 128);
        const sha256 = requireTaggedHash(
            dependency.sha256,
            `${depField}.sha256`,
        );
        if (dependency.kind !== "application"
            && dependency.kind !== "platform") {
            fail(`${depField}.kind must be "application" or "platform"`);
        }
        const key = `${dependency.kind}\0${role}\0${sha256}`;
        if (seen.has(key)) {
            fail(`${field} contains a duplicate dependency`, {
                role,
                sha256,
                kind: dependency.kind,
            });
        }
        seen.add(key);
        return { role, sha256, kind: dependency.kind };
    });
    out.sort((left, right) =>
        `${left.kind}\0${left.role}\0${left.sha256}`.localeCompare(
            `${right.kind}\0${right.role}\0${right.sha256}`,
        ));
    return out;
}

function normalizeCaseManifest(value, field) {
    if (!Array.isArray(value) || value.length > 4096) {
        fail(`${field} must be an array with at most 4096 entries`);
    }
    const ids = new Set();
    const snapshots = new Set();
    const out = value.map((caseRef, index) => {
        const caseField = `${field}[${index}]`;
        requireObject(caseRef, caseField);
        rejectUnknownKeys(caseRef, CASE_REF_KEYS, caseField);
        const id = requireId(caseRef.id, `${caseField}.id`);
        const snapshotHash = requireSnapshot(
            caseRef.snapshotHash,
            `${caseField}.snapshotHash`,
        );
        if (ids.has(id)) {
            fail(`${field} contains duplicate case id ${JSON.stringify(id)}`);
        }
        if (snapshots.has(snapshotHash)) {
            fail(`${field} assigns the same case bytes more than once`, {
                snapshotHash,
            });
        }
        ids.add(id);
        snapshots.add(snapshotHash);
        return { id, snapshotHash };
    });
    out.sort((left, right) => left.id.localeCompare(right.id));
    return out;
}

function normalizeSandboxIdentity(value, field) {
    requireObject(value, field);
    rejectUnknownKeys(value, SANDBOX_KEYS, field);
    if (typeof value.required !== "boolean") {
        fail(`${field}.required must be boolean`);
    }
    if (value.required) {
        return {
            required: true,
            policyDigest: requireTaggedHash(
                value.policyDigest,
                `${field}.policyDigest`,
            ),
        };
    }
    if (value.policyDigest !== null) {
        fail(`${field}.policyDigest must be null when sandboxing is not required`);
    }
    return { required: false, policyDigest: null };
}

function normalizeVerifierIndependenceAttestation(value, field) {
    requireObject(value, field);
    rejectUnknownKeys(value, INDEPENDENCE_ATTESTATION_KEYS, field);
    if (value.kind !== HARNESS_SUITE_V4_VERIFIER_INDEPENDENCE_ATTESTATION) {
        fail(
            `${field}.kind must be ${
                HARNESS_SUITE_V4_VERIFIER_INDEPENDENCE_ATTESTATION
            }`,
        );
    }
    return {
        kind: HARNESS_SUITE_V4_VERIFIER_INDEPENDENCE_ATTESTATION,
    };
}

function normalizeVerifierCertificateFormat(value, field) {
    if (value === null) return null;
    requireObject(value, field);
    rejectUnknownKeys(value, CERTIFICATE_FORMAT_KEYS, field);
    return {
        version: requireString(value.version, `${field}.version`, 256),
        schemaHash: requireTaggedHash(
            value.schemaHash,
            `${field}.schemaHash`,
        ),
    };
}

function normalizeVerifierPolicy(value, field) {
    requireObject(value, field);
    rejectUnknownKeys(value, VERIFICATION_POLICY_KEYS, field);
    if (!HARNESS_SUITE_V4_VERIFIER_MODES.includes(value.mode)) {
        fail(
            `${field}.mode must be "enumerand_reexecution" or "certificate_validation"`,
        );
    }
    const certificateFormat = normalizeVerifierCertificateFormat(
        value.certificateFormat,
        `${field}.certificateFormat`,
    );
    if ((value.mode === "certificate_validation")
        !== (certificateFormat !== null)) {
        fail(
            `${field}.certificateFormat is required only for certificate_validation`,
        );
    }
    return {
        mode: value.mode,
        certificateFormat,
    };
}

function normalizeRole(value, role) {
    const field = `roles.${role}`;
    requireObject(value, field);
    rejectUnknownKeys(value, ROLE_KEYS, field);
    const caseManifest = normalizeCaseManifest(
        value.caseManifest,
        `${field}.caseManifest`,
    );
    const caseManifestHash = hashCanonical(
        caseManifest,
        HARNESS_SUITE_V4_CASE_MANIFEST_ALGORITHM,
    );
    if (value.caseManifestHash !== undefined
        && value.caseManifestHash !== caseManifestHash) {
        fail(`${field}.caseManifestHash does not match the canonical manifest`, {
            expected: caseManifestHash,
            actual: value.caseManifestHash,
        });
    }
    const sandboxIdentity = normalizeSandboxIdentity(
        value.sandboxIdentity,
        `${field}.sandboxIdentity`,
    );
    if (role === "impossibility_verifier" && !sandboxIdentity.required) {
        fail(
            "roles.impossibility_verifier must require the frozen AppContainer sandbox policy",
        );
    }
    if (role !== "impossibility_verifier"
        && (value.independenceAttestation !== undefined
            || value.verificationPolicy !== undefined)) {
        fail(
            `${field} cannot declare impossibility-verifier independence fields`,
        );
    }
    const executableHash = requireTaggedHash(
        value.executableHash,
        `${field}.executableHash`,
    );
    const applicationEntrypointHash = requireTaggedHash(
        value.applicationEntrypointHash,
        `${field}.applicationEntrypointHash`,
    );
    const parser = normalizeParser(value.parser, `${field}.parser`);
    const dependencies = normalizeDependencies(
        value.dependencies,
        `${field}.dependencies`,
    );
    const verificationPolicy = role === "impossibility_verifier"
        ? normalizeVerifierPolicy(
            value.verificationPolicy,
            `${field}.verificationPolicy`,
        )
        : null;
    if (verificationPolicy?.mode === "certificate_validation") {
        const checkerDependencies = dependencies.filter((dependency) =>
            dependency.role === IMPOSSIBILITY_PROOF_CHECKER_ROLE
            && dependency.kind === "application");
        if (checkerDependencies.length !== 1) {
            fail(
                `${field}.verificationPolicy certificate_validation requires exactly one separately pinned ${IMPOSSIBILITY_PROOF_CHECKER_ROLE} application dependency`,
            );
        }
        const checkerHash = checkerDependencies[0].sha256;
        if ([
            executableHash,
            applicationEntrypointHash,
            parser.versionHash,
            parser.sourceHash,
        ].includes(checkerHash)) {
            fail(
                `${field} proof checker must be separately pinned from the verifier executable, entrypoint, and parser`,
            );
        }
    }
    return {
        harnessId: requireId(value.harnessId, `${field}.harnessId`),
        harnessEntryHash: requireTaggedHash(
            value.harnessEntryHash,
            `${field}.harnessEntryHash`,
        ),
        executableHash,
        applicationEntrypointHash,
        parser,
        dependencies,
        configHash: requireTaggedHash(
            value.configHash,
            `${field}.configHash`,
            HARNESS_SUITE_V4_CONFIG_ALGORITHM,
        ),
        observableSchemaHash: requireTaggedHash(
            value.observableSchemaHash,
            `${field}.observableSchemaHash`,
            HARNESS_SUITE_V4_OBSERVABLE_SCHEMA_ALGORITHM,
        ),
        caseManifest,
        caseManifestHash,
        deterministicSeed: requireString(
            value.deterministicSeed,
            `${field}.deterministicSeed`,
            256,
        ),
        sandboxIdentity,
        ...(role === "impossibility_verifier"
            ? {
                independenceAttestation:
                    normalizeVerifierIndependenceAttestation(
                        value.independenceAttestation,
                        `${field}.independenceAttestation`,
                    ),
                verificationPolicy,
            }
            : {}),
    };
}

function normalizeSharedPlatformDependencies(value) {
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.length > 128) {
        fail("sharedPlatformDependencies must be an array with at most 128 entries");
    }
    const seen = new Set();
    const out = value.map((dependency, index) => {
        const field = `sharedPlatformDependencies[${index}]`;
        requireObject(dependency, field);
        rejectUnknownKeys(dependency, SHARED_DEPENDENCY_KEYS, field);
        const role = requireString(dependency.role, `${field}.role`, 128);
        if (dependency.classification !== "platform"
            && dependency.classification !== "runtime") {
            fail(`${field}.classification must be "platform" or "runtime"`);
        }
        const sha256 = requireTaggedHash(
            dependency.sha256,
            `${field}.sha256`,
        );
        const digest = rawSha256Digest(sha256);
        if (seen.has(digest)) {
            fail("sharedPlatformDependencies contains a duplicate", {
                role,
                sha256,
            });
        }
        seen.add(digest);
        return {
            classification: dependency.classification,
            role,
            sha256,
        };
    });
    out.sort((left, right) =>
        `${left.classification}\0${left.role}\0${left.sha256}`.localeCompare(
            `${right.classification}\0${right.role}\0${right.sha256}`,
        ));
    return out;
}

function normalizeOperatorCorpus(value) {
    requireObject(value, "operatorCorpus");
    rejectUnknownKeys(value, CORPUS_KEYS, "operatorCorpus");
    if (value.version !== 1) {
        fail("operatorCorpus.version must be 1");
    }
    requireObject(value.cases, "operatorCorpus.cases");
    const ids = Object.keys(value.cases).sort();
    if (ids.length < 2 || ids.length > 8192) {
        fail("operatorCorpus.cases must contain 2..8192 immutable cases");
    }
    const cases = {};
    const expectations = new Set();
    for (const id of ids) {
        requireId(id, `operatorCorpus.cases key ${JSON.stringify(id)}`);
        const field = `operatorCorpus.cases.${id}`;
        const spec = value.cases[id];
        requireObject(spec, field);
        rejectUnknownKeys(spec, CORPUS_CASE_KEYS, field);
        const expectation = spec.expectation;
        if (!EXPECTATIONS.has(expectation)) {
            fail(`${field}.expectation must be "accept" or "reject"`);
        }
        expectations.add(expectation);
        cases[id] = {
            snapshotHash: requireSnapshot(
                spec.snapshotHash,
                `${field}.snapshotHash`,
            ),
            expectation,
        };
    }
    if (!expectations.has("accept") || !expectations.has("reject")) {
        fail("operatorCorpus must contain at least one accept and one reject expectation");
    }
    const identity = hashCanonical(
        cases,
        HARNESS_SUITE_V4_CORPUS_ALGORITHM,
    );
    if (value.identity !== undefined && value.identity !== identity) {
        fail("operatorCorpus.identity does not match its immutable cases", {
            expected: identity,
            actual: value.identity,
        });
    }
    return { version: 1, cases, identity };
}

function assertRoleSet(roles) {
    requireObject(roles, "roles");
    for (const role of Object.keys(roles)) {
        if (!ROLE_SET.has(role)) {
            fail(`roles has unknown role ${JSON.stringify(role)}`);
        }
    }
    for (const role of HARNESS_SUITE_V4_REQUIRED_ROLES) {
        if (!Object.hasOwn(roles, role)) {
            fail(`roles.${role} is required`);
        }
    }
}

function assertCorpusBindings(roles, corpus) {
    const referenced = new Set();
    for (const role of Object.keys(roles)) {
        for (const caseRef of roles[role].caseManifest) {
            const pinned = corpus.cases[caseRef.id];
            if (pinned === undefined) {
                fail(`roles.${role}.caseManifest references unknown operator case ${JSON.stringify(caseRef.id)}`);
            }
            if (pinned.snapshotHash !== caseRef.snapshotHash) {
                fail(`roles.${role}.caseManifest relabels case bytes for ${JSON.stringify(caseRef.id)}`, {
                    expected: pinned.snapshotHash,
                    actual: caseRef.snapshotHash,
                });
            }
            referenced.add(caseRef.id);
        }
    }
    const orphaned = Object.keys(corpus.cases).filter((id) => !referenced.has(id));
    if (orphaned.length > 0) {
        fail("operatorCorpus contains cases absent from every role manifest", {
            caseIds: orphaned,
        });
    }
    if (roles.calibration.caseManifest.length === 0) {
        fail("roles.calibration.caseManifest must not be empty");
    }
}

function manifestIdentitySets(role) {
    return {
        ids: new Set(role.caseManifest.map((item) => item.id)),
        snapshots: new Set(role.caseManifest.map((item) => item.snapshotHash)),
    };
}

function assertDisjoint(leftName, left, rightName, right) {
    for (const id of left.ids) {
        if (right.ids.has(id)) {
            fail(`${leftName} and ${rightName} case manifests overlap by id`, {
                caseId: id,
            });
        }
    }
    for (const snapshotHash of left.snapshots) {
        if (right.snapshots.has(snapshotHash)) {
            fail(`${leftName} and ${rightName} case manifests overlap by bytes`, {
                snapshotHash,
            });
        }
    }
}

function assertHeldOutDisjointness(roles) {
    const identities = Object.fromEntries(
        Object.entries(roles).map(([role, spec]) => [
            role,
            manifestIdentitySets(spec),
        ]),
    );
    for (const hiddenRole of HARNESS_SUITE_V4_HIDDEN_CASE_ROLES) {
        if (identities[hiddenRole] === undefined) continue;
        for (const exposedRole of ["calibration", "search"]) {
            assertDisjoint(
                `roles.${hiddenRole}`,
                identities[hiddenRole],
                `roles.${exposedRole}`,
                identities[exposedRole],
            );
        }
    }
    if (identities.challenge !== undefined) {
        if (identities.confirmation !== undefined) {
            assertDisjoint(
                "roles.challenge",
                identities.challenge,
                "roles.confirmation",
                identities.confirmation,
            );
        }
    }
}

function assertSharedPlatformDependencies(roles, shared) {
    const applicationFiles = new Map();
    for (const [role, spec] of Object.entries(roles)) {
        for (const occurrence of [
            {
                type: "executable",
                sha256: spec.executableHash,
            },
            {
                type: "parser",
                sha256: spec.parser.sourceHash,
            },
            {
                type: "application_entrypoint",
                sha256: spec.applicationEntrypointHash,
            },
            ...spec.dependencies
                .filter((dependency) => dependency.kind === "application")
                .map((dependency) => ({
                    type: "application_dependency",
                    sha256: dependency.sha256,
                })),
        ]) {
            const digest = rawSha256Digest(occurrence.sha256);
            const uses = applicationFiles.get(digest) ?? [];
            uses.push({ role, type: occurrence.type, sha256: occurrence.sha256 });
            applicationFiles.set(digest, uses);
        }
    }
    for (const dependency of shared) {
        const digest = rawSha256Digest(dependency.sha256);
        const applicationUses = applicationFiles.get(digest);
        if (applicationUses !== undefined) {
            fail(
                "sharedPlatformDependencies may contain only declared runtime/platform dependency files",
                {
                    dependency,
                    applicationUses,
                },
            );
        }
    }
    const declared = new Map(shared.map((item) => [
        rawSha256Digest(item.sha256),
        item,
    ]));
    const uses = new Map();
    for (const [role, spec] of Object.entries(roles)) {
        for (const dependency of spec.dependencies) {
            const digest = rawSha256Digest(dependency.sha256);
            if (dependency.kind === "platform") {
                const declaration = declared.get(digest);
                if (declaration === undefined
                    || declaration.role !== dependency.role) {
                    fail(`roles.${role} uses an undeclared shared platform dependency`, {
                        dependency,
                    });
                }
                const roleUses = uses.get(digest) ?? new Set();
                roleUses.add(role);
                uses.set(digest, roleUses);
            } else if (declared.has(digest)) {
                fail(`roles.${role} labels a declared platform dependency as application code`, {
                    dependency,
                });
            }
        }
    }
    for (const dependency of shared) {
        const roleUses = uses.get(rawSha256Digest(dependency.sha256));
        if (roleUses === undefined || roleUses.size < 2) {
            fail("a declared shared platform dependency must be used by at least two roles", {
                dependency,
                roles: roleUses === undefined ? [] : [...roleUses].sort(),
            });
        }
    }
}

function closureOccurrences(spec) {
    return [
        {
            sha256: spec.executableHash,
            digest: rawSha256Digest(spec.executableHash),
            type: "executable",
            kind: "application",
        },
        {
            sha256: spec.parser.sourceHash,
            digest: rawSha256Digest(spec.parser.sourceHash),
            type: "parser",
            kind: "application",
        },
        {
            sha256: spec.applicationEntrypointHash,
            digest: rawSha256Digest(spec.applicationEntrypointHash),
            type: "application_entrypoint",
            kind: "application",
        },
        ...spec.dependencies.map((dependency) => ({
            sha256: dependency.sha256,
            digest: rawSha256Digest(dependency.sha256),
            type: "dependency",
            kind: dependency.kind,
        })),
    ];
}

function assertVerifierClosureSeparation(roles, shared) {
    const verifier = roles.impossibility_verifier;
    if (verifier === undefined) return;
    const sharedDigests = new Set(shared.map((item) =>
        rawSha256Digest(item.sha256)));
    const primary = new Map();
    for (const role of HARNESS_SUITE_V4_REQUIRED_ROLES) {
        for (const occurrence of closureOccurrences(roles[role])) {
            const items = primary.get(occurrence.digest) ?? [];
            items.push({ role, ...occurrence });
            primary.set(occurrence.digest, items);
        }
    }
    for (const occurrence of closureOccurrences(verifier)) {
        const overlaps = primary.get(occurrence.digest);
        if (overlaps === undefined) continue;
        const verifierDeclaresPlatform = verifier.dependencies.some((dependency) =>
            dependency.kind === "platform"
            && rawSha256Digest(dependency.sha256) === occurrence.digest);
        const allowed = sharedDigests.has(occurrence.digest)
            && verifierDeclaresPlatform
            && overlaps.every((item) =>
                roles[item.role].dependencies.some((dependency) =>
                    dependency.kind === "platform"
                    && rawSha256Digest(dependency.sha256)
                        === occurrence.digest)
                && item.type === "dependency"
                && item.kind === "platform")
            && occurrence.type === "dependency"
            && occurrence.kind === "platform";
        if (!allowed) {
            fail("impossibility verifier application implementation closure overlaps a primary role", {
                sha256: occurrence.sha256,
                digest: occurrence.digest,
                verifierOccurrence: occurrence,
                primaryOccurrences: overlaps,
            });
        }
    }
}

export function normalizeHarnessSuiteV4(value) {
    requireObject(value, "HarnessSuiteV4");
    rejectUnknownKeys(value, TOP_LEVEL_KEYS, "HarnessSuiteV4");
    if (value.version !== HARNESS_SUITE_V4_VERSION) {
        fail(`HarnessSuiteV4.version must be ${HARNESS_SUITE_V4_VERSION}`);
    }
    if (value.kind !== undefined && value.kind !== HARNESS_SUITE_V4_KIND) {
        fail(`HarnessSuiteV4.kind must be ${HARNESS_SUITE_V4_KIND}`);
    }
    assertRoleSet(value.roles);
    const roles = {};
    for (const role of HARNESS_SUITE_V4_ROLES) {
        if (Object.hasOwn(value.roles, role)) {
            roles[role] = normalizeRole(value.roles[role], role);
        }
    }
    const sharedPlatformDependencies =
        normalizeSharedPlatformDependencies(value.sharedPlatformDependencies);
    const operatorCorpus = normalizeOperatorCorpus(value.operatorCorpus);
    assertCorpusBindings(roles, operatorCorpus);
    assertHeldOutDisjointness(roles);
    assertSharedPlatformDependencies(roles, sharedPlatformDependencies);
    assertVerifierClosureSeparation(roles, sharedPlatformDependencies);

    return immutableCanonical({
        version: HARNESS_SUITE_V4_VERSION,
        kind: HARNESS_SUITE_V4_KIND,
        id: requireId(value.id, "HarnessSuiteV4.id"),
        environmentIdentity: requireTaggedHash(
            value.environmentIdentity,
            "HarnessSuiteV4.environmentIdentity",
            HARNESS_SUITE_V4_ENVIRONMENT_ALGORITHM,
        ),
        sharedPlatformDependencies,
        roles,
        operatorCorpus,
    });
}

export function computeHarnessSuiteV4Identity(value) {
    return hashCanonical(
        normalizeHarnessSuiteV4(value),
        HARNESS_SUITE_V4_IDENTITY_ALGORITHM,
    );
}

export function validateHarnessSuiteV4CaseClaims(
    suiteValue,
    claims,
    options = {},
) {
    const suite = normalizeHarnessSuiteV4(suiteValue);
    const role = options.role === undefined
        ? null
        : requireString(options.role, "role", 64);
    if (role !== null && !ROLE_SET.has(role)) {
        fail(`role ${JSON.stringify(role)} is not a HarnessSuiteV4 role`);
    }
    if (!Array.isArray(claims) || claims.length === 0) {
        fail("claims must be a non-empty array");
    }
    const permitted = role === null
        ? null
        : new Set(suite.roles[role]?.caseManifest.map((item) => item.id) ?? []);
    const seen = new Set();
    const normalized = claims.map((claim, index) => {
        const field = `claims[${index}]`;
        requireObject(claim, field);
        rejectUnknownKeys(
            claim,
            new Set(["id", "snapshotHash", "expectation"]),
            field,
        );
        const id = requireId(claim.id, `${field}.id`);
        if (seen.has(id)) {
            fail(`claims contains duplicate case ${JSON.stringify(id)}`);
        }
        seen.add(id);
        if (permitted !== null && !permitted.has(id)) {
            fail(`case ${JSON.stringify(id)} is not assigned to role ${role}`);
        }
        const pinned = suite.operatorCorpus.cases[id];
        if (pinned === undefined) {
            fail(`case ${JSON.stringify(id)} is not in the operator-owned corpus`);
        }
        const snapshotHash = requireSnapshot(
            claim.snapshotHash,
            `${field}.snapshotHash`,
        );
        if (snapshotHash !== pinned.snapshotHash) {
            fail(`case ${JSON.stringify(id)} bytes do not match the operator-owned corpus`, {
                expected: pinned.snapshotHash,
                actual: snapshotHash,
            });
        }
        if (!EXPECTATIONS.has(claim.expectation)
            || claim.expectation !== pinned.expectation) {
            fail(`case ${JSON.stringify(id)} expectation cannot be relabeled`, {
                expected: pinned.expectation,
                actual: claim.expectation,
            });
        }
        return { id, snapshotHash, expectation: claim.expectation };
    });
    normalized.sort((left, right) => left.id.localeCompare(right.id));
    return immutableCanonical(normalized);
}

export function projectHarnessSuiteV4ForWorker(value) {
    const suite = normalizeHarnessSuiteV4(value);
    const roles = {};
    for (const role of HARNESS_SUITE_V4_ROLES) {
        const spec = suite.roles[role];
        if (spec === undefined) continue;
        const {
            caseManifest,
            ...identity
        } = spec;
        roles[role] = HIDDEN_ROLE_SET.has(role)
            ? {
                ...identity,
                caseManifest: null,
                caseCount: caseManifest.length,
            }
            : {
                ...identity,
                caseManifest,
                caseCount: caseManifest.length,
            };
    }
    return immutableCanonical({
        version: suite.version,
        kind: suite.kind,
        id: suite.id,
        suiteIdentity: hashCanonical(
            suite,
            HARNESS_SUITE_V4_IDENTITY_ALGORITHM,
        ),
        environmentIdentity: suite.environmentIdentity,
        sharedPlatformDependencies: suite.sharedPlatformDependencies,
        roles,
    });
}
