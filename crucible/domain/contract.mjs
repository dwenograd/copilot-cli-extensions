import {
    CONTRACT_HASH_ALGORITHM,
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import {
    CONTRACT_LIMITS,
    DEFAULT_IMPOSSIBILITY_POLICY,
    DEFAULT_SEARCH_POLICY,
    ESCAPE_SEARCH_OPERATORS,
    HYPOTHESIS_TOPOLOGIES,
    SEARCH_POLICY_LIMITS,
    SEARCH_OPERATORS,
} from "./constants.mjs";
import { ContractError, ERROR_CODES } from "./errors.mjs";

const COMPARISON_OPERATORS = Object.freeze(["<", "<=", "==", ">=", ">"]);
const VALIDATION_EXPECTATIONS = Object.freeze(["accept", "reject"]);
const METRIC_DIRECTIONS = Object.freeze(["min", "max"]);
const TAGGED_SHA256 = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@-]*$/u;
const FORBIDDEN_IDENTIFIERS = new Set([
    "__proto__",
    "constructor",
    "prototype",
]);
const HARNESS_IDENTITY_KEYS = Object.freeze([
    "allowedEnvHash",
    "allowlistFileHash",
    "allowlistVersion",
    "argvTemplateHash",
    "dependencyHashes",
    "executesCandidateCode",
    "executableHash",
    "harnessEntryHash",
    "harnessId",
    "parserSourceHash",
    "parserVersion",
    "parserVersionHash",
    "sandbox",
    "version",
]);
const HARNESS_DEPENDENCY_KEYS = Object.freeze(["path", "role", "sha256"]);
const HARNESS_SANDBOX_KEYS = Object.freeze([
    "policyDigest",
    "policyIdentity",
    "required",
]);
const HARNESS_SANDBOX_IDENTITY_KEYS = Object.freeze([
    "filesystem",
    "helperBinaryHash",
    "helperSourceHash",
    "job",
    "launcherBinaryHash",
    "launcherId",
    "launcherScriptHash",
    "network",
    "policyId",
    "primitive",
    "providerId",
    "providerVersion",
    "securityContext",
]);
const HARNESS_SANDBOX_SECURITY_CONTEXT_KEYS = Object.freeze([
    "appContainer",
    "capabilities",
    "loopbackExemptionRejected",
    "lowIntegrity",
]);
const HARNESS_SANDBOX_NETWORK_KEYS = Object.freeze([
    "enforcement",
    "mode",
]);
const HARNESS_SANDBOX_FILESYSTEM_KEYS = Object.freeze([
    "aclJournalRestored",
    "exactLaunchClosure",
    "hostWriteDenied",
    "immutableCandidate",
    "outputTemp",
    "stagedHarness",
]);
const HARNESS_SANDBOX_JOB_KEYS = Object.freeze([
    "activeProcessLimit",
    "cpuRatePercent",
    "cpuTimeMs",
    "descendantsContained",
    "jobMemoryBytes",
    "killOnJobClose",
    "processMemoryBytes",
    "terminationGraceMs",
    "uiRestrictions",
    "wallTimeMs",
]);
const SANDBOX_POLICY_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-measurement-sandbox-policy-identity-v1";
const SEARCH_POLICY_KEYS = Object.freeze([
    "archiveCaps",
    "dedupPolicy",
    "mandatoryEscapeRounds",
    "minRoundsBeforePlateau",
    "operatorWeights",
    "plateauMinImprovement",
    "plateauWindow",
    "promptCaps",
    "stopOnFirstAccept",
]);
const ARCHIVE_CAP_KEYS = Object.freeze([
    "accepted",
    "duplicateIndex",
    "invalidMetrics",
    "lessonGroups",
    "mechanismGroups",
    "nearMisses",
    "rejected",
]);
const PROMPT_CAP_KEYS = Object.freeze([
    "parentEvidenceIds",
    "promptContextRefs",
]);

function requireNonEmptyString(value, field, maximum = 4096) {
    if (typeof value !== "string" || value.trim().length === 0 || value.length > maximum) {
        throw new ContractError(`${field} must be a non-empty string of at most ${maximum} characters`, {
            field,
        });
    }
    return value;
}

function requireBoundedText(value, field, maximumCharacters, maximumBytes) {
    if (typeof value !== "string"
        || value.trim().length === 0
        || value.length > maximumCharacters
        || Buffer.byteLength(value, "utf8") > maximumBytes) {
        throw new ContractError(
            `${field} must be non-empty text of at most ${maximumCharacters} characters and ${maximumBytes} UTF-8 bytes`,
            { field, maximumCharacters, maximumBytes },
        );
    }
    return value;
}

export function isSafeDomainIdentifier(value) {
    return typeof value === "string"
        && value.length > 0
        && value.length <= 128
        && SAFE_IDENTIFIER.test(value)
        && value !== "."
        && value !== ".."
        && !value.endsWith(".")
        && !value.includes("..")
        && !FORBIDDEN_IDENTIFIERS.has(value.toLowerCase());
}

function requireIdentifier(value, field) {
    if (!isSafeDomainIdentifier(value)) {
        throw new ContractError(
            `${field} must be a safe identifier, not a filesystem path or prototype key`,
            {
                field,
                value,
            },
        );
    }
    return value;
}

function requirePositiveSafeInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        throw new ContractError(`${field} must be a positive safe integer no greater than ${maximum}`, {
            field,
            value,
        });
    }

    return value;
}

function requireSafeIntegerInRange(value, field, minimum, maximum) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new ContractError(
            `${field} must be a safe integer between ${minimum} and ${maximum}`,
            { field, value, minimum, maximum },
        );
    }
    return value;
}

function requireFiniteNumberInRange(value, field, minimum, maximum) {
    if (typeof value !== "number"
        || !Number.isFinite(value)
        || value < minimum
        || value > maximum) {
        throw new ContractError(
            `${field} must be a finite number between ${minimum} and ${maximum}`,
            { field, value, minimum, maximum },
        );
    }
    return value;
}

function requireExactObjectKeys(value, field, expectedKeys) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new ContractError(`${field} must be an object`, { field });
    }
    const actual = Object.keys(value).sort();
    const expected = [...expectedKeys].sort();
    if (!canonicalEqual(actual, expected)) {
        throw new ContractError(`${field} must contain exactly the canonical fields`, {
            field,
            expected,
            actual,
        });
    }
}

function requireArtifactHash(value, field) {
    if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value)) {
        throw new ContractError(`${field} must be a sha256:<64hex> artifact hash`, {
            field,
            value,
        });
    }
    return value;
}

function requireTaggedSha256(value, field) {
    if (typeof value !== "string" || !TAGGED_SHA256.test(value)) {
        throw new ContractError(`${field} must be an algorithm-tagged SHA-256`, {
            field,
            value,
        });
    }
    return value;
}

function normalizeHarnessDependencies(value) {
        if (!Array.isArray(value) || value.length > 64) {
            throw new ContractError("harnessIdentity.dependencyHashes must be an array of at most 64 items");
        }
        const paths = new Set();
        return value.map((dependency, index) => {
            const field = `harnessIdentity.dependencyHashes[${index}]`;
            requireExactObjectKeys(dependency, field, HARNESS_DEPENDENCY_KEYS);
            const dependencyPath = requireNonEmptyString(dependency.path, `${field}.path`, 32767);
            const pathKey = process.platform === "win32"
                ? dependencyPath.toLowerCase()
                : dependencyPath;
            if (paths.has(pathKey)) {
                throw new ContractError("harnessIdentity.dependencyHashes paths must be unique", {
                    path: dependencyPath,
                });
            }
            paths.add(pathKey);
            return {
                path: dependencyPath,
                role: requireNonEmptyString(dependency.role, `${field}.role`, 64),
                sha256: requireTaggedSha256(dependency.sha256, `${field}.sha256`),
            };
        });
}

function normalizeHarnessSandbox(value, executesCandidateCode) {
        requireExactObjectKeys(value, "harnessIdentity.sandbox", HARNESS_SANDBOX_KEYS);
        if (typeof value.required !== "boolean") {
            throw new ContractError("harnessIdentity.sandbox.required must be boolean");
        }
        if (value.required !== executesCandidateCode) {
            throw new ContractError(
                "harnessIdentity.sandbox.required must match executesCandidateCode",
            );
        }
        if (!value.required) {
            if (value.policyIdentity !== null || value.policyDigest !== null) {
                throw new ContractError(
                    "A non-executing harness must freeze a null sandbox policy identity/digest",
                );
            }
            return {
                required: false,
                policyIdentity: null,
                policyDigest: null,
            };
        }
        requireExactObjectKeys(
            value.policyIdentity,
            "harnessIdentity.sandbox.policyIdentity",
            HARNESS_SANDBOX_IDENTITY_KEYS,
        );
        requireExactObjectKeys(
            value.policyIdentity.securityContext,
            "harnessIdentity.sandbox.policyIdentity.securityContext",
            HARNESS_SANDBOX_SECURITY_CONTEXT_KEYS,
        );
        requireExactObjectKeys(
            value.policyIdentity.network,
            "harnessIdentity.sandbox.policyIdentity.network",
            HARNESS_SANDBOX_NETWORK_KEYS,
        );
        requireExactObjectKeys(
            value.policyIdentity.filesystem,
            "harnessIdentity.sandbox.policyIdentity.filesystem",
            HARNESS_SANDBOX_FILESYSTEM_KEYS,
        );
        requireExactObjectKeys(
            value.policyIdentity.job,
            "harnessIdentity.sandbox.policyIdentity.job",
            HARNESS_SANDBOX_JOB_KEYS,
        );
        const requireBoolean = (input, field) => {
            if (typeof input !== "boolean") {
                throw new ContractError(`${field} must be boolean`);
            }
            return input;
        };
        const capabilities = value.policyIdentity.securityContext.capabilities;
        if (!Array.isArray(capabilities)
            || capabilities.length > 64
            || capabilities.some((capability) =>
                typeof capability !== "string"
                || capability.length === 0
                || capability.length > 256)) {
            throw new ContractError(
                "harnessIdentity.sandbox.policyIdentity.securityContext.capabilities must be a bounded string array",
            );
        }
        const policyIdentity = {
            primitive: requireNonEmptyString(
                value.policyIdentity.primitive,
                "harnessIdentity.sandbox.policyIdentity.primitive",
                128,
            ),
            providerId: requireIdentifier(
                value.policyIdentity.providerId,
                "harnessIdentity.sandbox.policyIdentity.providerId",
            ),
            providerVersion: requireIdentifier(
                value.policyIdentity.providerVersion,
                "harnessIdentity.sandbox.policyIdentity.providerVersion",
            ),
            policyId: requireIdentifier(
                value.policyIdentity.policyId,
                "harnessIdentity.sandbox.policyIdentity.policyId",
            ),
            helperSourceHash: requireTaggedSha256(
                value.policyIdentity.helperSourceHash,
                "harnessIdentity.sandbox.policyIdentity.helperSourceHash",
            ),
            helperBinaryHash: requireTaggedSha256(
                value.policyIdentity.helperBinaryHash,
                "harnessIdentity.sandbox.policyIdentity.helperBinaryHash",
            ),
            launcherId: requireIdentifier(
                value.policyIdentity.launcherId,
                "harnessIdentity.sandbox.policyIdentity.launcherId",
            ),
            launcherBinaryHash: requireTaggedSha256(
                value.policyIdentity.launcherBinaryHash,
                "harnessIdentity.sandbox.policyIdentity.launcherBinaryHash",
            ),
            launcherScriptHash: requireTaggedSha256(
                value.policyIdentity.launcherScriptHash,
                "harnessIdentity.sandbox.policyIdentity.launcherScriptHash",
            ),
            securityContext: {
                appContainer: requireBoolean(
                    value.policyIdentity.securityContext.appContainer,
                    "harnessIdentity.sandbox.policyIdentity.securityContext.appContainer",
                ),
                lowIntegrity: requireBoolean(
                    value.policyIdentity.securityContext.lowIntegrity,
                    "harnessIdentity.sandbox.policyIdentity.securityContext.lowIntegrity",
                ),
                capabilities: [...capabilities],
                loopbackExemptionRejected: requireBoolean(
                    value.policyIdentity.securityContext.loopbackExemptionRejected,
                    "harnessIdentity.sandbox.policyIdentity.securityContext.loopbackExemptionRejected",
                ),
            },
            network: {
                mode: requireNonEmptyString(
                    value.policyIdentity.network.mode,
                    "harnessIdentity.sandbox.policyIdentity.network.mode",
                    128,
                ),
                enforcement: requireNonEmptyString(
                    value.policyIdentity.network.enforcement,
                    "harnessIdentity.sandbox.policyIdentity.network.enforcement",
                    1024,
                ),
            },
            filesystem: {
                stagedHarness: requireNonEmptyString(
                    value.policyIdentity.filesystem.stagedHarness,
                    "harnessIdentity.sandbox.policyIdentity.filesystem.stagedHarness",
                    128,
                ),
                immutableCandidate: requireNonEmptyString(
                    value.policyIdentity.filesystem.immutableCandidate,
                    "harnessIdentity.sandbox.policyIdentity.filesystem.immutableCandidate",
                    128,
                ),
                outputTemp: requireNonEmptyString(
                    value.policyIdentity.filesystem.outputTemp,
                    "harnessIdentity.sandbox.policyIdentity.filesystem.outputTemp",
                    128,
                ),
                aclJournalRestored: requireBoolean(
                    value.policyIdentity.filesystem.aclJournalRestored,
                    "harnessIdentity.sandbox.policyIdentity.filesystem.aclJournalRestored",
                ),
                exactLaunchClosure: requireBoolean(
                    value.policyIdentity.filesystem.exactLaunchClosure,
                    "harnessIdentity.sandbox.policyIdentity.filesystem.exactLaunchClosure",
                ),
                hostWriteDenied: requireBoolean(
                    value.policyIdentity.filesystem.hostWriteDenied,
                    "harnessIdentity.sandbox.policyIdentity.filesystem.hostWriteDenied",
                ),
            },
            job: {
                killOnJobClose: requireBoolean(
                    value.policyIdentity.job.killOnJobClose,
                    "harnessIdentity.sandbox.policyIdentity.job.killOnJobClose",
                ),
                descendantsContained: requireBoolean(
                    value.policyIdentity.job.descendantsContained,
                    "harnessIdentity.sandbox.policyIdentity.job.descendantsContained",
                ),
                uiRestrictions: requireBoolean(
                    value.policyIdentity.job.uiRestrictions,
                    "harnessIdentity.sandbox.policyIdentity.job.uiRestrictions",
                ),
                activeProcessLimit: requirePositiveSafeInteger(
                    value.policyIdentity.job.activeProcessLimit,
                    "harnessIdentity.sandbox.policyIdentity.job.activeProcessLimit",
                ),
                processMemoryBytes: requirePositiveSafeInteger(
                    value.policyIdentity.job.processMemoryBytes,
                    "harnessIdentity.sandbox.policyIdentity.job.processMemoryBytes",
                ),
                jobMemoryBytes: requirePositiveSafeInteger(
                    value.policyIdentity.job.jobMemoryBytes,
                    "harnessIdentity.sandbox.policyIdentity.job.jobMemoryBytes",
                ),
                cpuRatePercent: requirePositiveSafeInteger(
                    value.policyIdentity.job.cpuRatePercent,
                    "harnessIdentity.sandbox.policyIdentity.job.cpuRatePercent",
                ),
                cpuTimeMs: requirePositiveSafeInteger(
                    value.policyIdentity.job.cpuTimeMs,
                    "harnessIdentity.sandbox.policyIdentity.job.cpuTimeMs",
                ),
                wallTimeMs: requirePositiveSafeInteger(
                    value.policyIdentity.job.wallTimeMs,
                    "harnessIdentity.sandbox.policyIdentity.job.wallTimeMs",
                ),
                terminationGraceMs: requirePositiveSafeInteger(
                    value.policyIdentity.job.terminationGraceMs,
                    "harnessIdentity.sandbox.policyIdentity.job.terminationGraceMs",
                ),
            },
        };
        if (policyIdentity.job.cpuRatePercent > 100) {
            throw new ContractError(
                "harnessIdentity.sandbox.policyIdentity.job.cpuRatePercent must be <= 100",
            );
        }
        if (policyIdentity.job.jobMemoryBytes
            < policyIdentity.job.processMemoryBytes) {
            throw new ContractError(
                "harnessIdentity.sandbox.policyIdentity.job.jobMemoryBytes must be >= processMemoryBytes",
            );
        }
        const policyDigest = requireTaggedSha256(
            value.policyDigest,
            "harnessIdentity.sandbox.policyDigest",
        );
        const expectedDigest = hashCanonical(
            policyIdentity,
            SANDBOX_POLICY_IDENTITY_HASH_ALGORITHM,
        );
        if (policyDigest !== expectedDigest) {
            throw new ContractError(
                "harnessIdentity.sandbox.policyDigest must match the canonical policy identity",
                { expected: expectedDigest, actual: policyDigest },
            );
        }
        return {
            required: true,
            policyIdentity,
            policyDigest,
        };
}

function normalizeHarnessIdentity(value, harnessId, parserVersion) {
        requireExactObjectKeys(value, "harnessIdentity", HARNESS_IDENTITY_KEYS);
        if (value.version !== 1) {
            throw new ContractError("harnessIdentity.version must be 1");
        }
        if (value.allowlistVersion !== 1) {
            throw new ContractError("harnessIdentity.allowlistVersion must be 1");
        }
        const frozenHarnessId = requireIdentifier(value.harnessId, "harnessIdentity.harnessId");
        if (frozenHarnessId !== harnessId) {
            throw new ContractError("harnessIdentity.harnessId must match harnessId");
        }
        const frozenParserVersion = requireIdentifier(
            value.parserVersion,
            "harnessIdentity.parserVersion",
        );
        if (frozenParserVersion !== parserVersion) {
            throw new ContractError("harnessIdentity.parserVersion must match parserVersion");
        }
        if (typeof value.executesCandidateCode !== "boolean") {
            throw new ContractError("harnessIdentity.executesCandidateCode must be boolean");
        }
        return {
            version: 1,
            harnessId: frozenHarnessId,
            allowlistVersion: 1,
            allowlistFileHash: requireTaggedSha256(
                value.allowlistFileHash,
                "harnessIdentity.allowlistFileHash",
            ),
            harnessEntryHash: requireTaggedSha256(
                value.harnessEntryHash,
                "harnessIdentity.harnessEntryHash",
            ),
            executableHash: requireTaggedSha256(
                value.executableHash,
                "harnessIdentity.executableHash",
            ),
            dependencyHashes: normalizeHarnessDependencies(value.dependencyHashes),
            argvTemplateHash: requireTaggedSha256(
                value.argvTemplateHash,
                "harnessIdentity.argvTemplateHash",
            ),
            allowedEnvHash: requireTaggedSha256(
                value.allowedEnvHash,
                "harnessIdentity.allowedEnvHash",
            ),
            parserVersion: frozenParserVersion,
            parserVersionHash: requireTaggedSha256(
                value.parserVersionHash,
                "harnessIdentity.parserVersionHash",
            ),
            parserSourceHash: requireTaggedSha256(
                value.parserSourceHash,
                "harnessIdentity.parserSourceHash",
            ),
            executesCandidateCode: value.executesCandidateCode,
            sandbox: normalizeHarnessSandbox(value.sandbox, value.executesCandidateCode),
        };
}

function normalizePath(path, field) {
    const segments = typeof path === "string" ? path.split(".") : path;
    if (!Array.isArray(segments)
        || segments.length === 0
        || segments.length > CONTRACT_LIMITS.acceptancePathSegments
        || segments.some((segment) =>
            typeof segment !== "string"
            || segment.length === 0
            || segment.length > CONTRACT_LIMITS.acceptancePathSegmentCharacters
            || Buffer.byteLength(segment, "utf8")
                > CONTRACT_LIMITS.acceptanceValueStringBytes)) {
        throw new ContractError(`${field} must be a non-empty field path`, {
            field,
            maximumSegments: CONTRACT_LIMITS.acceptancePathSegments,
            maximumSegmentCharacters:
                CONTRACT_LIMITS.acceptancePathSegmentCharacters,
        }, ERROR_CODES.INVALID_ACCEPTANCE_PREDICATE);
    }
    return [...segments];
}

function predicateError(message, details = null) {
    throw new ContractError(message, details, ERROR_CODES.INVALID_ACCEPTANCE_PREDICATE);
}

function normalizeAcceptanceValue(value, field, state, depth = 0) {
    if (depth > CONTRACT_LIMITS.acceptanceValueDepth) {
        predicateError("Acceptance predicate comparison value exceeds maximum nesting depth", {
            field,
            maximumDepth: CONTRACT_LIMITS.acceptanceValueDepth,
        });
    }
    state.nodes += 1;
    if (state.nodes > CONTRACT_LIMITS.acceptanceValueNodes) {
        predicateError("Acceptance predicate comparison value exceeds maximum complexity", {
            field,
            maximumNodes: CONTRACT_LIMITS.acceptanceValueNodes,
        });
    }
    if (value === null || typeof value === "boolean") {
        return value;
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value)) {
            predicateError("Acceptance predicate comparison numbers must be finite", { field });
        }
        return value;
    }
    if (typeof value === "string") {
        if (value.length > CONTRACT_LIMITS.acceptanceValueStringCharacters
            || Buffer.byteLength(value, "utf8")
                > CONTRACT_LIMITS.acceptanceValueStringBytes) {
            predicateError("Acceptance predicate comparison string exceeds its bound", {
                field,
                maximumCharacters:
                    CONTRACT_LIMITS.acceptanceValueStringCharacters,
                maximumBytes: CONTRACT_LIMITS.acceptanceValueStringBytes,
            });
        }
        return value;
    }
    if (Array.isArray(value)) {
        if (value.length > CONTRACT_LIMITS.acceptanceValueArrayItems) {
            predicateError("Acceptance predicate comparison array exceeds its item bound", {
                field,
                maximumItems: CONTRACT_LIMITS.acceptanceValueArrayItems,
            });
        }
        return value.map((item, index) =>
            normalizeAcceptanceValue(item, `${field}[${index}]`, state, depth + 1));
    }
    if (value === null || typeof value !== "object") {
        predicateError("Acceptance predicate comparison value must be canonical JSON", {
            field,
        });
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        predicateError("Acceptance predicate comparison objects must be plain objects", {
            field,
        });
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
        predicateError("Acceptance predicate comparison objects cannot have symbol keys", {
            field,
        });
    }
    const keys = Object.keys(value);
    if (keys.length > CONTRACT_LIMITS.acceptanceValueObjectProperties) {
        predicateError("Acceptance predicate comparison object exceeds its property bound", {
            field,
            maximumProperties:
                CONTRACT_LIMITS.acceptanceValueObjectProperties,
        });
    }
    const output = {};
    for (const key of keys) {
        if (key.length > CONTRACT_LIMITS.acceptanceValueStringCharacters
            || Buffer.byteLength(key, "utf8")
                > CONTRACT_LIMITS.acceptanceValueStringBytes) {
            predicateError("Acceptance predicate comparison object key exceeds its bound", {
                field,
                key,
            });
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) {
            predicateError("Acceptance predicate comparison objects cannot use accessors", {
                field,
                key,
            });
        }
        output[key] = normalizeAcceptanceValue(
            descriptor.value,
            `${field}.${key}`,
            state,
            depth + 1,
        );
    }
    return output;
}

function normalizePredicateNode(predicate, state, depth = 0) {
    if (depth > CONTRACT_LIMITS.acceptancePredicateDepth) {
        predicateError("Acceptance predicate exceeds maximum nesting depth");
    }
    if (predicate === null || typeof predicate !== "object" || Array.isArray(predicate)) {
        predicateError("Acceptance predicate must be an object");
    }
    state.nodes += 1;
    if (state.nodes > CONTRACT_LIMITS.acceptancePredicateNodes) {
        predicateError("Acceptance predicate exceeds maximum node complexity", {
            maximumNodes: CONTRACT_LIMITS.acceptancePredicateNodes,
        });
    }

    switch (predicate.kind) {
        case "harness_pass":
            requireExactObjectKeys(predicate, "acceptancePredicate", ["kind"]);
            return { kind: "harness_pass" };
        case "constant":
            requireExactObjectKeys(predicate, "acceptancePredicate", ["kind", "value"]);
            if (typeof predicate.value !== "boolean") {
                predicateError("constant predicate value must be boolean");
            }
            return { kind: "constant", value: predicate.value };
        case "field_equals":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "path", "value"],
            );
            return {
                kind: "field_equals",
                path: normalizePath(predicate.path, "acceptancePredicate.path"),
                value: normalizeAcceptanceValue(
                    predicate.value,
                    "acceptancePredicate.value",
                    { nodes: 0 },
                ),
            };
        case "number_compare":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "operator", "path", "value"],
            );
            if (!COMPARISON_OPERATORS.includes(predicate.operator)) {
                predicateError("number_compare predicate has an unsupported operator", {
                    operator: predicate.operator,
                });
            }
            if (typeof predicate.value !== "number" || !Number.isFinite(predicate.value)) {
                predicateError("number_compare predicate value must be finite");
            }
            return {
                kind: "number_compare",
                path: normalizePath(predicate.path, "acceptancePredicate.path"),
                operator: predicate.operator,
                value: predicate.value,
            };
        case "metric_compare":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "metric", "operator", "value"],
            );
            requireNonEmptyString(predicate.metric, "acceptancePredicate.metric", 128);
            if (!COMPARISON_OPERATORS.includes(predicate.operator)) {
                predicateError("metric_compare predicate has an unsupported operator", {
                    operator: predicate.operator,
                });
            }
            if (typeof predicate.value !== "number" || !Number.isFinite(predicate.value)) {
                predicateError("metric_compare predicate value must be finite");
            }
            return {
                kind: "metric_compare",
                metric: predicate.metric,
                operator: predicate.operator,
                value: predicate.value,
            };
        case "all":
        case "any":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "predicates"],
            );
            if (!Array.isArray(predicate.predicates)
                || predicate.predicates.length === 0
                || predicate.predicates.length
                    > CONTRACT_LIMITS.acceptancePredicateChildren) {
                predicateError(`${predicate.kind} predicate requires at least one child`);
            }
            return {
                kind: predicate.kind,
                predicates: predicate.predicates.map((child) =>
                    normalizePredicateNode(child, state, depth + 1)),
            };
        case "not":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "predicate"],
            );
            return {
                kind: "not",
                predicate: normalizePredicateNode(predicate.predicate, state, depth + 1),
            };
        default:
            predicateError("Unknown acceptance predicate kind", {
                kind: predicate.kind ?? null,
            });
    }
}

function normalizePredicate(predicate) {
    const normalized = normalizePredicateNode(predicate, { nodes: 0 });
    const bytes = Buffer.byteLength(canonicalJson(normalized), "utf8");
    if (bytes > CONTRACT_LIMITS.acceptancePredicateBytes) {
        predicateError("Acceptance predicate exceeds maximum serialized size", {
            bytes,
            maximumBytes: CONTRACT_LIMITS.acceptancePredicateBytes,
        });
    }
    return normalized;
}

function valueAtPath(root, path) {
    let current = root;
    for (const segment of path) {
        if (current === null
            || typeof current !== "object"
            || !Object.hasOwn(current, segment)) {
            return { found: false, value: null };
        }
        current = current[segment];
    }
    return { found: true, value: current };
}

function compareNumbers(actual, operator, expected) {
    if (typeof actual !== "number" || !Number.isFinite(actual)) {
        return false;
    }
    switch (operator) {
        case "<": return actual < expected;
        case "<=": return actual <= expected;
        case "==": return actual === expected;
        case ">=": return actual >= expected;
        case ">": return actual > expected;
        default: return false;
    }
}

function evaluatePredicate(predicate, result) {
    switch (predicate.kind) {
        case "harness_pass":
            return result?.pass === true;
        case "constant":
            return predicate.value;
        case "field_equals": {
            const actual = valueAtPath(result, predicate.path);
            return actual.found && canonicalEqual(actual.value, predicate.value);
        }
        case "number_compare": {
            const actual = valueAtPath(result, predicate.path);
            return actual.found && compareNumbers(actual.value, predicate.operator, predicate.value);
        }
        case "metric_compare":
            return compareNumbers(result?.metrics?.[predicate.metric], predicate.operator, predicate.value);
        case "all":
            return predicate.predicates.every((child) => evaluatePredicate(child, result));
        case "any":
            return predicate.predicates.some((child) => evaluatePredicate(child, result));
        case "not":
            return !evaluatePredicate(predicate.predicate, result);
        default:
            return false;
    }
}

function numericFailureDistance(actual, operator, expected) {
    if (typeof actual !== "number" || !Number.isFinite(actual)) {
        return null;
    }
    let gap;
    switch (operator) {
        case "<":
            gap = actual < expected ? 0 : actual - expected + Number.EPSILON;
            break;
        case "<=":
            gap = actual <= expected ? 0 : actual - expected;
            break;
        case "==":
            gap = Math.abs(actual - expected);
            break;
        case ">=":
            gap = actual >= expected ? 0 : expected - actual;
            break;
        case ">":
            gap = actual > expected ? 0 : expected - actual + Number.EPSILON;
            break;
        default:
            return null;
    }
    return gap / Math.max(1, Math.abs(expected));
}

function assessPredicate(predicate, result) {
    switch (predicate.kind) {
        case "harness_pass":
            return {
                satisfied: result?.pass === true,
                near: false,
                distance: result?.pass === true ? 0 : null,
                failedLeaves: result?.pass === true ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: result?.pass !== true,
            };
        case "constant":
            return {
                satisfied: predicate.value,
                near: false,
                distance: predicate.value ? 0 : null,
                failedLeaves: predicate.value ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        case "field_equals": {
            const actual = valueAtPath(result, predicate.path);
            const satisfied = actual.found && canonicalEqual(actual.value, predicate.value);
            return {
                satisfied,
                near: false,
                distance: satisfied ? 0 : null,
                failedLeaves: satisfied ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        }
        case "number_compare": {
            const actual = valueAtPath(result, predicate.path);
            const satisfied = actual.found
                && compareNumbers(actual.value, predicate.operator, predicate.value);
            const distance = actual.found
                ? numericFailureDistance(actual.value, predicate.operator, predicate.value)
                : null;
            return {
                satisfied,
                near: !satisfied && distance !== null && distance <= 0.1,
                distance,
                failedLeaves: satisfied ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        }
        case "metric_compare": {
            const actual = result?.metrics?.[predicate.metric];
            const satisfied = compareNumbers(actual, predicate.operator, predicate.value);
            const distance = numericFailureDistance(actual, predicate.operator, predicate.value);
            return {
                satisfied,
                near: !satisfied && distance !== null && distance <= 0.1,
                distance,
                failedLeaves: satisfied ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        }
        case "all": {
            const children = predicate.predicates.map((child) => assessPredicate(child, result));
            const failed = children.filter((child) => !child.satisfied);
            const booleanGateOnly = failed.length === 1
                && failed[0].booleanGateFailure
                && children.length > 1;
            return {
                satisfied: failed.length === 0,
                near: failed.length === 1 && (failed[0].near || booleanGateOnly),
                distance: failed.length === 0
                    ? 0
                    : failed.length === 1
                        ? failed[0].distance
                        : null,
                failedLeaves: children.reduce((sum, child) => sum + child.failedLeaves, 0),
                leafCount: children.reduce((sum, child) => sum + child.leafCount, 0),
                booleanGateFailure: false,
            };
        }
        case "any": {
            const children = predicate.predicates.map((child) => assessPredicate(child, result));
            const satisfied = children.some((child) => child.satisfied);
            const nearChildren = children.filter((child) => child.near);
            const distances = nearChildren
                .map((child) => child.distance)
                .filter((distance) => distance !== null);
            return {
                satisfied,
                near: !satisfied && nearChildren.length > 0,
                distance: distances.length > 0 ? Math.min(...distances) : null,
                failedLeaves: satisfied
                    ? 0
                    : Math.min(...children.map((child) => child.failedLeaves)),
                leafCount: children.reduce((sum, child) => sum + child.leafCount, 0),
                booleanGateFailure: false,
            };
        }
        case "not": {
            const child = assessPredicate(predicate.predicate, result);
            return {
                satisfied: !child.satisfied,
                near: false,
                distance: !child.satisfied ? 0 : null,
                failedLeaves: !child.satisfied ? 0 : 1,
                leafCount: child.leafCount,
                booleanGateFailure: false,
            };
        }
        default:
            return {
                satisfied: false,
                near: false,
                distance: null,
                failedLeaves: 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
    }
}

function normalizeDeclaredLimits(limits) {
    if (limits === null || typeof limits !== "object" || Array.isArray(limits)) {
        throw new ContractError("declaredLimits must be an object");
    }
    const normalized = immutableCanonical(limits);
    for (const field of ["maxCommands", "commandBudget", "maxEvidence", "maxSearchRevisions"]) {
        if (Object.hasOwn(normalized, field)
            && (!Number.isSafeInteger(normalized[field]) || normalized[field] < 1)) {
            throw new ContractError(`declaredLimits.${field} must be a positive safe integer`);
        }
    }
    return normalized;
}

function normalizeValidationCases(cases) {
    if (!Array.isArray(cases)
        || cases.length < 2
        || cases.length > CONTRACT_LIMITS.validationCases) {
        throw new ContractError("validationCases must contain at least one accept and one reject case");
    }
    const ids = new Set();
    const expectations = new Set();
    const normalized = cases.map((item, index) => {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
            throw new ContractError(`validationCases[${index}] must be an object`);
        }
        const id = requireIdentifier(item.id, `validationCases[${index}].id`);
        if (ids.has(id)) {
            throw new ContractError("validationCases IDs must be unique", { id });
        }
        ids.add(id);
        if (!VALIDATION_EXPECTATIONS.includes(item.expectation)) {
            throw new ContractError(
                `validationCases[${index}].expectation must be accept or reject`,
            );
        }
        expectations.add(item.expectation);
        return {
            id,
            expectation: item.expectation,
            artifactHash: requireArtifactHash(
                item.artifactHash,
                `validationCases[${index}].artifactHash`,
            ),
        };
    });
    if (!expectations.has("accept") || !expectations.has("reject")) {
        throw new ContractError("validationCases must contain at least one accept and one reject case");
    }
    return normalized;
}

function normalizeIdentifierArray(value, field, minimum, maximum) {
    if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
        throw new ContractError(`${field} must contain between ${minimum} and ${maximum} identifiers`);
    }
    const normalized = value.map((item, index) => requireIdentifier(item, `${field}[${index}]`));
    if (new Set(normalized).size !== normalized.length) {
        throw new ContractError(`${field} must contain unique identifiers`);
    }
    return normalized;
}

function normalizeSearch(search, topology) {
    if (search === null || typeof search !== "object" || Array.isArray(search)) {
        throw new ContractError("search must be an object");
    }
    const normalized = {
        workerModels: normalizeIdentifierArray(
            search.workerModels,
            "search.workerModels",
            1,
            CONTRACT_LIMITS.workerModels,
        ),
        candidatesPerRound: requirePositiveSafeInteger(
            search.candidatesPerRound,
            "search.candidatesPerRound",
            CONTRACT_LIMITS.candidatesPerRound,
        ),
        maxRounds: requirePositiveSafeInteger(
            search.maxRounds,
            "search.maxRounds",
            CONTRACT_LIMITS.maxRounds,
        ),
    };
    if (normalized.candidatesPerRound * normalized.maxRounds
        > CONTRACT_LIMITS.maxEvaluations) {
        throw new ContractError(
            `search capacity cannot exceed ${CONTRACT_LIMITS.maxEvaluations} candidate evaluations`,
        );
    }
    const requiresBoundedCandidateIds =
        topology === "finite_enumerable" || topology === "bounded_parameterized";
    const hasBoundedCandidateIds =
        search.boundedCandidateIds !== undefined && search.boundedCandidateIds !== null;
    if (requiresBoundedCandidateIds && !hasBoundedCandidateIds) {
        throw new ContractError(
            "search.boundedCandidateIds is required for finite_enumerable and bounded_parameterized topologies",
        );
    }
    if (!requiresBoundedCandidateIds && hasBoundedCandidateIds) {
        throw new ContractError(
            "search.boundedCandidateIds is only valid for finite or bounded topologies",
        );
    }
    if (hasBoundedCandidateIds) {
        normalized.boundedCandidateIds = normalizeIdentifierArray(
            search.boundedCandidateIds,
            "search.boundedCandidateIds",
            1,
            CONTRACT_LIMITS.boundedCandidateIds,
        );
        if (normalized.boundedCandidateIds.length
            > normalized.candidatesPerRound * normalized.maxRounds) {
            throw new ContractError(
                "search capacity must cover every boundedCandidateId",
            );
        }
    }
    return normalized;
}

function normalizeImpossibilityPolicy(input, topology) {
    if (topology !== "certified_impossibility") {
        if (input !== undefined && input !== null) {
            throw new ContractError(
                "impossibilityPolicy is only valid for certified_impossibility topology",
            );
        }
        return null;
    }
    const policy = input ?? DEFAULT_IMPOSSIBILITY_POLICY;
    requireExactObjectKeys(
        policy,
        "impossibilityPolicy",
        ["certificateVersion", "requestVersion", "trigger"],
    );
    if (policy.trigger !== DEFAULT_IMPOSSIBILITY_POLICY.trigger
        || policy.requestVersion !== DEFAULT_IMPOSSIBILITY_POLICY.requestVersion
        || policy.certificateVersion !== DEFAULT_IMPOSSIBILITY_POLICY.certificateVersion) {
        throw new ContractError(
            "impossibilityPolicy must use the canonical certified-impossibility policy",
        );
    }
    return immutableCanonical(policy);
}

export function createSearchPolicy(input) {
    requireExactObjectKeys(input, "searchPolicy", SEARCH_POLICY_KEYS);
    if (typeof input.stopOnFirstAccept !== "boolean") {
        throw new ContractError("searchPolicy.stopOnFirstAccept must be boolean");
    }

    const plateauWindow = requireSafeIntegerInRange(
        input.plateauWindow,
        "searchPolicy.plateauWindow",
        1,
        SEARCH_POLICY_LIMITS.plateauWindow,
    );
    const minRoundsBeforePlateau = requireSafeIntegerInRange(
        input.minRoundsBeforePlateau,
        "searchPolicy.minRoundsBeforePlateau",
        1,
        SEARCH_POLICY_LIMITS.minRoundsBeforePlateau,
    );
    if (minRoundsBeforePlateau < plateauWindow) {
        throw new ContractError(
            "searchPolicy.minRoundsBeforePlateau must be at least plateauWindow",
        );
    }
    const plateauMinImprovement = requireFiniteNumberInRange(
        input.plateauMinImprovement,
        "searchPolicy.plateauMinImprovement",
        0,
        Number.MAX_SAFE_INTEGER,
    );
    const mandatoryEscapeRounds = requireSafeIntegerInRange(
        input.mandatoryEscapeRounds,
        "searchPolicy.mandatoryEscapeRounds",
        1,
        SEARCH_POLICY_LIMITS.mandatoryEscapeRounds,
    );

    requireExactObjectKeys(
        input.operatorWeights,
        "searchPolicy.operatorWeights",
        SEARCH_OPERATORS,
    );
    const operatorWeights = {};
    for (const operator of SEARCH_OPERATORS) {
        operatorWeights[operator] = requireSafeIntegerInRange(
            input.operatorWeights[operator],
            `searchPolicy.operatorWeights.${operator}`,
            0,
            1000000,
        );
    }
    if (operatorWeights.fresh < 1) {
        throw new ContractError("searchPolicy.operatorWeights.fresh must be at least 1");
    }
    if (ESCAPE_SEARCH_OPERATORS.reduce(
        (sum, operator) => sum + operatorWeights[operator],
        0,
    ) < 1) {
        throw new ContractError(
            "searchPolicy.operatorWeights must enable at least one mandatory-escape operator",
        );
    }
    if (operatorWeights.diversification + operatorWeights.restart < 1) {
        throw new ContractError(
            "searchPolicy.operatorWeights must enable a parent-free mandatory-escape fallback",
        );
    }

    requireExactObjectKeys(
        input.archiveCaps,
        "searchPolicy.archiveCaps",
        ARCHIVE_CAP_KEYS,
    );
    const archiveCaps = {};
    for (const key of ARCHIVE_CAP_KEYS) {
        archiveCaps[key] = requireSafeIntegerInRange(
            input.archiveCaps[key],
            `searchPolicy.archiveCaps.${key}`,
            1,
            SEARCH_POLICY_LIMITS.archiveCaps[key],
        );
    }

    requireExactObjectKeys(
        input.promptCaps,
        "searchPolicy.promptCaps",
        PROMPT_CAP_KEYS,
    );
    const promptCaps = {
        parentEvidenceIds: requireSafeIntegerInRange(
            input.promptCaps.parentEvidenceIds,
            "searchPolicy.promptCaps.parentEvidenceIds",
            1,
            SEARCH_POLICY_LIMITS.promptCaps.parentEvidenceIds,
        ),
        promptContextRefs: requireSafeIntegerInRange(
            input.promptCaps.promptContextRefs,
            "searchPolicy.promptCaps.promptContextRefs",
            1,
            SEARCH_POLICY_LIMITS.promptCaps.promptContextRefs,
        ),
    };
    if (promptCaps.parentEvidenceIds > promptCaps.promptContextRefs) {
        throw new ContractError(
            "searchPolicy.promptCaps.parentEvidenceIds cannot exceed promptContextRefs",
        );
    }

    if (input.dedupPolicy !== "mark") {
        throw new ContractError("searchPolicy.dedupPolicy must be mark");
    }

    return immutableCanonical({
        stopOnFirstAccept: input.stopOnFirstAccept,
        plateauWindow,
        minRoundsBeforePlateau,
        plateauMinImprovement,
        mandatoryEscapeRounds,
        operatorWeights,
        archiveCaps,
        promptCaps,
        dedupPolicy: "mark",
    });
}

export function defaultSearchPolicy() {
    return createSearchPolicy(DEFAULT_SEARCH_POLICY);
}

export const normalizeSearchPolicy = createSearchPolicy;

function normalizeMetrics(metrics) {
    if (metrics === undefined || metrics === null) {
        return [];
    }
    if (!Array.isArray(metrics)) {
        throw new ContractError("metrics must be an array");
    }
    if (metrics.length > CONTRACT_LIMITS.metrics) {
        throw new ContractError(`metrics must contain at most ${CONTRACT_LIMITS.metrics} items`);
    }
    const keys = new Set();
    return metrics.map((metric, index) => {
        if (metric === null || typeof metric !== "object" || Array.isArray(metric)) {
            throw new ContractError(`metrics[${index}] must be an object`);
        }
        const key = requireIdentifier(metric.key, `metrics[${index}].key`);
        if (keys.has(key)) {
            throw new ContractError("metrics keys must be unique", { key });
        }
        keys.add(key);
        if (!METRIC_DIRECTIONS.includes(metric.direction)) {
            throw new ContractError(`metrics[${index}].direction must be min or max`);
        }
        const epsilon = metric.epsilon ?? 0;
        if (typeof epsilon !== "number" || !Number.isFinite(epsilon) || epsilon < 0) {
            throw new ContractError(`metrics[${index}].epsilon must be a finite non-negative number`);
        }
        return {
            key,
            direction: metric.direction,
            epsilon,
        };
    });
}

export function createInvestigationContract(input) {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
        throw new ContractError("Investigation contract input must be an object");
    }

    const objective = requireBoundedText(
        input.objective,
        "objective",
        CONTRACT_LIMITS.objectiveCharacters,
        CONTRACT_LIMITS.objectiveBytes,
    );
    const harnessId = requireIdentifier(input.harnessId, "harnessId");
    if (!HYPOTHESIS_TOPOLOGIES.includes(input.hypothesisTopology)) {
        throw new ContractError("hypothesisTopology is not supported", {
            hypothesisTopology: input.hypothesisTopology ?? null,
        });
    }

    if (!Object.hasOwn(input, "searchPolicy")) {
        throw new ContractError(
            "searchPolicy is required; callers must provide the canonical version-2 search policy",
        );
    }
    const searchPolicy = createSearchPolicy(input.searchPolicy);
    if (!canonicalEqual(searchPolicy, input.searchPolicy)) {
        throw new ContractError("searchPolicy must already be in canonical kernel form");
    }

    const search = normalizeSearch(input.search ?? input, input.hypothesisTopology);
    const impossibilityPolicy = normalizeImpossibilityPolicy(
        input.impossibilityPolicy,
        input.hypothesisTopology,
    );
    const parserVersion = requireIdentifier(input.parserVersion, "parserVersion");
    const contract = {
        objective,
        acceptancePredicate: normalizePredicate(input.acceptancePredicate),
        validationCases: normalizeValidationCases(input.validationCases),
        harnessId,
        hypothesisTopology: input.hypothesisTopology,
        criticality: requireNonEmptyString(input.criticality, "criticality", 64),
        policyVersion: requireIdentifier(input.policyVersion, "policyVersion"),
        parserVersion,
        harnessIdentity: normalizeHarnessIdentity(
            input.harnessIdentity,
            harnessId,
            parserVersion,
        ),
        workerModels: search.workerModels,
        candidatesPerRound: search.candidatesPerRound,
        maxRounds: search.maxRounds,
        ...(search.boundedCandidateIds === undefined
            ? {}
            : { boundedCandidateIds: search.boundedCandidateIds }),
        metrics: normalizeMetrics(input.metrics),
        searchPolicy,
        ...(impossibilityPolicy === null ? {} : { impossibilityPolicy }),
        declaredLimits: normalizeDeclaredLimits(input.declaredLimits),
    };

    return immutableCanonical(contract);
}

export function acceptanceSatisfied(acceptancePredicate, harnessResult) {
    const normalized = normalizePredicate(acceptancePredicate);
    return evaluatePredicate(normalized, harnessResult);
}

export function assessAcceptancePredicate(acceptancePredicate, harnessResult) {
    return immutableCanonical(assessPredicate(
        normalizePredicate(acceptancePredicate),
        harnessResult,
    ));
}

export function validationSatisfied(validationCases, harnessResult) {
    const results = harnessResult?.caseResults;
    if (!Array.isArray(results) || results.length !== validationCases.length) {
        return false;
    }
    const byId = new Map();
    for (const result of results) {
        if (result === null
            || typeof result !== "object"
            || Array.isArray(result)
            || typeof result.id !== "string"
            || byId.has(result.id)) {
            return false;
        }
        byId.set(result.id, result);
    }
    return validationCases.every((validationCase) => {
        const result = byId.get(validationCase.id);
        return result !== undefined
            && result.artifactHash === validationCase.artifactHash
            && result.outcome === validationCase.expectation;
    });
}

export function candidateMetricValues(metrics, harnessResult) {
    const values = {};
    for (const metric of metrics) {
        const value = harnessResult?.metrics?.[metric.key];
        if (typeof value === "number" && Number.isFinite(value)) {
            values[metric.key] = value;
        }
    }
    return immutableCanonical(values);
}

export function candidateMetricsRankable(metrics, metricValues) {
    return metrics.every((metric) =>
        typeof metricValues?.[metric.key] === "number"
        && Number.isFinite(metricValues[metric.key]));
}

export const availableCandidateMetricValues = candidateMetricValues;

export function contractHash(contract) {
    return hashCanonical(contract, CONTRACT_HASH_ALGORITHM);
}

export function commandBudget(contract) {
    return contract.declaredLimits.maxCommands
        ?? contract.declaredLimits.commandBudget
        ?? null;
}
