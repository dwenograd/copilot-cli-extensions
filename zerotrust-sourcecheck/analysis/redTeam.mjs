import { createHash } from "node:crypto";
import nodePath from "node:path";

import { EVASION_CLASSES } from "./assurance.mjs";
import {
    EVASIVE_BLOCKERS,
    EVASIVE_LIMITS,
    createAssuranceAnalysisSnapshot,
    createEvasiveRedTeamCoverageRecord,
    validateAssuranceAnalysisSnapshot,
} from "./evasiveSchemas.mjs";
import {
    evaluateSemanticCoverage,
    validateSemanticCoveragePlan,
} from "./semanticCoverage.mjs";
import { validateSupplyChainGraph } from "./supplyChainGraph.mjs";
import { transitionAssuranceStageState } from "./assuranceState.mjs";

export const RED_TEAM_SCHEMA_REVISION = 6;
export const RED_TEAM_ASSIGNMENT_ISSUER_ID = "zerotrust-sourcecheck-wrapper";
export const RED_TEAM_REVIEW_MODE = "independent-evasive-threat-red-team";
export const RED_TEAM_HANDOFF_KIND = "initial-discovery-handoff";
export const RED_TEAM_PLAN_KIND = "evasive-red-team-plan";
export const RED_TEAM_ASSIGNMENT_KIND = "evasive-red-team-assignment";
export const RED_TEAM_REVIEW_RECORD_KIND = "evasive-red-team-review-record";
export const RED_TEAM_EVALUATION_KIND = "evasive-red-team-evaluation";
export const RED_TEAM_CANARY_MARKER = "zt-red-team-canary-normalized-view";
export const RED_TEAM_OUTPUT_CONTRACT_MARKER =
    "zt-red-team-output-contract-json-only";

export const RED_TEAM_CATEGORY_IDS = Object.freeze([
    "split-cross-file-chains",
    "dormant-env-time-platform-gates",
    "generated-decoded-code",
    "dependency-staging-substitution",
    "source-release-divergence",
    "binary-archive-concealment",
    "benign-decoy-alternate-path",
    "prompt-reviewer-manipulation",
    "dynamic-external-payload-loading",
]);

export const RED_TEAM_MANDATORY_CATEGORY_IDS = RED_TEAM_CATEGORY_IDS;

export const RED_TEAM_REVIEW_DECISIONS = Object.freeze([
    "candidate-submitted",
    "no-candidate",
    "incomplete",
]);

export const RED_TEAM_PROCEDURAL_LIMIT_CODES = Object.freeze([
    "same-reviewer-no-alternative",
    "same-model-distinct-reviewer",
    "model-independence-unverifiable",
]);

export const RED_TEAM_BENIGN_HYPOTHESIS_CODES = Object.freeze([
    "none-supported",
    "legitimate-build-step",
    "test-fixture",
    "documentation-example",
    "platform-compatibility",
    "generated-vendor-output",
    "release-packaging-difference",
    "dependency-manager-normalization",
    "alternate-benign-path",
    "unknown",
]);

export const RED_TEAM_LIMITS = Object.freeze({
    categories: RED_TEAM_CATEGORY_IDS.length,
    objectsPerCategory: 8_192,
    artifactsPerCategory: 8_192,
    factsPerCategory: 20_000,
    evidencePerCategory: 30_000,
    graphNodesPerCategory: 50_000,
    graphEdgesPerCategory: 100_000,
    candidatesPerReview: 256,
    candidateIdentities: 512,
    blockerDetails: 256,
});

const CATEGORY_DEFINITIONS = Object.freeze([
    Object.freeze({
        id: "split-cross-file-chains",
        roleId: "red-team-cross-file-chain",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION,
            EVASION_CLASSES.CROSS_LANGUAGE_AND_BUILD_GRAPH_INDIRECTION,
        ]),
        factKinds: Object.freeze([
            "activation",
            "source",
            "transform",
            "sink",
            "command-construction",
            "import",
            "dynamic-import",
        ]),
        artifactKinds: Object.freeze([
            "abstract-syntax",
            "intermediate-representation",
            "build-graph",
            "dependency-graph",
        ]),
        falsificationChecks: Object.freeze([
            "join-entry-source-transform-sink-across-object-boundaries",
            "challenge-single-file-no-finding-conclusions",
            "inspect-shared-symbol-config-dispatch-and-alias-edges",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-split-cross-file-chain-supported",
            "no-hidden-cross-object-edge-supported",
            "no-decoy-file-chain-redirection-supported",
        ]),
    }),
    Object.freeze({
        id: "dormant-env-time-platform-gates",
        roleId: "red-team-dormant-gates",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.ENVIRONMENT_TIME_AND_STATE_GATED_ACTIVATION,
        ]),
        factKinds: Object.freeze([
            "environment-gate",
            "platform-gate",
            "time-gate",
            "activation",
        ]),
        artifactKinds: Object.freeze([
            "abstract-syntax",
            "intermediate-representation",
        ]),
        falsificationChecks: Object.freeze([
            "challenge-dormant-environment-gates",
            "challenge-time-state-and-platform-gates",
            "trace-gated-branches-to-effects",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-dormant-environment-gate-supported",
            "no-time-or-state-trigger-supported",
            "no-platform-selective-payload-supported",
        ]),
    }),
    Object.freeze({
        id: "generated-decoded-code",
        roleId: "red-team-generated-decoded-code",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.OBFUSCATION_GENERATION_AND_SELF_MODIFICATION,
            EVASION_CLASSES.ENCODING_AND_PARSER_DIFFERENTIALS,
        ]),
        factKinds: Object.freeze([
            "generated-code-hook",
            "dynamic-evaluation",
            "transform",
            "command-construction",
        ]),
        artifactKinds: Object.freeze([
            "decoded-text",
            "decoded-binary",
            "deobfuscated-view",
            "generated-source",
            "payload-index",
            "archive-manifest",
        ]),
        falsificationChecks: Object.freeze([
            "challenge-generated-code-provenance",
            "trace-decode-transform-to-execution",
            "inspect-parser-differentials-and-late-materialization",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-generated-payload-supported",
            "no-decode-then-execute-chain-supported",
            "no-parser-differential-payload-supported",
        ]),
    }),
    Object.freeze({
        id: "dependency-staging-substitution",
        roleId: "red-team-dependency-substitution",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION,
            EVASION_CLASSES.CROSS_LANGUAGE_AND_BUILD_GRAPH_INDIRECTION,
        ]),
        factKinds: Object.freeze([
            "import",
            "dynamic-import",
            "activation",
            "generated-code-hook",
            "command-construction",
        ]),
        artifactKinds: Object.freeze([
            "dependency-graph",
            "build-graph",
            "archive-manifest",
            "binary-metadata",
        ]),
        falsificationChecks: Object.freeze([
            "challenge-locked-package-to-fetched-artifact-binding",
            "inspect-staged-local-git-alias-and-registry-substitution",
            "trace-dependency-hooks-to-execution",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-dependency-substitution-supported",
            "no-staged-package-payload-supported",
            "no-package-hook-execution-chain-supported",
        ]),
    }),
    Object.freeze({
        id: "source-release-divergence",
        roleId: "red-team-source-release-divergence",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.RELEASE_SOURCE_AND_ARTIFACT_DIVERGENCE,
        ]),
        factKinds: Object.freeze([
            "activation",
            "generated-code-hook",
            "command-construction",
        ]),
        artifactKinds: Object.freeze([
            "release-comparison",
            "build-graph",
            "binary-metadata",
            "archive-manifest",
        ]),
        falsificationChecks: Object.freeze([
            "challenge-source-to-release-identity-binding",
            "inspect-release-only-and-source-only-capabilities",
            "trace-packaging-transforms-to-shipped-artifacts",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-source-release-divergence-supported",
            "no-release-only-payload-supported",
            "no-packaging-substitution-supported",
        ]),
    }),
    Object.freeze({
        id: "binary-archive-concealment",
        roleId: "red-team-binary-archive-concealment",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.BINARY_AND_EMBEDDED_PAYLOADS,
            EVASION_CLASSES.UNSUPPORTED_OR_OPAQUE_ARTIFACTS,
            EVASION_CLASSES.ENCODING_AND_PARSER_DIFFERENTIALS,
        ]),
        factKinds: Object.freeze([
            "source",
            "transform",
            "sink",
            "dynamic-evaluation",
        ]),
        artifactKinds: Object.freeze([
            "decoded-binary",
            "archive-manifest",
            "binary-metadata",
            "payload-index",
        ]),
        falsificationChecks: Object.freeze([
            "challenge-binary-and-archive-container-boundaries",
            "inspect-nested-embedded-and-high-entropy-payloads",
            "trace-loader-paths-to-concealed-artifacts",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-binary-concealment-supported",
            "no-archive-nesting-evasion-supported",
            "no-concealed-loader-path-supported",
        ]),
    }),
    Object.freeze({
        id: "benign-decoy-alternate-path",
        roleId: "red-team-benign-decoy-alternate-path",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION,
            EVASION_CLASSES.CROSS_LANGUAGE_AND_BUILD_GRAPH_INDIRECTION,
        ]),
        factKinds: Object.freeze([
            "activation",
            "import",
            "dynamic-import",
            "reflection",
            "source",
            "sink",
            "command-construction",
        ]),
        artifactKinds: Object.freeze([
            "abstract-syntax",
            "intermediate-representation",
            "build-graph",
        ]),
        falsificationChecks: Object.freeze([
            "challenge-benign-decoy-as-reviewed-path",
            "inspect-shadow-alternate-and-platform-specific-paths",
            "trace-dispatch-selection-to-non-decoy-effects",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-benign-decoy-evasion-supported",
            "no-alternate-execution-path-supported",
            "no-shadow-path-substitution-supported",
        ]),
    }),
    Object.freeze({
        id: "prompt-reviewer-manipulation",
        roleId: "red-team-prompt-reviewer-manipulation",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.REVIEWER_MANIPULATION_AND_PROMPT_INJECTION,
        ]),
        factKinds: Object.freeze([]),
        artifactKinds: Object.freeze([]),
        falsificationChecks: Object.freeze([
            "challenge-review-suppression-and-role-reassignment-signals",
            "verify-normalized-view-canary-and-output-contract",
            "inspect-benign-looking-text-surfaces-for-reviewer-control",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-review-suppression-supported",
            "no-reviewer-role-manipulation-supported",
            "no-output-contract-manipulation-supported",
        ]),
    }),
    Object.freeze({
        id: "dynamic-external-payload-loading",
        roleId: "red-team-dynamic-external-payload",
        mandatory: true,
        highRisk: true,
        evasionClasses: Object.freeze([
            EVASION_CLASSES.DYNAMIC_CODE_AND_EXTERNAL_PAYLOAD_LOADING,
            EVASION_CLASSES.INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION,
        ]),
        factKinds: Object.freeze([
            "dynamic-import",
            "dynamic-evaluation",
            "unresolved-dynamic-target",
            "source",
            "transform",
            "sink",
            "command-construction",
        ]),
        artifactKinds: Object.freeze([
            "decoded-binary",
            "payload-index",
            "binary-metadata",
            "dependency-graph",
        ]),
        falsificationChecks: Object.freeze([
            "challenge-runtime-external-payload-resolution",
            "trace-network-file-and-dependency-sources-to-loaders",
            "inspect-unresolved-dynamic-targets-and-late-binding",
        ]),
        negativeEvidenceCodes: Object.freeze([
            "no-dynamic-external-payload-supported",
            "no-late-bound-loader-target-supported",
            "no-external-source-to-execution-chain-supported",
        ]),
    }),
]);

export const RED_TEAM_CATEGORIES = CATEGORY_DEFINITIONS;

const SHA256_RE = /^[a-f0-9]{64}$/u;
const OBJECT_ID_RE = /^zto-[a-f0-9]{64}$/u;
const ARTIFACT_ID_RE = /^zta-[a-f0-9]{64}$/u;
const FACT_ID_RE = /^[a-f0-9]{64}$/u;
const EVIDENCE_ID_RE = /^ztre-[a-f0-9]{64}$/u;
const GRAPH_NODE_ID_RE = /^ztrn-[a-f0-9]{64}$/u;
const GRAPH_EDGE_ID_RE = /^ztrg-[a-f0-9]{64}$/u;
const HANDOFF_ID_RE = /^ztrh-[a-f0-9]{64}$/u;
const PLAN_ID_RE = /^ztrp-[a-f0-9]{64}$/u;
const ASSIGNMENT_ID_RE = /^ztra-[a-f0-9]{64}$/u;
const ASSIGNMENT_TOKEN_RE = /^ztrt-[a-f0-9]{64}$/u;
const REVIEW_ID_RE = /^ztrr-[a-f0-9]{64}$/u;
const CANDIDATE_ID_RE = /^ztrf-[a-f0-9]{64}$/u;
const EVALUATION_ID_RE = /^ztreval-[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u;
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/u;

const RED_TEAM_STAGE_BLOCKERS = new Set([
    EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE,
    EVASIVE_BLOCKERS.RED_TEAM_REVIEWER_MANIPULATION,
    EVASIVE_BLOCKERS.RED_TEAM_MISSING_CATEGORY,
    EVASIVE_BLOCKERS.RED_TEAM_ASSIGNMENT_INCOMPLETE,
    EVASIVE_BLOCKERS.RED_TEAM_TRUNCATED,
]);

export class RedTeamContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "RedTeamContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new RedTeamContractError(path, message);
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function objectShape(value, path, required, optional = []) {
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) fail(`${path}.${key}`, "unknown field");
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
}

function cloneFrozen(value) {
    if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
    if (isPlainObject(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) result[key] = cloneFrozen(entry);
        return Object.freeze(result);
    }
    return value;
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function hashDomain(domain, value) {
    return createHash("sha256")
        .update(domain, "utf8")
        .update("\0", "utf8")
        .update(canonicalJson(value), "utf8")
        .digest("hex");
}

function compareStrings(left, right) {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
}

function boundedString(value, path, { max, pattern } = {}) {
    if (typeof value !== "string" || value.length < 1 || value.length > max
        || value.includes("\0") || (pattern && !pattern.test(value))) {
        fail(path, "is invalid");
    }
    return value;
}

function enumValue(value, path, allowed) {
    if (!allowed.includes(value)) fail(path, `must be one of: ${allowed.join(", ")}`);
    return value;
}

function boundedArray(value, path, max) {
    if (!Array.isArray(value) || value.length > max) {
        fail(path, `must be an array with at most ${max} entries`);
    }
    return value;
}

function sortedUnique(value, path, {
    max,
    pattern = null,
    allowed = null,
} = {}) {
    const result = boundedArray(value, path, max).map((entry, index) => {
        if (typeof entry !== "string" || entry.length === 0
            || (pattern && !pattern.test(entry))
            || (allowed && !allowed.includes(entry))) {
            fail(`${path}[${index}]`, "is invalid");
        }
        return entry;
    }).sort(compareStrings);
    if (new Set(result).size !== result.length) fail(path, "must not contain duplicates");
    return result;
}

function exactArray(actual, expected, path) {
    if (canonicalJson(actual) !== canonicalJson(expected)) {
        fail(path, "must exactly cover the wrapper-assigned identities");
    }
}

function categoryDefinition(categoryId, path = "categoryId") {
    const id = enumValue(categoryId, path, RED_TEAM_CATEGORY_IDS);
    return CATEGORY_DEFINITIONS.find((category) => category.id === id);
}

function validateSemanticInputs({
    semanticBaseSnapshot,
    semanticPlan,
    semanticEvaluation,
    semanticScannerRecords,
    semanticReviewAssignments,
    semanticReviewRecords,
}, path) {
    const base = validateAssuranceAnalysisSnapshot(
        semanticBaseSnapshot,
        `${path}.semanticBaseSnapshot`,
    );
    if (base.stageState.current !== "decoded") {
        fail(`${path}.semanticBaseSnapshot.stageState.current`, "must be decoded");
    }
    const plan = validateSemanticCoveragePlan(
        semanticPlan,
        base,
        `${path}.semanticPlan`,
    );
    const evaluation = evaluateSemanticCoverage({
        snapshot: base,
        plan,
        scannerRecords: semanticScannerRecords,
        reviewAssignments: semanticReviewAssignments,
        reviewRecords: semanticReviewRecords,
    }, `${path}.semanticEvaluation`);
    if (canonicalJson(semanticEvaluation) !== canonicalJson(evaluation)) {
        fail(`${path}.semanticEvaluation`, "is not the canonical semantic evaluation");
    }
    if (!evaluation.complete || evaluation.truncated
        || evaluation.blockerCodes.length > 0
        || evaluation.blockerDetailsTruncated) {
        fail(`${path}.semanticEvaluation`, "must be complete before red-team discovery");
    }
    return {
        base,
        plan,
        evaluation,
        scannerRecords: semanticScannerRecords,
        reviewAssignments: semanticReviewAssignments,
        reviewRecords: semanticReviewRecords,
    };
}

function semanticViewSet(reviewAssignments) {
    const byId = new Map();
    for (const assignment of reviewAssignments) {
        const view = assignment.semanticView;
        const existing = byId.get(view.semanticViewId);
        if (existing && canonicalJson(existing) !== canonicalJson(view)) {
            fail("semanticReviewAssignments", "contain conflicting semantic views");
        }
        byId.set(view.semanticViewId, view);
    }
    return [...byId.values()].sort((left, right) =>
        compareStrings(left.semanticViewId, right.semanticViewId));
}

function factCorpus(semanticViews) {
    const facts = new Map();
    for (const view of semanticViews) {
        for (const fact of view.facts) {
            const normalized = cloneFrozen({
                ...fact,
                objectId: view.objectId,
                semanticViewId: view.semanticViewId,
            });
            const existing = facts.get(fact.id);
            if (existing && canonicalJson(existing) !== canonicalJson(normalized)) {
                fail("semanticViews", `contain conflicting fact ${fact.id}`);
            }
            facts.set(fact.id, normalized);
        }
    }
    return [...facts.values()].sort((left, right) => compareStrings(left.id, right.id));
}

function evidenceRecord({
    evidenceKind,
    object,
    artifact = null,
    fact = null,
}) {
    const descriptor = {
        evidenceKind,
        objectId: object.objectId,
        objectIdentitySha256: object.hashes.identitySha256,
        artifactId: artifact?.artifactId || null,
        factId: fact?.id || null,
        path: artifact?.path || fact?.path || object.path,
        startLine: fact?.line || 0,
        endLine: fact?.endLine || 0,
        excerptHash: fact?.excerptHash || null,
        contentSha256: artifact?.hashes.contentSha256
            || object.hashes.contentSha256
            || object.hashes.identitySha256,
    };
    const evidenceSha256 = hashDomain("zerotrust-red-team-evidence", descriptor);
    return cloneFrozen({
        evidenceId: `ztre-${evidenceSha256}`,
        ...descriptor,
        hashes: {
            evidenceSha256,
        },
    });
}

function evidenceCorpus(snapshot, facts) {
    const objectById = new Map(
        snapshot.objectInventory.map((object) => [object.objectId, object]),
    );
    const evidence = [];
    for (const object of snapshot.objectInventory) {
        evidence.push(evidenceRecord({ evidenceKind: "object", object }));
    }
    for (const artifact of snapshot.derivedArtifacts) {
        const object = objectById.get(artifact.sourceObjectId);
        evidence.push(evidenceRecord({
            evidenceKind: "artifact",
            object,
            artifact,
        }));
    }
    for (const fact of facts) {
        const object = objectById.get(fact.objectId);
        evidence.push(evidenceRecord({
            evidenceKind: "fact",
            object,
            fact,
        }));
    }
    return evidence.sort((left, right) =>
        compareStrings(left.evidenceId, right.evidenceId));
}

function graphNode(kind, identity, metadata) {
    const descriptor = { kind, identity, metadata };
    const nodeSha256 = hashDomain("zerotrust-red-team-graph-node", descriptor);
    return cloneFrozen({
        nodeId: `ztrn-${nodeSha256}`,
        kind,
        identity,
        metadata,
        hashes: { nodeSha256 },
    });
}

function graphEdge(kind, fromNodeId, toNodeId, metadata = {}) {
    const descriptor = { kind, fromNodeId, toNodeId, metadata };
    const edgeSha256 = hashDomain("zerotrust-red-team-graph-edge", descriptor);
    return cloneFrozen({
        edgeId: `ztrg-${edgeSha256}`,
        kind,
        fromNodeId,
        toNodeId,
        metadata,
        hashes: { edgeSha256 },
    });
}

function normalizedLinkTokens(fact) {
    return [...new Set([
        fact.name,
        fact.value,
        fact.target,
    ].filter((entry) => typeof entry === "string" && entry.length > 0))]
        .sort(compareStrings);
}

function discoveryGraph(snapshot, facts, semanticReviewRecords) {
    const nodes = [];
    const edges = [];
    const objectNodeById = new Map();
    const artifactNodeById = new Map();
    const factNodeById = new Map();
    for (const object of snapshot.objectInventory) {
        const node = graphNode("object", object.objectId, {
            path: object.path,
            objectKind: object.objectKind,
            executable: object.executable,
            status: object.status,
            blockerCodes: object.blockerCodes,
            identitySha256: object.hashes.identitySha256,
        });
        nodes.push(node);
        objectNodeById.set(object.objectId, node.nodeId);
    }
    for (const artifact of snapshot.derivedArtifacts) {
        const node = graphNode("artifact", artifact.artifactId, {
            objectId: artifact.sourceObjectId,
            path: artifact.path,
            artifactKind: artifact.artifactKind,
            status: artifact.status,
            blockerCodes: artifact.blockerCodes,
            contentSha256: artifact.hashes.contentSha256,
        });
        nodes.push(node);
        artifactNodeById.set(artifact.artifactId, node.nodeId);
        edges.push(graphEdge(
            "derived-from",
            node.nodeId,
            objectNodeById.get(artifact.sourceObjectId),
        ));
    }
    for (const fact of facts) {
        const node = graphNode("semantic-fact", fact.id, {
            objectId: fact.objectId,
            path: fact.path,
            kind: fact.kind,
            line: fact.line,
            endLine: fact.endLine,
            excerptHash: fact.excerptHash,
            resolution: fact.resolution || null,
            linkTokens: normalizedLinkTokens(fact),
        });
        nodes.push(node);
        factNodeById.set(fact.id, node.nodeId);
        edges.push(graphEdge(
            "observed-on",
            node.nodeId,
            objectNodeById.get(fact.objectId),
        ));
    }
    const factsByObject = new Map();
    for (const fact of facts) {
        if (!factsByObject.has(fact.objectId)) factsByObject.set(fact.objectId, []);
        factsByObject.get(fact.objectId).push(fact);
    }
    for (const objectFacts of factsByObject.values()) {
        objectFacts.sort((left, right) =>
            left.line - right.line || left.endLine - right.endLine
            || compareStrings(left.id, right.id));
        for (let index = 1; index < objectFacts.length; index += 1) {
            edges.push(graphEdge(
                "precedes",
                factNodeById.get(objectFacts[index - 1].id),
                factNodeById.get(objectFacts[index].id),
            ));
        }
    }
    const factTokenIndex = new Map();
    for (const fact of facts) {
        for (const token of normalizedLinkTokens(fact)) {
            if (!factTokenIndex.has(token)) factTokenIndex.set(token, []);
            factTokenIndex.get(token).push(fact);
        }
    }
    for (const [token, linkedFacts] of factTokenIndex.entries()) {
        const byObject = new Map();
        for (const fact of linkedFacts) {
            if (!byObject.has(fact.objectId)) byObject.set(fact.objectId, fact);
        }
        const representatives = [...byObject.values()].sort((left, right) =>
            compareStrings(left.objectId, right.objectId));
        for (let index = 1; index < representatives.length; index += 1) {
            edges.push(graphEdge(
                "cross-object-reference",
                factNodeById.get(representatives[index - 1].id),
                factNodeById.get(representatives[index].id),
                { tokenHash: hashDomain("zerotrust-red-team-link-token", token) },
            ));
        }
    }
    for (const review of semanticReviewRecords) {
        const node = graphNode("semantic-review", review.reviewId, {
            objectId: review.objectId,
            semanticViewId: review.semanticViewId,
            decision: review.decision,
            negativeEvidenceCodes: review.negativeEvidenceCodes,
            candidateIds: review.candidates.map((candidate) =>
                candidate.candidateId),
        });
        nodes.push(node);
        edges.push(graphEdge(
            "reviewed",
            node.nodeId,
            objectNodeById.get(review.objectId),
        ));
    }
    const uniqueNodes = new Map(nodes.map((node) => [node.nodeId, node]));
    const uniqueEdges = new Map(edges.map((edge) => [edge.edgeId, edge]));
    return cloneFrozen({
        nodes: [...uniqueNodes.values()].sort((left, right) =>
            compareStrings(left.nodeId, right.nodeId)),
        edges: [...uniqueEdges.values()].sort((left, right) =>
            compareStrings(left.edgeId, right.edgeId)),
    });
}

function alternatePathGroups(snapshot) {
    const groups = new Map();
    for (const object of snapshot.objectInventory) {
        const basename = nodePath.posix.basename(object.path.toLowerCase());
        if (!groups.has(basename)) groups.set(basename, []);
        groups.get(basename).push(object);
    }
    return [...groups.entries()]
        .filter(([, objects]) => objects.length > 1)
        .map(([basename, objects]) => cloneFrozen({
            basename,
            objectIds: objects.map((object) => object.objectId).sort(compareStrings),
            paths: objects.map((object) => object.path).sort(compareStrings),
        }))
        .sort((left, right) => compareStrings(left.basename, right.basename));
}

function supplyChainBinding(snapshot, supplyChainGraph = null) {
    const graph = supplyChainGraph === null || supplyChainGraph === undefined
        ? null: validateSupplyChainGraph(supplyChainGraph);
    if (graph
        && (graph.auditId !== snapshot.auditId
            || graph.sourceNamespace !== snapshot.sourceNamespace)) {
        fail("supplyChainGraph", "does not match the scanned snapshot identity");
    }
    const dependencyArtifacts = snapshot.derivedArtifacts
        .filter((artifact) => artifact.artifactKind === "dependency-graph")
        .map((artifact) => cloneFrozen({
            artifactId: artifact.artifactId,
            objectId: artifact.sourceObjectId,
            path: artifact.path,
            status: artifact.status,
            blockerCodes: artifact.blockerCodes,
            contentSha256: artifact.hashes.contentSha256,
            derivationSha256: artifact.hashes.derivationSha256,
        }))
        .sort((left, right) => compareStrings(left.artifactId, right.artifactId));
    const releaseArtifacts = snapshot.derivedArtifacts
        .filter((artifact) => artifact.artifactKind === "release-comparison")
        .map((artifact) => cloneFrozen({
            artifactId: artifact.artifactId,
            objectId: artifact.sourceObjectId,
            path: artifact.path,
            status: artifact.status,
            blockerCodes: artifact.blockerCodes,
            contentSha256: artifact.hashes.contentSha256,
            derivationSha256: artifact.hashes.derivationSha256,
        }))
        .sort((left, right) => compareStrings(left.artifactId, right.artifactId));
    const bindingSha256 = hashDomain("zerotrust-red-team-supply-chain-binding", {
        sourceNamespace: snapshot.sourceNamespace,
        sourceIdentitySha256: snapshot.hashes.sourceIdentitySha256,
        graphId: graph?.graphId || null,
        graphSha256: graph?.hashes.graphSha256 || null,
        dependencyArtifacts,
        releaseArtifacts,
    });
    return cloneFrozen({
        graph,
        dependencyArtifacts,
        releaseArtifacts,
        hashes: { bindingSha256 },
    });
}

function createInitialDiscoveryHandoff({
    snapshot,
    semanticPlan,
    semanticEvaluation,
    semanticViews,
    semanticReviewRecords,
    facts,
    evidence,
    graph,
    supplyChain,
    promptViews,
}) {
    const reviewByAssignmentId = new Map(
        semanticReviewRecords.map((review) => [review.assignmentId, review]),
    );
    const initialFindings = semanticEvaluation.candidateLedger
        .map((candidate) => {
            const review = reviewByAssignmentId.get(candidate.producerAssignmentId);
            return cloneFrozen({
                candidateId: candidate.candidateId,
                reviewId: review?.reviewId || null,
                reviewerId: review?.reviewerId || null,
                producerAssignmentId: candidate.producerAssignmentId,
                objectIds: candidate.objectIds,
                artifactIds: candidate.artifactIds,
                factIds: candidate.factIds,
                evidenceIds: candidate.evidenceIds,
                severity: candidate.severity,
                confidence: candidate.confidence,
                maliciousProjectFit: candidate.maliciousProjectFit,
                benignHypothesisCode: candidate.benignHypothesisCode,
                behavior: candidate.behavior,
            });
        })
        .sort((left, right) => compareStrings(left.candidateId, right.candidateId));
    const initialNoFindings = semanticReviewRecords
        .filter((review) => review.decision === "no-findings")
        .map((review) => cloneFrozen({
            reviewId: review.reviewId,
            reviewerId: review.reviewerId,
            objectId: review.objectId,
            semanticViewId: review.semanticViewId,
            checks: review.checks,
            negativeEvidenceCodes: review.negativeEvidenceCodes,
            promptReviewDecision: review.promptReviewRecord?.decision || null,
        }))
        .sort((left, right) => compareStrings(left.reviewId, right.reviewId));
    const promptManipulationReviewIds = semanticReviewRecords
        .filter((review) =>
            review.promptReviewRecord?.decision === "manipulation-candidate")
        .map((review) => review.reviewId)
        .sort(compareStrings);
    const base = {
        schemaVersion: RED_TEAM_SCHEMA_REVISION,
        contractKind: RED_TEAM_HANDOFF_KIND,
        auditId: snapshot.auditId,
        sourceNamespace: snapshot.sourceNamespace,
        snapshotId: snapshot.snapshotId,
        semanticPlanId: semanticPlan.planId,
        semanticEvaluationId: semanticEvaluation.evaluationId,
        semanticViewIds: semanticViews
            .map((view) => view.semanticViewId).sort(compareStrings),
        semanticCoverageIds: semanticEvaluation.coverageRecords
            .map((record) => record.semanticCoverageId).sort(compareStrings),
        factIds: facts.map((fact) => fact.id).sort(compareStrings),
        evidenceIds: evidence.map((entry) => entry.evidenceId).sort(compareStrings),
        graphNodeIds: graph.nodes.map((node) => node.nodeId).sort(compareStrings),
        graphEdgeIds: graph.edges.map((edge) => edge.edgeId).sort(compareStrings),
        initialFindings,
        initialNoFindings,
        promptManipulationReviewIds,
        promptViewIds: promptViews
            .map((view) => view.normalizedViewId).sort(compareStrings),
        supplyChainBindingSha256: supplyChain.hashes.bindingSha256,
    };
    const handoffSha256 = hashDomain("zerotrust-initial-discovery-handoff", base);
    return cloneFrozen({
        ...base,
        handoffId: `ztrh-${handoffSha256}`,
        hashes: { handoffSha256 },
    });
}

function validateInitialDiscoveryHandoff(value, expected, path) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "auditId",
        "sourceNamespace",
        "snapshotId",
        "semanticPlanId",
        "semanticEvaluationId",
        "semanticViewIds",
        "semanticCoverageIds",
        "factIds",
        "evidenceIds",
        "graphNodeIds",
        "graphEdgeIds",
        "initialFindings",
        "initialNoFindings",
        "promptManipulationReviewIds",
        "promptViewIds",
        "supplyChainBindingSha256",
        "handoffId",
        "hashes",
    ]);
    boundedString(value.handoffId, `${path}.handoffId`, {
        max: 72,
        pattern: HANDOFF_ID_RE,
    });
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match the deterministic initial discovery handoff");
    }
    return expected;
}

function objectIsExecutableOrConfig(object, semanticPlan) {
    const classification = semanticPlan.classifications.find((entry) =>
        entry.objectId === object.objectId);
    return classification?.required === true
        || ["executable-source", "build-config", "workflow", "generated-input"]
            .includes(classification?.semanticClass);
}

function categorySubjectSet({
    category,
    snapshot,
    semanticPlan,
    facts,
    evidence,
    graph,
    promptViews,
    alternateGroups,
}) {
    const factKindSet = new Set(category.factKinds);
    const artifactKindSet = new Set(category.artifactKinds);
    let selectedFacts = category.id === "prompt-reviewer-manipulation"
        ? []: facts.filter((fact) => factKindSet.has(fact.kind));
    let selectedArtifacts = snapshot.derivedArtifacts.filter((artifact) =>
        artifactKindSet.has(artifact.artifactKind));
    let selectedObjects;
    if (category.id === "split-cross-file-chains"
        || category.id === "benign-decoy-alternate-path") {
        selectedFacts = facts;
        selectedObjects = snapshot.objectInventory;
    } else if (category.id === "prompt-reviewer-manipulation") {
        const promptObjectIds = new Set(promptViews.map((view) => view.objectId));
        selectedObjects = snapshot.objectInventory.filter((object) =>
            promptObjectIds.has(object.objectId));
    } else if (category.id === "binary-archive-concealment") {
        selectedObjects = snapshot.objectInventory.filter((object) =>
            ["binary", "archive", "archive-entry", "embedded-payload",
                "release-asset", "opaque"].includes(object.objectKind));
    } else if (category.id === "dependency-staging-substitution") {
        selectedObjects = snapshot.objectInventory.filter((object) =>
            ["manifest", "dependency-metadata"].includes(object.objectKind)
            || /(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|cargo\.lock|requirements[^/]*\.txt)$/iu
                .test(object.path));
    } else if (category.id === "source-release-divergence") {
        selectedObjects = snapshot.objectInventory.filter((object) =>
            object.objectKind === "release-asset");
    } else {
        const selectedObjectIds = new Set([
            ...selectedFacts.map((fact) => fact.objectId),
            ...selectedArtifacts.map((artifact) => artifact.sourceObjectId),
        ]);
        selectedObjects = snapshot.objectInventory.filter((object) =>
            selectedObjectIds.has(object.objectId));
    }
    if (selectedObjects.length === 0) {
        selectedObjects = snapshot.objectInventory.filter((object) =>
            objectIsExecutableOrConfig(object, semanticPlan));
    }
    if (selectedObjects.length === 0) selectedObjects = snapshot.objectInventory;
    const objectIdSet = new Set(selectedObjects.map((object) => object.objectId));
    for (const fact of selectedFacts) objectIdSet.add(fact.objectId);
    for (const artifact of selectedArtifacts) objectIdSet.add(artifact.sourceObjectId);
    selectedObjects = snapshot.objectInventory.filter((object) =>
        objectIdSet.has(object.objectId));
    const objectIds = selectedObjects
        .map((object) => object.objectId).sort(compareStrings);
    const artifactIds = selectedArtifacts
        .filter((artifact) => objectIdSet.has(artifact.sourceObjectId))
        .map((artifact) => artifact.artifactId).sort(compareStrings);
    const factIds = selectedFacts
        .filter((fact) => objectIdSet.has(fact.objectId))
        .map((fact) => fact.id).sort(compareStrings);
    const selectedEvidence = evidence.filter((entry) =>
        objectIdSet.has(entry.objectId)
        && (entry.artifactId === null || artifactIds.includes(entry.artifactId))
        && (entry.factId === null || factIds.includes(entry.factId)));
    const evidenceIds = selectedEvidence
        .map((entry) => entry.evidenceId).sort(compareStrings);
    const selectedNodeIds = new Set();
    for (const node of graph.nodes) {
        const metadataObjectId = node.metadata?.objectId;
        if (objectIds.includes(node.identity)
            || artifactIds.includes(node.identity)
            || factIds.includes(node.identity)
            || (metadataObjectId && objectIds.includes(metadataObjectId))) {
            selectedNodeIds.add(node.nodeId);
        }
    }
    const selectedEdges = graph.edges.filter((edge) =>
        selectedNodeIds.has(edge.fromNodeId) && selectedNodeIds.has(edge.toNodeId));
    const graphNodeIds = [...selectedNodeIds].sort(compareStrings);
    const graphEdgeIds = selectedEdges
        .map((edge) => edge.edgeId).sort(compareStrings);
    const categoryPromptViews = category.id === "prompt-reviewer-manipulation"
        ? promptViews: promptViews.filter((view) => objectIdSet.has(view.objectId));
    const categoryAlternateGroups = category.id === "benign-decoy-alternate-path"
        ? alternateGroups: [];
    const truncated = objectIds.length > RED_TEAM_LIMITS.objectsPerCategory
        || artifactIds.length > RED_TEAM_LIMITS.artifactsPerCategory
        || factIds.length > RED_TEAM_LIMITS.factsPerCategory
        || evidenceIds.length > RED_TEAM_LIMITS.evidencePerCategory
        || graphNodeIds.length > RED_TEAM_LIMITS.graphNodesPerCategory
        || graphEdgeIds.length > RED_TEAM_LIMITS.graphEdgesPerCategory
        || selectedObjects.some((object) =>
            selectedArtifacts.filter((artifact) =>
                artifact.sourceObjectId === object.objectId).length
                > EVASIVE_LIMITS.artifactReferencesPerCoverage);
    return cloneFrozen({
        objectIds: objectIds.slice(0, RED_TEAM_LIMITS.objectsPerCategory),
        artifactIds: artifactIds.slice(0, RED_TEAM_LIMITS.artifactsPerCategory),
        factIds: factIds.slice(0, RED_TEAM_LIMITS.factsPerCategory),
        evidenceIds: evidenceIds.slice(0, RED_TEAM_LIMITS.evidencePerCategory),
        graphNodeIds: graphNodeIds.slice(0, RED_TEAM_LIMITS.graphNodesPerCategory),
        graphEdgeIds: graphEdgeIds.slice(0, RED_TEAM_LIMITS.graphEdgesPerCategory),
        promptViewIds: categoryPromptViews
            .map((view) => view.normalizedViewId).sort(compareStrings),
        alternatePathGroupNames: categoryAlternateGroups
            .map((group) => group.basename).sort(compareStrings),
        truncated,
    });
}

function buildCategoryView({
    category,
    subjects,
    semanticViews,
    facts,
    evidence,
    graph,
    artifacts,
    promptViews,
    alternateGroups,
    supplyChain,
    handoff,
}) {
    const objectIdSet = new Set(subjects.objectIds);
    const semanticViewPayloads = semanticViews
        .filter((view) => objectIdSet.has(view.objectId))
        .map((view) => cloneFrozen({
            semanticViewId: view.semanticViewId,
            objectId: view.objectId,
            path: view.path,
            semanticClass: view.semanticClass,
            substantive: view.substantive,
            complete: view.complete,
            scannerSubjects: view.scannerSubjects,
            factIds: view.facts.map((fact) => fact.id).sort(compareStrings),
            artifactIds: view.derivedArtifacts
                .map((artifact) => artifact.artifactId).sort(compareStrings),
            checks: view.checks,
            unresolvedDynamicFactIds: view.unresolvedDynamicFactIds,
            blockerCodes: view.blockerCodes,
            hashes: view.hashes,
        }));
    const factIdSet = new Set(subjects.factIds);
    const artifactIdSet = new Set(subjects.artifactIds);
    const evidenceIdSet = new Set(subjects.evidenceIds);
    const nodeIdSet = new Set(subjects.graphNodeIds);
    const edgeIdSet = new Set(subjects.graphEdgeIds);
    const promptViewIdSet = new Set(subjects.promptViewIds);
    const alternateNameSet = new Set(subjects.alternatePathGroupNames);
    const supplyChainView = [
        "dependency-staging-substitution",
        "source-release-divergence",
        "dynamic-external-payload-loading",
    ].includes(category.id)
        ? supplyChain: cloneFrozen({
            graph: supplyChain.graph
                ? {
                    graphId: supplyChain.graph.graphId,
                    status: supplyChain.graph.status,
                    blockerCodes: supplyChain.graph.blockerCodes,
                    counts: supplyChain.graph.counts,
                    hashes: supplyChain.graph.hashes,
                }: null,
            dependencyArtifacts: supplyChain.dependencyArtifacts,
            releaseArtifacts: supplyChain.releaseArtifacts,
            hashes: supplyChain.hashes,
        });
    const view = {
        categoryId: category.id,
        initialDiscoveryHandoffId: handoff.handoffId,
        semanticViews: semanticViewPayloads,
        facts: facts.filter((fact) => factIdSet.has(fact.id)),
        artifacts: artifacts
            .filter((artifact) => artifactIdSet.has(artifact.artifactId))
            .map((artifact) => cloneFrozen({
                artifactId: artifact.artifactId,
                objectId: artifact.sourceObjectId,
                path: artifact.path,
                artifactKind: artifact.artifactKind,
                producer: artifact.producer,
                producerVersion: artifact.producerVersion,
                byteLength: artifact.byteLength,
                status: artifact.status,
                blockerCodes: artifact.blockerCodes,
                sourceRange: artifact.sourceRange,
                transformKinds: [...new Set(
                    artifact.transformChain.map((step) => step.kind),
                )].sort(compareStrings),
                hashes: {
                    contentSha256: artifact.hashes.contentSha256,
                    derivationSha256: artifact.hashes.derivationSha256,
                },
            })),
        evidence: evidence.filter((entry) => evidenceIdSet.has(entry.evidenceId)),
        graph: {
            nodes: graph.nodes.filter((node) => nodeIdSet.has(node.nodeId)),
            edges: graph.edges.filter((edge) => edgeIdSet.has(edge.edgeId)),
        },
        promptViews: promptViews.filter((entry) =>
            promptViewIdSet.has(entry.normalizedViewId)),
        alternatePathGroups: alternateGroups.filter((group) =>
            alternateNameSet.has(group.basename)),
        supplyChain: supplyChainView,
        initialNoFindings: handoff.initialNoFindings.filter((review) =>
            objectIdSet.has(review.objectId)),
        initialFindings: handoff.initialFindings.filter((review) =>
            objectIdSet.has(review.objectId)),
    };
    const viewSha256 = hashDomain("zerotrust-red-team-category-view", view);
    return cloneFrozen({
        ...view,
        hashes: { viewSha256 },
    });
}

export function createRedTeamScannedSnapshot({
    snapshot,
    stageState = null,
} = {}, path = "redTeamScannedSnapshotInput") {
    const current = validateAssuranceAnalysisSnapshot(snapshot, `${path}.snapshot`);
    if (current.stageState.current !== "semantically-covered") {
        fail(`${path}.snapshot.stageState.current`, "must be semantically-covered");
    }
    if (current.redTeamCoverage.length > 0) {
        fail(`${path}.snapshot.redTeamCoverage`, "must be empty before red-team preparation");
    }
    const scannedStage = stageState || transitionAssuranceStageState(current.stageState, {
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        from: "semantically-covered",
        to: "scanned",
    });
    if (scannedStage.current !== "scanned") {
        fail(`${path}.stageState.current`, "must be scanned");
    }
    const upstreamBlockers = current.blockerCodes.filter((code) =>
        !RED_TEAM_STAGE_BLOCKERS.has(code));
    return createAssuranceAnalysisSnapshot({
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        stageState: scannedStage,
        status: "incomplete",
        objectInventory: current.objectInventory,
        derivedArtifacts: current.derivedArtifacts,
        semanticReviewCoverage: current.semanticReviewCoverage,
        semanticCandidateLedger: current.semanticCandidateLedger,
        redTeamCoverage: [],
        blockerCodes: [...new Set([
            ...upstreamBlockers,
            EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE,
        ])].sort(compareStrings),
        sourceIdentitySha256: current.hashes.sourceIdentitySha256,
    });
}

export function createRedTeamPlan({
    snapshot,
    semanticBaseSnapshot,
    semanticPlan,
    semanticEvaluation,
    semanticScannerRecords = [],
    semanticReviewAssignments = [],
    semanticReviewRecords = [],
    supplyChainGraph = null,
} = {}, path = "redTeamPlanInput") {
    const current = validateAssuranceAnalysisSnapshot(snapshot, `${path}.snapshot`);
    if (current.stageState.current !== "scanned") {
        fail(`${path}.snapshot.stageState.current`, "must be scanned");
    }
    const semantic = validateSemanticInputs({
        semanticBaseSnapshot,
        semanticPlan,
        semanticEvaluation,
        semanticScannerRecords,
        semanticReviewAssignments,
        semanticReviewRecords,
    }, path);
    if (current.auditId !== semantic.base.auditId
        || current.sourceNamespace !== semantic.base.sourceNamespace
        || current.hashes.inventorySha256 !== semantic.base.hashes.inventorySha256
        || current.hashes.derivedArtifactsSha256
            !== semantic.base.hashes.derivedArtifactsSha256
        || current.hashes.semanticCoverageSha256
            !== hashDomain(
                "zerotrust-semantic-coverage-snapshot",
                semantic.evaluation.coverageRecords,
            )
        || canonicalJson(current.semanticCandidateLedger)
           !== canonicalJson(semantic.evaluation.candidateLedger)) {
        fail(`${path}.snapshot`, "does not carry the completed semantic discovery state");
    }
    const upstreamBlockers = current.blockerCodes.filter((code) =>
        !RED_TEAM_STAGE_BLOCKERS.has(code));
    if (upstreamBlockers.length > 0) {
        fail(`${path}.snapshot.blockerCodes`, "contains upstream blockers");
    }
    const semanticViews = semanticViewSet(semantic.reviewAssignments);
    const facts = factCorpus(semanticViews);
    const evidence = evidenceCorpus(current, facts);
    const graph = discoveryGraph(current, facts, semantic.reviewRecords);
    const promptViews = semantic.plan.normalizedViews;
    const alternateGroups = alternatePathGroups(current);
    const supplyChain = supplyChainBinding(current, supplyChainGraph);
    const handoff = createInitialDiscoveryHandoff({
        snapshot: current,
        semanticPlan: semantic.plan,
        semanticEvaluation: semantic.evaluation,
        semanticViews,
        semanticReviewRecords: semantic.reviewRecords,
        facts,
        evidence,
        graph,
        supplyChain,
        promptViews,
    });
    const categoryPlans = CATEGORY_DEFINITIONS.map((category) => {
        const subjects = categorySubjectSet({
            category,
            snapshot: current,
            semanticPlan: semantic.plan,
            facts,
            evidence,
            graph,
            promptViews,
            alternateGroups,
        });
        const view = buildCategoryView({
            category,
            subjects,
            semanticViews,
            facts,
            evidence,
            graph,
            artifacts: current.derivedArtifacts,
            promptViews,
            alternateGroups,
            supplyChain,
            handoff,
        });
        const categoryPlanSha256 = hashDomain("zerotrust-red-team-category-plan", {
            category,
            subjects,
            viewSha256: view.hashes.viewSha256,
        });
        return cloneFrozen({
            categoryId: category.id,
            roleId: category.roleId,
            mandatory: category.mandatory,
            highRisk: category.highRisk,
            evasionClasses: category.evasionClasses,
            falsificationChecks: [...category.falsificationChecks].sort(compareStrings),
            negativeEvidenceCodes: [...category.negativeEvidenceCodes].sort(compareStrings),
            subjects,
            view,
            hashes: { categoryPlanSha256 },
        });
    });
    const truncated = categoryPlans.some((entry) => entry.subjects.truncated);
    const blockerCodes = truncated
        ? [EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE, EVASIVE_BLOCKERS.RED_TEAM_TRUNCATED]: [];
    const planSha256 = hashDomain("zerotrust-red-team-plan", {
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        snapshotId: current.snapshotId,
        snapshotSha256: current.hashes.snapshotSha256,
        semanticPlanId: semantic.plan.planId,
        semanticEvaluationId: semantic.evaluation.evaluationId,
        handoffId: handoff.handoffId,
        supplyChainBindingSha256: supplyChain.hashes.bindingSha256,
        categoryPlans,
        blockerCodes,
        truncated,
    });
    return cloneFrozen({
        schemaVersion: RED_TEAM_SCHEMA_REVISION,
        contractKind: RED_TEAM_PLAN_KIND,
        planId: `ztrp-${planSha256}`,
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        snapshotId: current.snapshotId,
        stage: current.stageState.current,
        semanticPlanId: semantic.plan.planId,
        semanticEvaluationId: semantic.evaluation.evaluationId,
        initialDiscoveryHandoff: handoff,
        supplyChainBinding: supplyChain,
        categoryPlans,
        mandatoryCategoryIds: RED_TEAM_MANDATORY_CATEGORY_IDS,
        coverageThresholdPercent: 90,
        blockerCodes,
        truncated,
        hashes: {
            snapshotSha256: current.hashes.snapshotSha256,
            semanticPlanSha256: semantic.plan.hashes.planSha256,
            semanticEvaluationSha256: semantic.evaluation.hashes.evaluationSha256,
            handoffSha256: handoff.hashes.handoffSha256,
            supplyChainBindingSha256: supplyChain.hashes.bindingSha256,
            planSha256,
        },
    });
}

export function validateRedTeamPlan(
    value,
    inputs,
    path = "redTeamPlan",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "planId",
        "auditId",
        "sourceNamespace",
        "snapshotId",
        "stage",
        "semanticPlanId",
        "semanticEvaluationId",
        "initialDiscoveryHandoff",
        "supplyChainBinding",
        "categoryPlans",
        "mandatoryCategoryIds",
        "coverageThresholdPercent",
        "blockerCodes",
        "truncated",
        "hashes",
    ]);
    if (value.schemaVersion !== RED_TEAM_SCHEMA_REVISION
        || value.contractKind !== RED_TEAM_PLAN_KIND) {
        fail(path, "has an invalid red-team plan contract");
    }
    boundedString(value.planId, `${path}.planId`, { max: 72, pattern: PLAN_ID_RE });
    const expected = createRedTeamPlan(inputs, path);
    validateInitialDiscoveryHandoff(
        value.initialDiscoveryHandoff,
        expected.initialDiscoveryHandoff,
        `${path}.initialDiscoveryHandoff`,
    );
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic red-team plan");
    }
    return expected;
}

function initialReviewerIdsForCategory(categoryPlan) {
    return [...new Set([
        ...categoryPlan.view.initialNoFindings,
        ...categoryPlan.view.initialFindings,
    ].map((review) => review.reviewerId))]
        .sort(compareStrings);
}

function initialModelIdsForCategory(categoryPlan) {
    return [...new Set([
        ...categoryPlan.view.initialNoFindings,
        ...categoryPlan.view.initialFindings,
    ].map((review) => review.modelId).filter(Boolean))]
        .sort(compareStrings);
}

function requiredProceduralLimit(categoryPlan, reviewerId, modelId) {
    const initialReviewerIds = initialReviewerIdsForCategory(categoryPlan);
    if (initialReviewerIds.includes(reviewerId)) {
        return "same-reviewer-no-alternative";
    }
    const initialModelIds = initialModelIdsForCategory(categoryPlan);
    if (initialModelIds.length === 0) {
        return "model-independence-unverifiable";
    }
    if (initialModelIds.includes(modelId)) {
        return "same-model-distinct-reviewer";
    }
    return null;
}

export function createRedTeamAssignment({
    plan,
    planInputs,
    categoryId,
    reviewerId,
    reviewerVersion,
    modelId,
    assignmentNonceSha256,
} = {}, path = "redTeamAssignmentInput") {
    const canonicalPlan = validateRedTeamPlan(plan, planInputs, `${path}.plan`);
    const category = categoryDefinition(categoryId, `${path}.categoryId`);
    const categoryPlan = canonicalPlan.categoryPlans.find((entry) =>
        entry.categoryId === category.id);
    const reviewer = boundedString(reviewerId, `${path}.reviewerId`, {
        max: 128,
        pattern: IDENTIFIER_RE,
    });
    const version = boundedString(reviewerVersion, `${path}.reviewerVersion`, {
        max: 64,
        pattern: VERSION_RE,
    });
    const model = boundedString(modelId, `${path}.modelId`, {
        max: 128,
        pattern: IDENTIFIER_RE,
    });
    const nonceSha256 = boundedString(
        assignmentNonceSha256,
        `${path}.assignmentNonceSha256`,
        { max: 64, pattern: SHA256_RE },
    );
    const requiredLimit = requiredProceduralLimit(
        categoryPlan,
        reviewer,
        model,
    );
    const initialReviewerIds = initialReviewerIdsForCategory(categoryPlan);
    const initialModelIds = initialModelIdsForCategory(categoryPlan);
    const independence = cloneFrozen({
        initialReviewerIds,
        initialModelIds,
        reviewerDistinctFromInitial: !initialReviewerIds.includes(reviewer),
        modelDistinctFromInitial: initialModelIds.length === 0
            ? null: !initialModelIds.includes(model),
        modelIndependenceVerified: initialModelIds.length > 0,
        proceduralLimitCode: requiredLimit,
    });
    const assignmentSha256 = hashDomain("zerotrust-red-team-assignment", {
        issuerId: RED_TEAM_ASSIGNMENT_ISSUER_ID,
        reviewMode: RED_TEAM_REVIEW_MODE,
        planId: canonicalPlan.planId,
        snapshotId: canonicalPlan.snapshotId,
        semanticPlanId: canonicalPlan.semanticPlanId,
        supplyChainBindingSha256:
            canonicalPlan.hashes.supplyChainBindingSha256,
        categoryPlanSha256: categoryPlan.hashes.categoryPlanSha256,
        categoryId: category.id,
        roleId: category.roleId,
        reviewerId: reviewer,
        reviewerVersion: version,
        modelId: model,
        independence,
        assignmentNonceSha256: nonceSha256,
    });
    const tokenSha256 = hashDomain("zerotrust-red-team-assignment-token", {
        assignmentSha256,
        assignmentNonceSha256: nonceSha256,
    });
    return cloneFrozen({
        schemaVersion: RED_TEAM_SCHEMA_REVISION,
        contractKind: RED_TEAM_ASSIGNMENT_KIND,
        assignmentId: `ztra-${assignmentSha256}`,
        assignmentToken: `ztrt-${tokenSha256}`,
        issuerId: RED_TEAM_ASSIGNMENT_ISSUER_ID,
        reviewMode: RED_TEAM_REVIEW_MODE,
        auditId: canonicalPlan.auditId,
        sourceNamespace: canonicalPlan.sourceNamespace,
        planId: canonicalPlan.planId,
        snapshotId: canonicalPlan.snapshotId,
        semanticPlanId: canonicalPlan.semanticPlanId,
        semanticEvaluationId: canonicalPlan.semanticEvaluationId,
        initialDiscoveryHandoffId:
            canonicalPlan.initialDiscoveryHandoff.handoffId,
        supplyChainBindingSha256:
            canonicalPlan.hashes.supplyChainBindingSha256,
        categoryId: category.id,
        roleId: category.roleId,
        mandatory: category.mandatory,
        highRisk: category.highRisk,
        reviewerId: reviewer,
        reviewerVersion: version,
        modelId: model,
        independence,
        subjects: categoryPlan.subjects,
        falsificationChecks: categoryPlan.falsificationChecks,
        negativeEvidenceCodes: categoryPlan.negativeEvidenceCodes,
        normalizedView: categoryPlan.view,
        markers: {
            canary: RED_TEAM_CANARY_MARKER,
            outputContract: RED_TEAM_OUTPUT_CONTRACT_MARKER,
        },
        hashes: {
            categoryPlanSha256: categoryPlan.hashes.categoryPlanSha256,
            normalizedViewSha256: categoryPlan.view.hashes.viewSha256,
            assignmentNonceSha256: nonceSha256,
            assignmentSha256,
            tokenSha256,
        },
    });
}

export function validateRedTeamAssignment(
    value,
    { plan, planInputs },
    path = "redTeamAssignment",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "assignmentId",
        "assignmentToken",
        "issuerId",
        "reviewMode",
        "auditId",
        "sourceNamespace",
        "planId",
        "snapshotId",
        "semanticPlanId",
        "semanticEvaluationId",
        "initialDiscoveryHandoffId",
        "supplyChainBindingSha256",
        "categoryId",
        "roleId",
        "mandatory",
        "highRisk",
        "reviewerId",
        "reviewerVersion",
        "modelId",
        "independence",
        "subjects",
        "falsificationChecks",
        "negativeEvidenceCodes",
        "normalizedView",
        "markers",
        "hashes",
    ]);
    boundedString(value.assignmentId, `${path}.assignmentId`, {
        max: 72,
        pattern: ASSIGNMENT_ID_RE,
    });
    boundedString(value.assignmentToken, `${path}.assignmentToken`, {
        max: 72,
        pattern: ASSIGNMENT_TOKEN_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "categoryPlanSha256",
        "normalizedViewSha256",
        "assignmentNonceSha256",
        "assignmentSha256",
        "tokenSha256",
    ]);
    const expected = createRedTeamAssignment({
        plan,
        planInputs,
        categoryId: value.categoryId,
        reviewerId: value.reviewerId,
        reviewerVersion: value.reviewerVersion,
        modelId: value.modelId,
        assignmentNonceSha256: value.hashes.assignmentNonceSha256,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its wrapper-issued red-team assignment");
    }
    return expected;
}

function normalizeCandidate(candidate, assignment, path) {
    objectShape(candidate, path, [
        "behavior",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "benignHypothesisCode",
        "objectIds",
        "artifactIds",
        "factIds",
        "evidenceIds",
        "graphNodeIds",
        "graphEdgeIds",
    ]);
    objectShape(candidate.behavior, `${path}.behavior`, [
        "trigger",
        "capability",
        "action",
        "target",
    ]);
    const behavior = {};
    for (const key of ["trigger", "capability", "action", "target"]) {
        behavior[key] = boundedString(
            candidate.behavior[key],
            `${path}.behavior.${key}`,
            { max: 128, pattern: IDENTIFIER_RE },
        );
    }
    const identities = {
        objectIds: sortedUnique(candidate.objectIds, `${path}.objectIds`, {
            max: RED_TEAM_LIMITS.candidateIdentities,
            pattern: OBJECT_ID_RE,
        }),
        artifactIds: sortedUnique(candidate.artifactIds, `${path}.artifactIds`, {
            max: RED_TEAM_LIMITS.candidateIdentities,
            pattern: ARTIFACT_ID_RE,
        }),
        factIds: sortedUnique(candidate.factIds, `${path}.factIds`, {
            max: RED_TEAM_LIMITS.candidateIdentities,
            pattern: FACT_ID_RE,
        }),
        evidenceIds: sortedUnique(candidate.evidenceIds, `${path}.evidenceIds`, {
            max: RED_TEAM_LIMITS.candidateIdentities,
            pattern: EVIDENCE_ID_RE,
        }),
        graphNodeIds: sortedUnique(candidate.graphNodeIds, `${path}.graphNodeIds`, {
            max: RED_TEAM_LIMITS.candidateIdentities,
            pattern: GRAPH_NODE_ID_RE,
        }),
        graphEdgeIds: sortedUnique(candidate.graphEdgeIds, `${path}.graphEdgeIds`, {
            max: RED_TEAM_LIMITS.candidateIdentities,
            pattern: GRAPH_EDGE_ID_RE,
        }),
    };
    if (identities.objectIds.length === 0 || identities.evidenceIds.length === 0) {
        fail(path, "must bind at least one assigned object and evidence identity");
    }
    for (const [field, assigned] of [
        ["objectIds", assignment.subjects.objectIds],
        ["artifactIds", assignment.subjects.artifactIds],
        ["factIds", assignment.subjects.factIds],
        ["evidenceIds", assignment.subjects.evidenceIds],
        ["graphNodeIds", assignment.subjects.graphNodeIds],
        ["graphEdgeIds", assignment.subjects.graphEdgeIds],
    ]) {
        if (identities[field].some((id) => !assigned.includes(id))) {
            fail(`${path}.${field}`, "references an identity outside the assignment");
        }
    }
    const evidenceById = new Map(
        assignment.normalizedView.evidence.map((entry) =>
            [entry.evidenceId, entry]),
    );
    for (const evidenceId of identities.evidenceIds) {
        const evidence = evidenceById.get(evidenceId);
        if (!evidence || !identities.objectIds.includes(evidence.objectId)
            || (evidence.artifactId
                && !identities.artifactIds.includes(evidence.artifactId))
            || (evidence.factId && !identities.factIds.includes(evidence.factId))) {
            fail(`${path}.evidenceIds`, "is not internally bound to candidate identities");
        }
    }
    const graphEdgeById = new Map(
        assignment.normalizedView.graph.edges.map((edge) => [edge.edgeId, edge]),
    );
    for (const edgeId of identities.graphEdgeIds) {
        const edge = graphEdgeById.get(edgeId);
        if (!edge
            || !identities.graphNodeIds.includes(edge.fromNodeId)
            || !identities.graphNodeIds.includes(edge.toNodeId)) {
            fail(`${path}.graphEdgeIds`, "must be backed by candidate graph nodes");
        }
    }
    const base = {
        categoryId: assignment.categoryId,
        producerAssignmentId: assignment.assignmentId,
        behavior,
        severity: enumValue(candidate.severity, `${path}.severity`, [
            "info", "low", "medium", "high", "critical",
        ]),
        confidence: enumValue(candidate.confidence, `${path}.confidence`, [
            "low", "medium", "high",
        ]),
        maliciousProjectFit: enumValue(
            candidate.maliciousProjectFit,
            `${path}.maliciousProjectFit`,
            ["unknown", "unlikely", "ambiguous", "likely", "strong"],
        ),
        benignHypothesisCode: enumValue(
            candidate.benignHypothesisCode,
            `${path}.benignHypothesisCode`,
            RED_TEAM_BENIGN_HYPOTHESIS_CODES,
        ),
        ...identities,
    };
    const candidateSha256 = hashDomain("zerotrust-red-team-candidate", base);
    return cloneFrozen({
        candidateId: `ztrf-${candidateSha256}`,
        ...base,
        hashes: { candidateSha256 },
    });
}

function validateStoredCandidate(value, assignment, path) {
    objectShape(value, path, [
        "candidateId",
        "categoryId",
        "producerAssignmentId",
        "behavior",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "benignHypothesisCode",
        "objectIds",
        "artifactIds",
        "factIds",
        "evidenceIds",
        "graphNodeIds",
        "graphEdgeIds",
        "hashes",
    ]);
    boundedString(value.candidateId, `${path}.candidateId`, {
        max: 72,
        pattern: CANDIDATE_ID_RE,
    });
    const expected = normalizeCandidate({
        behavior: value.behavior,
        severity: value.severity,
        confidence: value.confidence,
        maliciousProjectFit: value.maliciousProjectFit,
        benignHypothesisCode: value.benignHypothesisCode,
        objectIds: value.objectIds,
        artifactIds: value.artifactIds,
        factIds: value.factIds,
        evidenceIds: value.evidenceIds,
        graphNodeIds: value.graphNodeIds,
        graphEdgeIds: value.graphEdgeIds,
    }, assignment, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic candidate identity");
    }
    return expected;
}

export function createRedTeamReviewRecord({
    assignment,
    plan,
    planInputs,
    assignmentToken,
    reviewerId,
    decision,
    reviewedObjectIds,
    reviewedArtifactIds,
    reviewedFactIds,
    reviewedEvidenceIds,
    reviewedGraphNodeIds,
    reviewedGraphEdgeIds,
    falsificationChecks,
    negativeEvidenceCodes,
    candidates = [],
    blockerCodes = [],
    canaryMarker,
    outputContractMarker,
} = {}, path = "redTeamReviewRecordInput") {
    const canonicalAssignment = validateRedTeamAssignment(
        assignment,
        { plan, planInputs },
        `${path}.assignment`,
    );
    if (assignmentToken !== canonicalAssignment.assignmentToken) {
        fail(`${path}.assignmentToken`, "does not match the wrapper-issued token");
    }
    if (reviewerId !== canonicalAssignment.reviewerId) {
        fail(`${path}.reviewerId`, "does not match the assigned reviewer");
    }
    if (canaryMarker !== RED_TEAM_CANARY_MARKER
        || outputContractMarker !== RED_TEAM_OUTPUT_CONTRACT_MARKER) {
        fail(path, "red-team canary or output-contract marker changed");
    }
    const reviewed = {
        objectIds: sortedUnique(reviewedObjectIds, `${path}.reviewedObjectIds`, {
            max: RED_TEAM_LIMITS.objectsPerCategory,
            pattern: OBJECT_ID_RE,
        }),
        artifactIds: sortedUnique(
            reviewedArtifactIds,
            `${path}.reviewedArtifactIds`,
            { max: RED_TEAM_LIMITS.artifactsPerCategory, pattern: ARTIFACT_ID_RE },
        ),
        factIds: sortedUnique(reviewedFactIds, `${path}.reviewedFactIds`, {
            max: RED_TEAM_LIMITS.factsPerCategory,
            pattern: FACT_ID_RE,
        }),
        evidenceIds: sortedUnique(
            reviewedEvidenceIds,
            `${path}.reviewedEvidenceIds`,
            { max: RED_TEAM_LIMITS.evidencePerCategory, pattern: EVIDENCE_ID_RE },
        ),
        graphNodeIds: sortedUnique(
            reviewedGraphNodeIds,
            `${path}.reviewedGraphNodeIds`,
            { max: RED_TEAM_LIMITS.graphNodesPerCategory, pattern: GRAPH_NODE_ID_RE },
        ),
        graphEdgeIds: sortedUnique(
            reviewedGraphEdgeIds,
            `${path}.reviewedGraphEdgeIds`,
            { max: RED_TEAM_LIMITS.graphEdgesPerCategory, pattern: GRAPH_EDGE_ID_RE },
        ),
    };
    for (const [field, assigned] of [
        ["objectIds", canonicalAssignment.subjects.objectIds],
        ["artifactIds", canonicalAssignment.subjects.artifactIds],
        ["factIds", canonicalAssignment.subjects.factIds],
        ["evidenceIds", canonicalAssignment.subjects.evidenceIds],
        ["graphNodeIds", canonicalAssignment.subjects.graphNodeIds],
        ["graphEdgeIds", canonicalAssignment.subjects.graphEdgeIds],
    ]) {
        if (reviewed[field].some((id) => !assigned.includes(id))) {
            fail(`${path}.reviewed${field[0].toUpperCase()}${field.slice(1)}`,
                "references an identity outside the assignment");
        }
    }
    const checks = sortedUnique(
        falsificationChecks,
        `${path}.falsificationChecks`,
        {
            max: canonicalAssignment.falsificationChecks.length,
            allowed: canonicalAssignment.falsificationChecks,
        },
    );
    const negatives = sortedUnique(
        negativeEvidenceCodes,
        `${path}.negativeEvidenceCodes`,
        {
            max: canonicalAssignment.negativeEvidenceCodes.length,
            allowed: canonicalAssignment.negativeEvidenceCodes,
        },
    );
    const normalizedDecision = enumValue(
        decision,
        `${path}.decision`,
        RED_TEAM_REVIEW_DECISIONS,
    );
    const normalizedBlockers = sortedUnique(
        blockerCodes,
        `${path}.blockerCodes`,
        {
            max: 3,
            allowed: [
                EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE,
                EVASIVE_BLOCKERS.RED_TEAM_ASSIGNMENT_INCOMPLETE,
                EVASIVE_BLOCKERS.RED_TEAM_REVIEWER_MANIPULATION,
            ],
        },
    );
    const normalizedCandidates = boundedArray(
        candidates,
        `${path}.candidates`,
        RED_TEAM_LIMITS.candidatesPerReview,
    ).map((candidate, index) =>
        normalizeCandidate(
            candidate,
            canonicalAssignment,
            `${path}.candidates[${index}]`,
        )).sort((left, right) => compareStrings(left.candidateId, right.candidateId));
    if (new Set(normalizedCandidates.map((candidate) => candidate.candidateId)).size
        !== normalizedCandidates.length) {
        fail(`${path}.candidates`, "must not contain duplicate candidates");
    }
    if (normalizedDecision === "incomplete") {
        if (!normalizedBlockers.includes(EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE)
            || !normalizedBlockers.includes(EVASIVE_BLOCKERS.RED_TEAM_ASSIGNMENT_INCOMPLETE)
            || normalizedCandidates.length > 0) {
            fail(path, "incomplete reviews require exact incompleteness blockers and no candidates");
        }
    } else {
        if (normalizedBlockers.length > 0) {
            fail(`${path}.blockerCodes`, "completed reviews must not contain blockers");
        }
        for (const [field, expected] of [
            ["objectIds", canonicalAssignment.subjects.objectIds],
            ["artifactIds", canonicalAssignment.subjects.artifactIds],
            ["factIds", canonicalAssignment.subjects.factIds],
            ["evidenceIds", canonicalAssignment.subjects.evidenceIds],
            ["graphNodeIds", canonicalAssignment.subjects.graphNodeIds],
            ["graphEdgeIds", canonicalAssignment.subjects.graphEdgeIds],
        ]) {
            exactArray(reviewed[field], expected, `${path}.reviewed.${field}`);
        }
        exactArray(
            checks,
            canonicalAssignment.falsificationChecks,
            `${path}.falsificationChecks`,
        );
        if (normalizedDecision === "no-candidate") {
            if (normalizedCandidates.length > 0) {
                fail(`${path}.candidates`, "must be empty for no-candidate");
            }
            exactArray(
                negatives,
                canonicalAssignment.negativeEvidenceCodes,
                `${path}.negativeEvidenceCodes`,
            );
        } else {
            if (normalizedCandidates.length === 0) {
                fail(`${path}.candidates`, "must contain a candidate");
            }
        }
    }
    const reviewSha256 = hashDomain("zerotrust-red-team-review-record", {
        assignmentId: canonicalAssignment.assignmentId,
        assignmentToken: canonicalAssignment.assignmentToken,
        reviewerId: canonicalAssignment.reviewerId,
        categoryId: canonicalAssignment.categoryId,
        decision: normalizedDecision,
        reviewed,
        falsificationChecks: checks,
        negativeEvidenceCodes: negatives,
        candidateIds: normalizedCandidates.map((candidate) => candidate.candidateId),
        blockerCodes: normalizedBlockers,
        canaryMarker,
        outputContractMarker,
    });
    return cloneFrozen({
        schemaVersion: RED_TEAM_SCHEMA_REVISION,
        contractKind: RED_TEAM_REVIEW_RECORD_KIND,
        reviewId: `ztrr-${reviewSha256}`,
        assignmentId: canonicalAssignment.assignmentId,
        assignmentToken: canonicalAssignment.assignmentToken,
        reviewerId: canonicalAssignment.reviewerId,
        modelId: canonicalAssignment.modelId,
        categoryId: canonicalAssignment.categoryId,
        roleId: canonicalAssignment.roleId,
        decision: normalizedDecision,
        reviewed,
        falsificationChecks: checks,
        negativeEvidenceCodes: negatives,
        candidates: normalizedCandidates,
        blockerCodes: normalizedBlockers,
        markers: {
            canary: canaryMarker,
            outputContract: outputContractMarker,
        },
        independence: canonicalAssignment.independence,
        hashes: {
            assignmentSha256: canonicalAssignment.hashes.assignmentSha256,
            normalizedViewSha256:
                canonicalAssignment.hashes.normalizedViewSha256,
            reviewSha256,
        },
    });
}

export function validateRedTeamReviewRecord(
    value,
    { assignment, plan, planInputs },
    path = "redTeamReviewRecord",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "reviewId",
        "assignmentId",
        "assignmentToken",
        "reviewerId",
        "modelId",
        "categoryId",
        "roleId",
        "decision",
        "reviewed",
        "falsificationChecks",
        "negativeEvidenceCodes",
        "candidates",
        "blockerCodes",
        "markers",
        "independence",
        "hashes",
    ]);
    boundedString(value.reviewId, `${path}.reviewId`, {
        max: 72,
        pattern: REVIEW_ID_RE,
    });
    const canonicalAssignment = validateRedTeamAssignment(
        assignment,
        { plan, planInputs },
        `${path}.assignment`,
    );
    const candidateInputs = boundedArray(
        value.candidates,
        `${path}.candidates`,
        RED_TEAM_LIMITS.candidatesPerReview,
    ).map((candidate, index) => {
        const stored = validateStoredCandidate(
            candidate,
            canonicalAssignment,
            `${path}.candidates[${index}]`,
        );
        const {
            candidateId: _candidateId,
            categoryId: _categoryId,
            producerAssignmentId: _producerAssignmentId,
            hashes: _hashes,
            ...input
        } = stored;
        return input;
    });
    const expected = createRedTeamReviewRecord({
        assignment: canonicalAssignment,
        plan,
        planInputs,
        assignmentToken: value.assignmentToken,
        reviewerId: value.reviewerId,
        decision: value.decision,
        reviewedObjectIds: value.reviewed.objectIds,
        reviewedArtifactIds: value.reviewed.artifactIds,
        reviewedFactIds: value.reviewed.factIds,
        reviewedEvidenceIds: value.reviewed.evidenceIds,
        reviewedGraphNodeIds: value.reviewed.graphNodeIds,
        reviewedGraphEdgeIds: value.reviewed.graphEdgeIds,
        falsificationChecks: value.falsificationChecks,
        negativeEvidenceCodes: value.negativeEvidenceCodes,
        candidates: candidateInputs,
        blockerCodes: value.blockerCodes,
        canaryMarker: value.markers?.canary,
        outputContractMarker: value.markers?.outputContract,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its immutable red-team review record");
    }
    return expected;
}

function dedupeExact(records, idField, conflictField, path) {
    const byId = new Map();
    const byConflict = new Map();
    for (const record of records) {
        const existing = byId.get(record[idField]);
        if (existing) {
            if (canonicalJson(existing) !== canonicalJson(record)) {
                fail(path, `contains conflicting duplicate ${idField}`);
            }
            continue;
        }
        const conflict = byConflict.get(record[conflictField]);
        if (conflict && conflict[idField] !== record[idField]) {
            fail(path, `contains conflicting records for ${conflictField}`);
        }
        byId.set(record[idField], record);
        byConflict.set(record[conflictField], record);
    }
    return [...byId.values()];
}

export function evaluateRedTeamCoverage({
    plan,
    planInputs,
    assignments = [],
    reviewRecords = [],
} = {}, path = "redTeamEvaluationInput") {
    const canonicalPlan = validateRedTeamPlan(plan, planInputs, `${path}.plan`);
    const canonicalAssignments = dedupeExact(
        boundedArray(
            assignments,
            `${path}.assignments`,
            RED_TEAM_LIMITS.categories,
        ).map((assignment, index) =>
            validateRedTeamAssignment(
                assignment,
                { plan: canonicalPlan, planInputs },
                `${path}.assignments[${index}]`,
            )),
        "assignmentId",
        "categoryId",
        `${path}.assignments`,
    );
    const assignmentById = new Map(
        canonicalAssignments.map((assignment) =>
            [assignment.assignmentId, assignment]),
    );
    const reviews = dedupeExact(
        boundedArray(
            reviewRecords,
            `${path}.reviewRecords`,
            RED_TEAM_LIMITS.categories,
        ).map((review, index) => {
            const assignment = assignmentById.get(review?.assignmentId);
            if (!assignment) {
                fail(
                    `${path}.reviewRecords[${index}].assignmentId`,
                    "does not reference a wrapper-issued assignment",
                );
            }
            return validateRedTeamReviewRecord(
                review,
                { assignment, plan: canonicalPlan, planInputs },
                `${path}.reviewRecords[${index}]`,
            );
        }),
        "reviewId",
        "assignmentId",
        `${path}.reviewRecords`,
    );
    const reviewByAssignment = new Map(
        reviews.map((review) => [review.assignmentId, review]),
    );
    const completedCategoryIds = [];
    const blockerDetails = [];
    const coverageRecords = [];
    for (const categoryPlan of canonicalPlan.categoryPlans) {
        const assignment = canonicalAssignments.find((entry) =>
            entry.categoryId === categoryPlan.categoryId);
        const review = assignment
            ? reviewByAssignment.get(assignment.assignmentId): null;
        const completed = review !== null
            && review !== undefined
            && review.decision !== "incomplete";
        if (completed) completedCategoryIds.push(categoryPlan.categoryId);
        else {
            blockerDetails.push(cloneFrozen({
                categoryId: categoryPlan.categoryId,
                roleId: categoryPlan.roleId,
                mandatory: categoryPlan.mandatory,
                assignmentId: assignment?.assignmentId || null,
                reviewId: review?.reviewId || null,
                reason: assignment
                    ? "assignment-incomplete-or-missing-review": "assignment-missing",
            }));
        }
        const objectById = new Map(
            planInputs.snapshot.objectInventory.map((object) =>
                [object.objectId, object]),
        );
        for (const objectId of categoryPlan.subjects.objectIds) {
            const object = objectById.get(objectId);
            const artifactIds = categoryPlan.subjects.artifactIds
                .filter((artifactId) => {
                    const artifact = planInputs.snapshot.derivedArtifacts.find((entry) =>
                        entry.artifactId === artifactId);
                    return artifact?.sourceObjectId === objectId;
                })
                .slice(0, EVASIVE_LIMITS.artifactReferencesPerCoverage);
            const recordBlockers = completed
                ? []: [
                    EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE,
                    EVASIVE_BLOCKERS.RED_TEAM_ASSIGNMENT_INCOMPLETE,
                ];
            const basisSha256 = hashDomain("zerotrust-red-team-object-coverage", {
                planId: canonicalPlan.planId,
                categoryPlanSha256: categoryPlan.hashes.categoryPlanSha256,
                assignmentId: assignment?.assignmentId || null,
                reviewId: review?.reviewId || null,
                objectId,
                artifactIds,
                decision: review?.decision || null,
                candidateIds: review?.candidates.map((candidate) =>
                    candidate.candidateId) || [],
                completed,
            });
            coverageRecords.push(createEvasiveRedTeamCoverageRecord({
                auditId: canonicalPlan.auditId,
                sourceNamespace: canonicalPlan.sourceNamespace,
                path: object.path,
                objectId,
                artifactIds,
                producer: "evasive-red-team",
                producerVersion: "1.0.0",
                status: completed ? "comprehensive": "partial",
                evasionClasses: categoryPlan.evasionClasses,
                blockerCodes: recordBlockers,
                basisSha256,
                objectIdentitySha256: object.hashes.identitySha256,
            }));
        }
    }
    coverageRecords.sort((left, right) =>
        compareStrings(left.redTeamCoverageId, right.redTeamCoverageId));
    blockerDetails.sort((left, right) =>
        compareStrings(left.categoryId, right.categoryId));
    const completedSet = new Set(completedCategoryIds);
    const missingMandatoryCategoryIds = canonicalPlan.mandatoryCategoryIds
        .filter((categoryId) => !completedSet.has(categoryId))
        .sort(compareStrings);
    const successfulAssignments = completedCategoryIds.length;
    const assignmentCount = canonicalPlan.categoryPlans.length;
    const ninetyPercentSatisfied =
        successfulAssignments * 100 >= assignmentCount * 90;
    const mandatoryCategoriesSatisfied = missingMandatoryCategoryIds.length === 0;
    const upstreamBlockers = planInputs.snapshot.blockerCodes
        .filter((code) => !RED_TEAM_STAGE_BLOCKERS.has(code));
    const complete = upstreamBlockers.length === 0
        && canonicalPlan.blockerCodes.length === 0
        && !canonicalPlan.truncated
        && ninetyPercentSatisfied
        && mandatoryCategoriesSatisfied
        && blockerDetails.length === 0;
    const blockerCodes = complete ? []: [...new Set([
        ...upstreamBlockers,
        ...canonicalPlan.blockerCodes,
        EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE,
        ...(missingMandatoryCategoryIds.length > 0
            ? [EVASIVE_BLOCKERS.RED_TEAM_MISSING_CATEGORY]: []),
        ...(blockerDetails.some((entry) => entry.assignmentId !== null)
            ? [EVASIVE_BLOCKERS.RED_TEAM_ASSIGNMENT_INCOMPLETE]: []),
        ...(canonicalPlan.truncated ? [EVASIVE_BLOCKERS.RED_TEAM_TRUNCATED]: []),
        ...(canonicalPlan.initialDiscoveryHandoff.promptManipulationReviewIds.length > 0
            && !completedSet.has("prompt-reviewer-manipulation")
            ? [EVASIVE_BLOCKERS.RED_TEAM_REVIEWER_MANIPULATION]: []),
    ])].sort(compareStrings);
    const candidateLedger = reviews
        .flatMap((review) => review.candidates)
        .sort((left, right) => compareStrings(left.candidateId, right.candidateId));
    if (new Set(candidateLedger.map((candidate) => candidate.candidateId)).size
        !== candidateLedger.length) {
        fail(`${path}.reviewRecords`, "contain duplicate candidate ledger identities");
    }
    const evaluationSha256 = hashDomain("zerotrust-red-team-evaluation", {
        planId: canonicalPlan.planId,
        assignmentIds: canonicalAssignments
            .map((assignment) => assignment.assignmentId).sort(compareStrings),
        reviewIds: reviews.map((review) => review.reviewId).sort(compareStrings),
        completedCategoryIds: completedCategoryIds.sort(compareStrings),
        missingMandatoryCategoryIds,
        candidateIds: candidateLedger
            .map((candidate) => candidate.candidateId).sort(compareStrings),
        coverageRecordIds: coverageRecords
            .map((record) => record.redTeamCoverageId).sort(compareStrings),
        blockerCodes,
        blockerDetails,
        complete,
    });
    return cloneFrozen({
        schemaVersion: RED_TEAM_SCHEMA_REVISION,
        contractKind: RED_TEAM_EVALUATION_KIND,
        evaluationId: `ztreval-${evaluationSha256}`,
        auditId: canonicalPlan.auditId,
        sourceNamespace: canonicalPlan.sourceNamespace,
        snapshotId: canonicalPlan.snapshotId,
        planId: canonicalPlan.planId,
        semanticPlanId: canonicalPlan.semanticPlanId,
        initialDiscoveryHandoffId:
            canonicalPlan.initialDiscoveryHandoff.handoffId,
        complete,
        status: complete ? "comprehensive": "partial",
        truncated: canonicalPlan.truncated,
        coverageRecords,
        candidateLedger,
        blockerCodes,
        blockerDetails: blockerDetails.slice(0, RED_TEAM_LIMITS.blockerDetails),
        blockerDetailsTruncated:
            blockerDetails.length > RED_TEAM_LIMITS.blockerDetails,
        gates: {
            assignmentCount,
            successfulAssignments,
            assignmentCoveragePercent: assignmentCount === 0
                ? 0: Math.floor((successfulAssignments * 100) / assignmentCount),
            ninetyPercentSatisfied,
            mandatoryCategoriesSatisfied,
            missingMandatoryCategoryIds,
            stageEligible: complete,
        },
        independenceLimits: canonicalAssignments
            .filter((assignment) =>
                assignment.independence.proceduralLimitCode !== null)
            .map((assignment) => cloneFrozen({
                assignmentId: assignment.assignmentId,
                categoryId: assignment.categoryId,
                reviewerId: assignment.reviewerId,
                modelId: assignment.modelId,
                proceduralLimitCode:
                    assignment.independence.proceduralLimitCode,
            }))
            .sort((left, right) =>
                compareStrings(left.assignmentId, right.assignmentId)),
        hashes: { evaluationSha256 },
    });
}

export function validateRedTeamEvaluation(
    value,
    { plan, planInputs, assignments = [], reviewRecords = [] },
    path = "redTeamEvaluation",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "evaluationId",
        "auditId",
        "sourceNamespace",
        "snapshotId",
        "planId",
        "semanticPlanId",
        "initialDiscoveryHandoffId",
        "complete",
        "status",
        "truncated",
        "coverageRecords",
        "candidateLedger",
        "blockerCodes",
        "blockerDetails",
        "blockerDetailsTruncated",
        "gates",
        "independenceLimits",
        "hashes",
    ]);
    boundedString(value.evaluationId, `${path}.evaluationId`, {
        max: 75,
        pattern: EVALUATION_ID_RE,
    });
    const expected = evaluateRedTeamCoverage({
        plan,
        planInputs,
        assignments,
        reviewRecords,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match the deterministic red-team evaluation");
    }
    return expected;
}

export function applyRedTeamCoverageToSnapshot({
    snapshot,
    evaluation,
    stageState = snapshot?.stageState,
} = {}) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    if (!evaluation
        || evaluation.schemaVersion !== RED_TEAM_SCHEMA_REVISION
        || evaluation.contractKind !== RED_TEAM_EVALUATION_KIND
        || evaluation.auditId !== current.auditId
        || evaluation.sourceNamespace !== current.sourceNamespace
        || evaluation.snapshotId !== current.snapshotId) {
        fail("evaluation", "does not bind to the supplied scanned snapshot");
    }
    const upstreamBlockers = current.blockerCodes.filter((code) =>
        !RED_TEAM_STAGE_BLOCKERS.has(code));
    const blockerCodes = evaluation.complete
        ? upstreamBlockers: [...new Set([
            ...upstreamBlockers,
            ...evaluation.blockerCodes,
        ])].sort(compareStrings);
    return createAssuranceAnalysisSnapshot({
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        stageState,
        status: "incomplete",
        objectInventory: current.objectInventory,
        derivedArtifacts: current.derivedArtifacts,
        semanticReviewCoverage: current.semanticReviewCoverage,
        semanticCandidateLedger: current.semanticCandidateLedger,
        redTeamCoverage: evaluation.coverageRecords,
        blockerCodes,
        sourceIdentitySha256: current.hashes.sourceIdentitySha256,
    });
}

export function redTeamSnapshotCanAdvance(snapshot, evaluation) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    return current.stageState.current === "scanned"
        && evaluation?.complete === true
        && evaluation.truncated === false
        && evaluation.blockerCodes?.length === 0
        && evaluation.blockerDetailsTruncated === false
        && evaluation.gates?.ninetyPercentSatisfied === true
        && evaluation.gates?.mandatoryCategoriesSatisfied === true;
}

export const __internals = Object.freeze({
    RED_TEAM_STAGE_BLOCKERS,
    alternatePathGroups,
    canonicalJson,
    categorySubjectSet,
    discoveryGraph,
    evidenceCorpus,
    hashDomain,
    requiredProceduralLimit,
    supplyChainBinding,
});
