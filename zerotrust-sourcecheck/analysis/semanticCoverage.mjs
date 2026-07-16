import { createHash } from "node:crypto";
import nodePath from "node:path";

import { EVASION_CLASSES } from "./assurance.mjs";
import {
    createPromptReviewAssignment,
    validatePromptNormalizedView,
    validatePromptReviewRecord,
} from "./promptResilience.mjs";
import {
    SCANNER_LIMITS,
    selectScanner,
    validateScannerResult,
    validateSemanticFact,
} from "./scanners/index.mjs";
import {
    EVASIVE_BLOCKERS,
    EVASIVE_LIMITS,
    EVASIVE_SEMANTIC_BENIGN_HYPOTHESIS_CODES,
    EVASIVE_SEMANTIC_CANDIDATE_CONFIDENCE_LEVELS,
    EVASIVE_SEMANTIC_CANDIDATE_FIT_LEVELS,
    EVASIVE_SEMANTIC_CANDIDATE_SEVERITIES,
    createAssuranceAnalysisSnapshot,
    createEvasiveSemanticCandidateRecord,
    createEvasiveSemanticReviewCoverageRecord,
    validateEvasiveSemanticCandidateRecord,
    validateAssuranceAnalysisSnapshot,
} from "./evasiveSchemas.mjs";
import { ASSURANCE_ANALYSIS_SCHEMA_REVISION } from "./assuranceState.mjs";

// Additive assurance-only semantic coverage. The live baseline packet remains unchanged.
export const SEMANTIC_COVERAGE_SCHEMA_REVISION = 6;
export const SEMANTIC_COVERAGE_PLAN_KIND = "semantic-coverage-plan";
export const SEMANTIC_SCANNER_ASSIGNMENT_KIND = "semantic-scanner-assignment";
export const SEMANTIC_SCANNER_RECORD_KIND = "semantic-scanner-coverage-record";
export const SEMANTIC_REVIEW_ASSIGNMENT_KIND = "semantic-model-review-assignment";
export const SEMANTIC_REVIEW_RECORD_KIND = "semantic-model-review-record";
export const SEMANTIC_VIEW_KIND = "semantic-review-view";
export const SEMANTIC_COVERAGE_EVALUATION_KIND = "semantic-coverage-evaluation";
export const SEMANTIC_ASSIGNMENT_ISSUER_ID = "zerotrust-sourcecheck-wrapper";
export const SEMANTIC_REVIEW_MODE = "independent-object-semantic-review";

if (SEMANTIC_COVERAGE_SCHEMA_REVISION !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
    throw new Error("semantic coverage and assurance analysis schema revisions must align");
}

export const SEMANTIC_OBJECT_CLASSES = Object.freeze([
    "executable-source",
    "build-config",
    "workflow",
    "generated-input",
    "dependency-metadata",
    "binary-archive",
    "document-data",
    "unsupported",
]);

export const SEMANTIC_REVIEW_DECISIONS = Object.freeze([
    "findings-recorded",
    "no-findings",
    "incomplete",
]);

export const SEMANTIC_CHECK_NAMES = Object.freeze([
    "activationAndEntryPoints",
    "dataflowSourcesTransformsSinks",
    "dynamicExecutionAndIndirection",
    "environmentTimeStateGates",
    "generatedAndDecodedContent",
    "externalPayloads",
    "buildAndWorkflowHooks",
    "dependencyResolution",
]);

export const SEMANTIC_CHECK_RESULTS = Object.freeze([
    "checked",
    "not-applicable",
    "unresolved",
]);

export const SEMANTIC_NEGATIVE_EVIDENCE_CODES = Object.freeze([
    "no-activation-path-supported",
    "no-source-transform-sink-chain-supported",
    "no-dynamic-execution-supported",
    "no-environment-time-state-gate-supported",
    "no-generated-or-decoded-payload-supported",
    "no-external-payload-supported",
    "no-build-workflow-hook-supported",
    "no-dependency-substitution-supported",
]);

export const SEMANTIC_COVERAGE_LIMITS = Object.freeze({
    scannerShards: 256,
    modelShards: 256,
    reviewersPerObject: 2,
    candidatesPerReview: 64,
    factsPerView: 8_192,
    blockerDetails: 2_048,
});

const SHA256_RE = /^[a-f0-9]{64}$/u;
const OBJECT_ID_RE = /^zto-[a-f0-9]{64}$/u;
const ARTIFACT_ID_RE = /^zta-[a-f0-9]{64}$/u;
const PLAN_ID_RE = /^ztsp-[a-f0-9]{64}$/u;
const SCANNER_ASSIGNMENT_ID_RE = /^ztsa-[a-f0-9]{64}$/u;
const SCANNER_ASSIGNMENT_TOKEN_RE = /^ztst-[a-f0-9]{64}$/u;
const SCANNER_RECORD_ID_RE = /^ztsr-[a-f0-9]{64}$/u;
const REVIEW_ASSIGNMENT_ID_RE = /^ztsma-[a-f0-9]{64}$/u;
const REVIEW_ASSIGNMENT_TOKEN_RE = /^ztsmt-[a-f0-9]{64}$/u;
const REVIEW_RECORD_ID_RE = /^ztsmr-[a-f0-9]{64}$/u;
const SEMANTIC_VIEW_ID_RE = /^ztsv-[a-f0-9]{64}$/u;
const SEMANTIC_EVIDENCE_ID_RE = /^ztre-[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u;
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/u;

const SOURCE_EXTENSIONS = new Set([
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".cs", ".csx", ".fs", ".fsx", ".go", ".java", ".js", ".jsx",
    ".kt", ".kts", ".lua", ".m", ".mm", ".mjs", ".cjs", ".mts",
    ".cts", ".php", ".pl", ".pm", ".py", ".pyi", ".pyw", ".rb",
    ".rs", ".scala", ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".psm1", ".cmd", ".bat", ".swift", ".ts", ".tsx", ".vb",
]);

const BINARY_ARCHIVE_EXTENSIONS = new Set([
    ".7z", ".a", ".apk", ".appx", ".bin", ".bz2", ".cab", ".class",
    ".deb", ".dll", ".dmg", ".dylib", ".ear", ".exe", ".gz", ".iso",
    ".jar", ".lib", ".msi", ".nupkg", ".o", ".obj", ".pdf", ".pkg",
    ".rar", ".rpm", ".so", ".tar", ".tgz", ".wasm", ".war", ".whl",
    ".xz", ".zip", ".zst",
]);

const GENERATED_EXTENSIONS = new Set([
    ".ejs", ".erb", ".hbs", ".jinja", ".jinja2", ".liquid", ".mustache",
    ".njk", ".tmpl", ".tpl", ".tt", ".in", ".proto",
]);

const DEPENDENCY_BASENAMES = new Set([
    "bun.lock", "bun.lockb", "cargo.lock", "composer.lock", "deno.lock",
    "gemfile.lock", "go.mod", "go.sum", "packages.lock.json",
    "package-lock.json", "pnpm-lock.yaml", "poetry.lock", "pypi.lock",
    "requirements.txt", "uv.lock", "yarn.lock",
]);

const BUILD_BASENAMES = new Set([
    "build.gradle", "build.gradle.kts", "build.xml", "cargo.toml",
    "cmakelists.txt", "composer.json", "deno.json", "deno.jsonc",
    "directory.build.props", "directory.build.targets", "dockerfile",
    "gemfile", "go.work", "gradle.properties", "makefile", "meson.build",
    "package.json", "pyproject.toml", "sconstruct", "setup.cfg", "setup.py",
    "taskfile.yml", "taskfile.yaml", "vagrantfile",
]);

const WORKFLOW_BASENAMES = new Set([
    ".gitlab-ci.yml", "appveyor.yml", "azure-pipelines.yml", "bitrise.yml",
    "buildkite.yml", "circle.yml", "jenkinsfile", "teamcity-settings.kts",
]);

const CONFIG_SOURCE_CLASSES = new Set([
    "executable-source",
    "build-config",
    "workflow",
    "generated-input",
    "dependency-metadata",
]);

const TEXTUAL_ARTIFACT_KINDS = new Set([
    "decoded-text",
    "deobfuscated-view",
    "generated-source",
    "intermediate-representation",
]);

const SEMANTIC_STAGE_BLOCKERS = new Set([
    EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE,
    EVASIVE_BLOCKERS.SEMANTIC_TRUNCATED,
]);

const NEGATIVE_CODE_BY_CHECK = Object.freeze({
    activationAndEntryPoints: "no-activation-path-supported",
    dataflowSourcesTransformsSinks: "no-source-transform-sink-chain-supported",
    dynamicExecutionAndIndirection: "no-dynamic-execution-supported",
    environmentTimeStateGates: "no-environment-time-state-gate-supported",
    generatedAndDecodedContent: "no-generated-or-decoded-payload-supported",
    externalPayloads: "no-external-payload-supported",
    buildAndWorkflowHooks: "no-build-workflow-hook-supported",
    dependencyResolution: "no-dependency-substitution-supported",
});

const FACT_KINDS_BY_CHECK = Object.freeze({
    activationAndEntryPoints: Object.freeze([
        "activation",
        "persistence",
    ]),
    dataflowSourcesTransformsSinks: Object.freeze([
        "source",
        "transform",
        "sink",
        "command-construction",
    ]),
    dynamicExecutionAndIndirection: Object.freeze([
        "dynamic-import",
        "reflection",
        "dynamic-evaluation",
        "unresolved-dynamic-target",
    ]),
    environmentTimeStateGates: Object.freeze([
        "environment-gate",
        "platform-gate",
        "time-gate",
    ]),
    generatedAndDecodedContent: Object.freeze([
        "generated-code-hook",
    ]),
    externalPayloads: Object.freeze([
        "dynamic-import",
        "source",
        "sink",
        "unresolved-dynamic-target",
    ]),
    buildAndWorkflowHooks: Object.freeze([
        "activation",
        "command-construction",
        "generated-code-hook",
        "persistence",
    ]),
    dependencyResolution: Object.freeze([
        "import",
        "dynamic-import",
    ]),
});

export class SemanticCoverageContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "SemanticCoverageContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new SemanticCoverageContractError(path, message);
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
        for (const [key, entry] of Object.entries(value)) {
            result[key] = cloneFrozen(entry);
        }
        return Object.freeze(result);
    }
    return value;
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function hashDomain(domain, value) {
    return createHash("sha256")
        .update(`${domain}\0${canonicalJson(value)}`, "utf8")
        .digest("hex");
}

function compareStrings(left, right) {
    return String(left).localeCompare(String(right));
}

function boundedString(value, path, { max, pattern }) {
    if (typeof value !== "string" || value.length < 1 || value.length > max
        || (pattern && !pattern.test(value))) {
        fail(path, "is invalid");
    }
    return value;
}

function enumValue(value, path, allowed) {
    if (!allowed.includes(value)) fail(path, `must be one of: ${allowed.join(", ")}`);
    return value;
}

function boundedInteger(value, path, min, max) {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
        fail(path, `must be an integer between ${min} and ${max}`);
    }
    return value;
}

function boundedArray(value, path, max) {
    if (!Array.isArray(value) || value.length > max) {
        fail(path, `must be an array with at most ${max} entries`);
    }
    return value;
}

function sortedUnique(values, path, {
    max,
    pattern = null,
    allowed = null,
} = {}) {
    const entries = boundedArray(values, path, max);
    const normalized = entries.map((entry, index) => {
        if (typeof entry !== "string" || entry.length === 0
            || (pattern && !pattern.test(entry))
            || (allowed && !allowed.includes(entry))) {
            fail(`${path}[${index}]`, "is invalid");
        }
        return entry;
    }).sort(compareStrings);
    if (new Set(normalized).size !== normalized.length) {
        fail(path, "must not contain duplicates");
    }
    return normalized;
}

function pathParts(value) {
    const path = String(value || "").replace(/\\/gu, "/");
    const lower = path.toLowerCase();
    return {
        path,
        lower,
        basename: nodePath.posix.basename(lower),
        extension: nodePath.posix.extname(lower),
    };
}

function isWorkflowPath(parts) {
    return parts.lower.startsWith(".github/workflows/")
        || parts.lower.includes("/.github/workflows/")
        || parts.lower.startsWith(".circleci/")
        || parts.lower.includes("/.circleci/")
        || parts.lower.startsWith(".buildkite/")
        || parts.lower.includes("/.buildkite/")
        || WORKFLOW_BASENAMES.has(parts.basename);
}

function isBuildPath(parts) {
    return BUILD_BASENAMES.has(parts.basename)
        || /^(?:dockerfile|containerfile)(?:\..+)?$/u.test(parts.basename)
        || /\.(?:csproj|fsproj|vbproj|vcxproj|props|targets|proj|gradle|cmake|mk)$/u
            .test(parts.lower)
        || parts.lower.startsWith(".devcontainer/")
        || parts.lower.includes("/.devcontainer/");
}

function isDependencyPath(parts, object) {
    return object.objectKind === "dependency-metadata"
        || DEPENDENCY_BASENAMES.has(parts.basename)
        || /(?:^|\/)requirements(?:[-_.][^/]*)?\.txt$/u.test(parts.lower)
        || /\.(?:lock|lockb)$/u.test(parts.lower);
}

function isGeneratedPath(parts, object) {
    return object.objectKind === "generated-source"
        || GENERATED_EXTENSIONS.has(parts.extension)
        || /(?:^|\/)(?:generated|codegen|templates?|scaffolds?)(?:\/|$)/u
            .test(parts.lower);
}

function isBinaryArchive(parts, object) {
    return [
        "archive",
        "binary",
        "embedded-payload",
        "release-asset",
    ].includes(object.objectKind)
        || BINARY_ARCHIVE_EXTENSIONS.has(parts.extension);
}

function evasionClassesForSemanticClass(semanticClass) {
    const common = [
        EVASION_CLASSES.OBFUSCATION_GENERATION_AND_SELF_MODIFICATION,
        EVASION_CLASSES.INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION,
        EVASION_CLASSES.ENVIRONMENT_TIME_AND_STATE_GATED_ACTIVATION,
        EVASION_CLASSES.DYNAMIC_CODE_AND_EXTERNAL_PAYLOAD_LOADING,
    ];
    const byClass = {
        "executable-source": common,
        "build-config": [
            ...common,
            EVASION_CLASSES.CROSS_LANGUAGE_AND_BUILD_GRAPH_INDIRECTION,
        ],
        workflow: [
            ...common,
            EVASION_CLASSES.CROSS_LANGUAGE_AND_BUILD_GRAPH_INDIRECTION,
        ],
        "generated-input": [
            ...common,
            EVASION_CLASSES.ENCODING_AND_PARSER_DIFFERENTIALS,
        ],
        "dependency-metadata": [
            EVASION_CLASSES.DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION,
            EVASION_CLASSES.CROSS_LANGUAGE_AND_BUILD_GRAPH_INDIRECTION,
        ],
        "binary-archive": [
            EVASION_CLASSES.BINARY_AND_EMBEDDED_PAYLOADS,
            EVASION_CLASSES.ENCODING_AND_PARSER_DIFFERENTIALS,
            EVASION_CLASSES.DYNAMIC_CODE_AND_EXTERNAL_PAYLOAD_LOADING,
        ],
        "document-data": [
            EVASION_CLASSES.REVIEWER_MANIPULATION_AND_PROMPT_INJECTION,
        ],
        unsupported: [
            EVASION_CLASSES.UNSUPPORTED_OR_OPAQUE_ARTIFACTS,
        ],
    };
    return [...new Set(byClass[semanticClass])].sort(compareStrings);
}

export function classifyObjectForSemanticCoverage(
    object,
    { artifacts = [], promptAffected = false } = {},
) {
    if (!object || object.schemaVersion !== 6 || !OBJECT_ID_RE.test(object.objectId || "")) {
        fail("object", "must be a validated assurance inventory object");
    }
    const parts = pathParts(object.path);
    let semanticClass;
    if (["tree", "symlink", "gitlink", "reparse-point", "opaque"].includes(
        object.objectKind,
    )) {
        semanticClass = "unsupported";
    } else if (isWorkflowPath(parts)) {
        semanticClass = "workflow";
    } else if (isDependencyPath(parts, object)) {
        semanticClass = "dependency-metadata";
    } else if (isBuildPath(parts) || object.objectKind === "manifest") {
        semanticClass = "build-config";
    } else if (isGeneratedPath(parts, object)) {
        semanticClass = "generated-input";
    } else if (isBinaryArchive(parts, object)) {
        semanticClass = "binary-archive";
    } else if (object.executable === true
        || object.objectKind === "executable-blob"
        || SOURCE_EXTENSIONS.has(parts.extension)) {
        semanticClass = "executable-source";
    } else if (["source-text", "blob", "local-file"].includes(object.objectKind)) {
        semanticClass = "document-data";
    } else {
        semanticClass = "unsupported";
    }

    const artifactIds = artifacts
        .filter((artifact) => artifact.sourceObjectId === object.objectId)
        .map((artifact) => artifact.artifactId)
        .sort(compareStrings);
    const configOrExecutable = CONFIG_SOURCE_CLASSES.has(semanticClass);
    const scannerRequired = configOrExecutable;
    const modelReviewRequired = configOrExecutable
        || semanticClass === "binary-archive"
        || promptAffected;
    const highRisk = [
        "workflow",
        "build-config",
        "generated-input",
        "binary-archive",
    ].includes(semanticClass)
        || object.executable === true
        || object.objectKind === "executable-blob"
        || promptAffected;
    const requiredReviewerCount = modelReviewRequired ? (highRisk ? 2: 1): 0;
    const required = scannerRequired || modelReviewRequired;
    const classificationSha256 = hashDomain("zerotrust-semantic-classification", {
        objectId: object.objectId,
        objectIdentitySha256: object.hashes.identitySha256,
        path: object.path,
        semanticClass,
        artifactIds,
        scannerRequired,
        modelReviewRequired,
        highRisk,
        requiredReviewerCount,
        promptAffected,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        classificationId: `ztscclass-${classificationSha256}`,
        objectId: object.objectId,
        path: object.path,
        semanticClass,
        artifactIds,
        required,
        scannerRequired,
        modelReviewRequired,
        highRisk,
        requiredReviewerCount,
        promptAssessmentRequired: configOrExecutable,
        promptAffected,
        evasionClasses: evasionClassesForSemanticClass(semanticClass),
        hashes: {
            objectIdentitySha256: object.hashes.identitySha256,
            classificationSha256,
        },
    });
}

function deterministicShard(domain, identitySha256, shardCount) {
    const digest = hashDomain(domain, identitySha256);
    return Number.parseInt(digest.slice(0, 12), 16) % shardCount;
}

function normalizeViews(snapshot, normalizedViews, path) {
    const views = boundedArray(
        normalizedViews,
        path,
        EVASIVE_LIMITS.semanticCoverageRecords,
    ).map((view, index) =>
        validatePromptNormalizedView(view, `${path}[${index}]`));
    const objectById = new Map(
        snapshot.objectInventory.map((object) => [object.objectId, object]),
    );
    const byObjectId = new Map();
    for (const [index, view] of views.entries()) {
        const object = objectById.get(view.objectId);
        if (!object
            || view.auditId !== snapshot.auditId
            || view.sourceNamespace !== snapshot.sourceNamespace
            || view.path !== object.path
            || view.hashes.objectIdentitySha256 !== object.hashes.identitySha256) {
            fail(`${path}[${index}]`, "does not bind to the supplied assurance snapshot");
        }
        if (byObjectId.has(view.objectId)) {
            fail(path, "must contain at most one normalized view per object");
        }
        byObjectId.set(view.objectId, view);
    }
    return { views: [...views].sort((a, b) => compareStrings(a.objectId, b.objectId)), byObjectId };
}

function scannerSubjectPath(object, artifact) {
    return artifact ? artifact.path: object.path;
}

function createScannerAssignment({
    snapshot,
    planBasisSha256,
    object,
    artifact,
    scannerShardCount,
}) {
    const path = scannerSubjectPath(object, artifact);
    const contentSha256 = artifact
        ? artifact.hashes.contentSha256: object.hashes.contentSha256;
    const scanner = selectScanner(path);
    const artifactId = artifact?.artifactId || null;
    const subjectSha256 = hashDomain("zerotrust-semantic-scanner-subject", {
        objectId: object.objectId,
        artifactId,
        path,
        contentSha256,
        objectIdentitySha256: object.hashes.identitySha256,
    });
    const assignmentSha256 = hashDomain("zerotrust-semantic-scanner-assignment", {
        issuerId: SEMANTIC_ASSIGNMENT_ISSUER_ID,
        auditId: snapshot.auditId,
        sourceNamespace: snapshot.sourceNamespace,
        snapshotId: snapshot.snapshotId,
        planBasisSha256,
        subjectSha256,
        scannerId: scanner.id,
        scannerShardCount,
        scannerShard: deterministicShard(
            "zerotrust-semantic-scanner-shard",
            subjectSha256,
            scannerShardCount,
        ),
    });
    const tokenSha256 = hashDomain("zerotrust-semantic-scanner-token", {
        assignmentSha256,
        planBasisSha256,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        contractKind: SEMANTIC_SCANNER_ASSIGNMENT_KIND,
        assignmentId: `ztsa-${assignmentSha256}`,
        assignmentToken: `ztst-${tokenSha256}`,
        issuerId: SEMANTIC_ASSIGNMENT_ISSUER_ID,
        auditId: snapshot.auditId,
        sourceNamespace: snapshot.sourceNamespace,
        snapshotId: snapshot.snapshotId,
        objectId: object.objectId,
        artifactId,
        path,
        contentSha256,
        objectIdentitySha256: object.hashes.identitySha256,
        scannerId: scanner.id,
        scannerShard: deterministicShard(
            "zerotrust-semantic-scanner-shard",
            subjectSha256,
            scannerShardCount,
        ),
        hashes: {
            subjectSha256,
            assignmentSha256,
            tokenSha256,
        },
    });
}

export function createSemanticCoveragePlan({
    snapshot,
    normalizedViews = [],
    scannerShardCount = 16,
    modelShardCount = 16,
} = {}, path = "semanticCoveragePlanInput") {
    const current = validateAssuranceAnalysisSnapshot(snapshot, `${path}.snapshot`);
    if (current.stageState.current !== "decoded") {
        fail(`${path}.snapshot.stageState.current`, "must be decoded");
    }
    const scannerShards = boundedInteger(
        scannerShardCount,
        `${path}.scannerShardCount`,
        1,
        SEMANTIC_COVERAGE_LIMITS.scannerShards,
    );
    const modelShards = boundedInteger(
        modelShardCount,
        `${path}.modelShardCount`,
        1,
        SEMANTIC_COVERAGE_LIMITS.modelShards,
    );
    const { views, byObjectId: viewByObjectId } = normalizeViews(
        current,
        normalizedViews,
        `${path}.normalizedViews`,
    );
    const artifactsByObject = new Map();
    for (const artifact of current.derivedArtifacts) {
        if (!artifactsByObject.has(artifact.sourceObjectId)) {
            artifactsByObject.set(artifact.sourceObjectId, []);
        }
        artifactsByObject.get(artifact.sourceObjectId).push(artifact);
    }
    const classifications = current.objectInventory.map((object) =>
        classifyObjectForSemanticCoverage(object, {
            artifacts: artifactsByObject.get(object.objectId) || [],
            promptAffected: viewByObjectId.get(object.objectId)?.promptAffected === true,
        })).sort((left, right) => compareStrings(left.objectId, right.objectId));

    const missingPromptAssessmentObjectIds = classifications
        .filter((classification) =>
            classification.promptAssessmentRequired
            && !viewByObjectId.has(classification.objectId))
        .map((classification) => classification.objectId)
        .sort(compareStrings);
    const planBasisSha256 = hashDomain("zerotrust-semantic-plan-basis", {
        snapshotId: current.snapshotId,
        snapshotSha256: current.hashes.snapshotSha256,
        scannerShardCount: scannerShards,
        modelShardCount: modelShards,
        normalizedViewIds: views.map((view) => view.normalizedViewId),
        classifications,
    });
    const scannerAssignments = [];
    for (const classification of classifications) {
        const object = current.objectInventory.find((entry) =>
            entry.objectId === classification.objectId);
        if (classification.scannerRequired
            && object.hashes.contentSha256 !== null
            && object.path.length <= SCANNER_LIMITS.path) {
            scannerAssignments.push(createScannerAssignment({
                snapshot: current,
                planBasisSha256,
                object,
                artifact: null,
                scannerShardCount: scannerShards,
            }));
        }
        for (const artifact of artifactsByObject.get(object.objectId) || []) {
            if (artifact.status === "decoded"
                && TEXTUAL_ARTIFACT_KINDS.has(artifact.artifactKind)
                && artifact.path.length <= SCANNER_LIMITS.path) {
                scannerAssignments.push(createScannerAssignment({
                    snapshot: current,
                    planBasisSha256,
                    object,
                    artifact,
                    scannerShardCount: scannerShards,
                }));
            }
        }
    }
    scannerAssignments.sort((left, right) =>
        compareStrings(left.assignmentId, right.assignmentId));

    const modelReviewShards = classifications
        .filter((classification) => classification.modelReviewRequired)
        .map((classification) => {
            const normalizedView = viewByObjectId.get(classification.objectId) || null;
            const modelShard = deterministicShard(
                "zerotrust-semantic-model-shard",
                classification.hashes.classificationSha256,
                modelShards,
            );
            return cloneFrozen({
                objectId: classification.objectId,
                path: classification.path,
                semanticClass: classification.semanticClass,
                artifactIds: classification.artifactIds,
                highRisk: classification.highRisk,
                requiredReviewerCount: classification.requiredReviewerCount,
                modelShard,
                normalizedViewId: normalizedView?.normalizedViewId || null,
                promptAffected: normalizedView?.promptAffected === true,
            });
        }).sort((left, right) => compareStrings(left.objectId, right.objectId));
    const blockerCodes = [];
    if (missingPromptAssessmentObjectIds.length > 0) {
        blockerCodes.push(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE);
    }
    if (scannerAssignments.length > EVASIVE_LIMITS.semanticCoverageRecords
        || modelReviewShards.length > EVASIVE_LIMITS.semanticCoverageRecords) {
        fail(path, "semantic assignment bounds exceeded");
    }
    const planSha256 = hashDomain("zerotrust-semantic-coverage-plan", {
        planBasisSha256,
        classifications,
        scannerAssignments,
        modelReviewShards,
        missingPromptAssessmentObjectIds,
        blockerCodes,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        contractKind: SEMANTIC_COVERAGE_PLAN_KIND,
        planId: `ztsp-${planSha256}`,
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        snapshotId: current.snapshotId,
        stage: current.stageState.current,
        scannerShardCount: scannerShards,
        modelShardCount: modelShards,
        normalizedViews: views,
        classifications,
        scannerAssignments,
        modelReviewShards,
        missingPromptAssessmentObjectIds,
        blockerCodes,
        truncated: false,
        hashes: {
            snapshotSha256: current.hashes.snapshotSha256,
            planBasisSha256,
            planSha256,
        },
    });
}

export function validateSemanticCoveragePlan(
    value,
    snapshot,
    path = "semanticCoveragePlan",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "planId",
        "auditId",
        "sourceNamespace",
        "snapshotId",
        "stage",
        "scannerShardCount",
        "modelShardCount",
        "normalizedViews",
        "classifications",
        "scannerAssignments",
        "modelReviewShards",
        "missingPromptAssessmentObjectIds",
        "blockerCodes",
        "truncated",
        "hashes",
    ]);
    if (value.schemaVersion !== SEMANTIC_COVERAGE_SCHEMA_REVISION
        || value.contractKind !== SEMANTIC_COVERAGE_PLAN_KIND
        || value.truncated !== false) {
        fail(path, "has an invalid semantic plan contract");
    }
    boundedString(value.planId, `${path}.planId`, { max: 72, pattern: PLAN_ID_RE });
    const expected = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: value.normalizedViews,
        scannerShardCount: value.scannerShardCount,
        modelShardCount: value.modelShardCount,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic semantic coverage plan");
    }
    return expected;
}

function findScannerAssignment(plan, assignmentId, path) {
    boundedString(assignmentId, path, {
        max: 72,
        pattern: SCANNER_ASSIGNMENT_ID_RE,
    });
    const assignment = plan.scannerAssignments.find((entry) =>
        entry.assignmentId === assignmentId);
    if (!assignment) fail(path, "does not reference a plan scanner assignment");
    return assignment;
}

export function createSemanticScannerCoverageRecord({
    plan,
    snapshot,
    assignmentId,
    assignmentToken,
    scannerResult,
} = {}, path = "semanticScannerCoverageInput") {
    const canonicalPlan = validateSemanticCoveragePlan(plan, snapshot, `${path}.plan`);
    const assignment = findScannerAssignment(
        canonicalPlan,
        assignmentId,
        `${path}.assignmentId`,
    );
    if (assignmentToken !== assignment.assignmentToken) {
        fail(`${path}.assignmentToken`, "does not match the wrapper-issued token");
    }
    const result = validateScannerResult(scannerResult, `${path}.scannerResult`);
    if (result.scannerId !== assignment.scannerId
        || result.path !== assignment.path
        || result.sourceSha256 !== assignment.contentSha256) {
        fail(`${path}.scannerResult`, "does not match the assigned scanner subject");
    }
    const facts = [...result.facts].sort((left, right) =>
        compareStrings(left.id, right.id));
    const factIds = facts.map((fact) => fact.id);
    const scannerResultSha256 = hashDomain("zerotrust-semantic-scanner-result", {
        scannerId: result.scannerId,
        language: result.language,
        path: result.path,
        sourceSha256: result.sourceSha256,
        byteLength: result.byteLength,
        lineCount: result.lineCount,
        tokenCount: result.tokenCount,
        facts,
        truncated: result.truncated,
        blockers: result.blockers,
    });
    const recordSha256 = hashDomain("zerotrust-semantic-scanner-record", {
        assignmentId: assignment.assignmentId,
        assignmentToken: assignment.assignmentToken,
        objectId: assignment.objectId,
        artifactId: assignment.artifactId,
        scannerResultSha256,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        contractKind: SEMANTIC_SCANNER_RECORD_KIND,
        scannerRecordId: `ztsr-${recordSha256}`,
        assignmentId: assignment.assignmentId,
        assignmentToken: assignment.assignmentToken,
        objectId: assignment.objectId,
        artifactId: assignment.artifactId,
        path: assignment.path,
        contentSha256: assignment.contentSha256,
        scannerId: assignment.scannerId,
        language: result.language,
        byteLength: result.byteLength,
        lineCount: result.lineCount,
        tokenCount: result.tokenCount,
        facts,
        factIds,
        factCount: factIds.length,
        truncated: result.truncated,
        blockerCodes: [...result.blockers].sort(compareStrings),
        hashes: {
            scannerResultSha256,
            recordSha256,
        },
    });
}

export function validateSemanticScannerCoverageRecord(
    value,
    { plan, snapshot, scannerResult },
    path = "semanticScannerCoverageRecord",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "scannerRecordId",
        "assignmentId",
        "assignmentToken",
        "objectId",
        "artifactId",
        "path",
        "contentSha256",
        "scannerId",
        "language",
        "byteLength",
        "lineCount",
        "tokenCount",
        "facts",
        "factIds",
        "factCount",
        "truncated",
        "blockerCodes",
        "hashes",
    ]);
    boundedString(value.scannerRecordId, `${path}.scannerRecordId`, {
        max: 72,
        pattern: SCANNER_RECORD_ID_RE,
    });
    const expected = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: value.assignmentId,
        assignmentToken: value.assignmentToken,
        scannerResult,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its immutable scanner coverage record");
    }
    return expected;
}

function findModelShard(plan, objectId, path) {
    boundedString(objectId, path, { max: 71, pattern: OBJECT_ID_RE });
    const shard = plan.modelReviewShards.find((entry) => entry.objectId === objectId);
    if (!shard) fail(path, "does not reference a model-review subject");
    return shard;
}

function artifactMetadataForView(artifact) {
    return cloneFrozen({
        artifactId: artifact.artifactId,
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
    });
}

function semanticEvidenceRecord({
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
    const evidenceSha256 = hashDomain(
        "zerotrust-red-team-evidence",
        descriptor,
    );
    return cloneFrozen({
        evidenceId: `ztre-${evidenceSha256}`,
        ...descriptor,
        hashes: {
            evidenceSha256,
        },
    });
}

function checkArtifactIds(checkName, artifacts) {
    const allowedKinds = {
        generatedAndDecodedContent: new Set([
            "decoded-text",
            "decoded-binary",
            "deobfuscated-view",
            "generated-source",
            "abstract-syntax",
            "intermediate-representation",
            "payload-index",
        ]),
        externalPayloads: new Set([
            "decoded-binary",
            "binary-metadata",
            "payload-index",
            "archive-manifest",
        ]),
        buildAndWorkflowHooks: new Set([
            "build-graph",
            "generated-source",
            "intermediate-representation",
        ]),
        dependencyResolution: new Set([
            "dependency-graph",
        ]),
    }[checkName];
    if (!allowedKinds) return [];
    return artifacts
        .filter((artifact) => allowedKinds.has(artifact.artifactKind))
        .map((artifact) => artifact.artifactId)
        .sort(compareStrings);
}

function checkBlockers(checkName, blockerCodes, unresolvedDynamicFactIds) {
    const globalBlockers = new Set([
        EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE,
        EVASIVE_BLOCKERS.SEMANTIC_TRUNCATED,
        EVASIVE_BLOCKERS.BOUNDS_EXCEEDED,
    ]);
    if (blockerCodes.some((code) => globalBlockers.has(code))) return true;
    if (checkName === "dynamicExecutionAndIndirection") {
        return unresolvedDynamicFactIds.length > 0
            || blockerCodes.includes(EVASIVE_BLOCKERS.SCAN_DYNAMIC_BEHAVIOR_UNRESOLVED);
    }
    if (checkName === "externalPayloads") {
        return unresolvedDynamicFactIds.length > 0
            || blockerCodes.includes(EVASIVE_BLOCKERS.SCAN_EXTERNAL_PAYLOAD_UNRESOLVED);
    }
    if (checkName === "generatedAndDecodedContent") {
        return blockerCodes.some((code) => code.startsWith("decode/"));
    }
    return false;
}

export function createSemanticView({
    plan,
    snapshot,
    objectId,
    scannerRecords = [],
} = {}, path = "semanticViewInput") {
    const canonicalPlan = validateSemanticCoveragePlan(plan, snapshot, `${path}.plan`);
    const current = validateAssuranceAnalysisSnapshot(snapshot, `${path}.snapshot`);
    const classification = canonicalPlan.classifications.find((entry) =>
        entry.objectId === objectId);
    if (!classification) fail(`${path}.objectId`, "is not classified by the plan");
    const object = current.objectInventory.find((entry) =>
        entry.objectId === objectId);
    if (!object) fail(`${path}.objectId`, "does not exist in the snapshot");
    const assignedScanners = canonicalPlan.scannerAssignments
        .filter((assignment) => assignment.objectId === objectId);
    const normalizedScannerRecords = dedupeExact(
        boundedArray(
            scannerRecords,
            `${path}.scannerRecords`,
            EVASIVE_LIMITS.semanticCoverageRecords,
        ).map((record, index) =>
            normalizeStoredScannerRecord(
                record,
                canonicalPlan,
                `${path}.scannerRecords[${index}]`,
            )),
        "scannerRecordId",
        "assignmentId",
        `${path}.scannerRecords`,
    );
    const recordByAssignment = new Map(
        normalizedScannerRecords.map((record) => [record.assignmentId, record]),
    );
    const missingScannerAssignmentIds = assignedScanners
        .filter((assignment) => !recordByAssignment.has(assignment.assignmentId))
        .map((assignment) => assignment.assignmentId)
        .sort(compareStrings);
    if (missingScannerAssignmentIds.length > 0) {
        fail(
            `${path}.scannerRecords`,
            `must record every assigned scanner subject before model review: ${missingScannerAssignmentIds.join(", ")}`,
        );
    }
    const relevantScannerRecords = assignedScanners
        .map((assignment) => recordByAssignment.get(assignment.assignmentId))
        .filter(Boolean)
        .sort((left, right) => compareStrings(left.assignmentId, right.assignmentId));
    const factById = new Map();
    for (const record of relevantScannerRecords) {
        for (const fact of record.facts) {
            const existing = factById.get(fact.id);
            if (existing && canonicalJson(existing) !== canonicalJson(fact)) {
                fail(`${path}.scannerRecords`, `contains conflicting fact ${fact.id}`);
            }
            factById.set(fact.id, fact);
        }
    }
    const facts = [...factById.values()].sort((left, right) =>
        compareStrings(left.id, right.id));
    if (facts.length > SEMANTIC_COVERAGE_LIMITS.factsPerView) {
        fail(`${path}.scannerRecords`, "semantic view fact bound exceeded");
    }
    const sourceArtifacts = current.derivedArtifacts
        .filter((artifact) => artifact.sourceObjectId === objectId)
        .sort((left, right) => compareStrings(left.artifactId, right.artifactId));
    const artifacts = sourceArtifacts
        .map(artifactMetadataForView)
        .sort((left, right) => compareStrings(left.artifactId, right.artifactId));
    if (canonicalJson(artifacts.map((artifact) => artifact.artifactId))
        !== canonicalJson(classification.artifactIds)) {
        fail(`${path}.snapshot.derivedArtifacts`, "do not match classified artifacts");
    }
    const scannerSubjects = relevantScannerRecords.map((record) => cloneFrozen({
        scannerRecordId: record.scannerRecordId,
        assignmentId: record.assignmentId,
        artifactId: record.artifactId,
        path: record.path,
        contentSha256: record.contentSha256,
        scannerId: record.scannerId,
        language: record.language,
        factIds: record.factIds,
        truncated: record.truncated,
        blockerCodes: record.blockerCodes,
        hashes: {
            scannerResultSha256: record.hashes.scannerResultSha256,
        },
    }));
    const evidence = [
        semanticEvidenceRecord({ evidenceKind: "object", object }),
        ...sourceArtifacts.map((artifact) =>
            semanticEvidenceRecord({
                evidenceKind: "artifact",
                object,
                artifact,
            })),
        ...facts.map((fact) =>
            semanticEvidenceRecord({
                evidenceKind: "fact",
                object,
                fact,
            })),
    ].sort((left, right) => compareStrings(left.evidenceId, right.evidenceId));
    const unresolvedDynamicFactIds = facts
        .filter((fact) => fact.kind === "unresolved-dynamic-target")
        .map((fact) => fact.id)
        .sort(compareStrings);
    const blockerCodes = [...new Set([
        ...relevantScannerRecords.flatMap((record) => record.blockerCodes),
        ...artifacts.flatMap((artifact) => artifact.blockerCodes),
        ...(relevantScannerRecords.some((record) => record.truncated)
            ? [EVASIVE_BLOCKERS.SEMANTIC_TRUNCATED]: []),
    ])].sort(compareStrings);
    const substantive = CONFIG_SOURCE_CLASSES.has(classification.semanticClass)
        ? facts.length > 0: facts.length > 0 || artifacts.length > 0;
    if (!substantive
        && classification.modelReviewRequired
        && !blockerCodes.includes(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE)) {
        blockerCodes.push(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE);
        blockerCodes.sort(compareStrings);
    }
    const checks = {};
    for (const checkName of SEMANTIC_CHECK_NAMES) {
        const factKinds = FACT_KINDS_BY_CHECK[checkName];
        const basisFactIds = facts
            .filter((fact) => factKinds.includes(fact.kind))
            .map((fact) => fact.id)
            .sort(compareStrings);
        const basisArtifactIds = checkArtifactIds(checkName, artifacts);
        checks[checkName] = cloneFrozen({
            applicable: true,
            basisFactIds,
            basisArtifactIds,
            unresolved: checkBlockers(
                checkName,
                blockerCodes,
                unresolvedDynamicFactIds,
            ),
        });
    }
    const factsSha256 = hashDomain("zerotrust-semantic-view-facts", facts);
    const artifactsSha256 = hashDomain(
        "zerotrust-semantic-view-artifacts",
        artifacts,
    );
    const evidenceSha256 = hashDomain(
        "zerotrust-semantic-view-evidence",
        evidence,
    );
    const checksSha256 = hashDomain("zerotrust-semantic-view-checks", checks);
    const complete = substantive
        && blockerCodes.length === 0
        && unresolvedDynamicFactIds.length === 0
        && Object.values(checks).every((check) => !check.unresolved);
    const semanticViewSha256 = hashDomain("zerotrust-semantic-review-view", {
        planId: canonicalPlan.planId,
        snapshotId: canonicalPlan.snapshotId,
        objectId: classification.objectId,
        objectIdentitySha256: classification.hashes.objectIdentitySha256,
        artifactIds: classification.artifactIds,
        semanticClass: classification.semanticClass,
        scannerRecordIds: scannerSubjects.map((record) => record.scannerRecordId),
        factsSha256,
        artifactsSha256,
        evidenceSha256,
        checksSha256,
        unresolvedDynamicFactIds,
        blockerCodes,
        substantive,
        complete,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        contractKind: SEMANTIC_VIEW_KIND,
        semanticViewId: `ztsv-${semanticViewSha256}`,
        auditId: canonicalPlan.auditId,
        sourceNamespace: canonicalPlan.sourceNamespace,
        planId: canonicalPlan.planId,
        snapshotId: canonicalPlan.snapshotId,
        objectId: classification.objectId,
        path: classification.path,
        semanticClass: classification.semanticClass,
        artifactIds: classification.artifactIds,
        substantive,
        complete,
        scannerSubjects,
        facts,
        derivedArtifacts: artifacts,
        evidence,
        checks,
        unresolvedDynamicFactIds,
        blockerCodes,
        hashes: {
            objectIdentitySha256: classification.hashes.objectIdentitySha256,
            factsSha256,
            artifactsSha256,
            evidenceSha256,
            checksSha256,
            semanticViewSha256,
        },
    });
}

export function validateSemanticView(
    value,
    { plan, snapshot, scannerRecords },
    path = "semanticView",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "semanticViewId",
        "auditId",
        "sourceNamespace",
        "planId",
        "snapshotId",
        "objectId",
        "path",
        "semanticClass",
        "artifactIds",
        "substantive",
        "complete",
        "scannerSubjects",
        "facts",
        "derivedArtifacts",
        "evidence",
        "checks",
        "unresolvedDynamicFactIds",
        "blockerCodes",
        "hashes",
    ]);
    boundedString(value.semanticViewId, `${path}.semanticViewId`, {
        max: 72,
        pattern: SEMANTIC_VIEW_ID_RE,
    });
    const expected = createSemanticView({
        plan,
        snapshot,
        objectId: value.objectId,
        scannerRecords,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match the deterministic scanner-derived semantic view");
    }
    return expected;
}

export function createSemanticReviewAssignment({
    plan,
    snapshot,
    scannerRecords = [],
    objectId,
    reviewerSlot,
    reviewerId,
    reviewerVersion,
    assignmentNonceSha256,
} = {}, path = "semanticReviewAssignmentInput") {
    const canonicalPlan = validateSemanticCoveragePlan(plan, snapshot, `${path}.plan`);
    const shard = findModelShard(canonicalPlan, objectId, `${path}.objectId`);
    const semanticView = createSemanticView({
        plan: canonicalPlan,
        snapshot,
        objectId,
        scannerRecords,
    }, `${path}.semanticView`);
    const slot = boundedInteger(
        reviewerSlot,
        `${path}.reviewerSlot`,
        1,
        shard.requiredReviewerCount,
    );
    const reviewer = boundedString(reviewerId, `${path}.reviewerId`, {
        max: 128,
        pattern: IDENTIFIER_RE,
    });
    const version = boundedString(reviewerVersion, `${path}.reviewerVersion`, {
        max: 64,
        pattern: VERSION_RE,
    });
    const nonceSha256 = boundedString(
        assignmentNonceSha256,
        `${path}.assignmentNonceSha256`,
        { max: 64, pattern: SHA256_RE },
    );
    const normalizedView = shard.normalizedViewId === null
        ? null: canonicalPlan.normalizedViews.find((view) =>
            view.normalizedViewId === shard.normalizedViewId);
    const promptAssignment = shard.promptAffected
        ? createPromptReviewAssignment({
            normalizedView,
            reviewerId: reviewer,
            reviewerVersion: version,
            assignmentNonceSha256: nonceSha256,
        }): null;
    const assignmentSha256 = hashDomain("zerotrust-semantic-model-assignment", {
        issuerId: SEMANTIC_ASSIGNMENT_ISSUER_ID,
        reviewMode: SEMANTIC_REVIEW_MODE,
        planId: canonicalPlan.planId,
        snapshotId: canonicalPlan.snapshotId,
        objectId: shard.objectId,
        artifactIds: shard.artifactIds,
        semanticClass: shard.semanticClass,
        modelShard: shard.modelShard,
        reviewerSlot: slot,
        reviewerId: reviewer,
        reviewerVersion: version,
        assignmentNonceSha256: nonceSha256,
        semanticViewId: semanticView.semanticViewId,
        semanticViewSha256: semanticView.hashes.semanticViewSha256,
        promptAssignmentId: promptAssignment?.assignmentId || null,
    });
    const tokenSha256 = hashDomain("zerotrust-semantic-model-token", {
        assignmentSha256,
        assignmentNonceSha256: nonceSha256,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        contractKind: SEMANTIC_REVIEW_ASSIGNMENT_KIND,
        assignmentId: `ztsma-${assignmentSha256}`,
        assignmentToken: `ztsmt-${tokenSha256}`,
        issuerId: SEMANTIC_ASSIGNMENT_ISSUER_ID,
        reviewMode: SEMANTIC_REVIEW_MODE,
        auditId: canonicalPlan.auditId,
        sourceNamespace: canonicalPlan.sourceNamespace,
        planId: canonicalPlan.planId,
        snapshotId: canonicalPlan.snapshotId,
        objectId: shard.objectId,
        path: shard.path,
        artifactIds: shard.artifactIds,
        semanticClass: shard.semanticClass,
        highRisk: shard.highRisk,
        requiredReviewerCount: shard.requiredReviewerCount,
        modelShard: shard.modelShard,
        reviewerSlot: slot,
        reviewerId: reviewer,
        reviewerVersion: version,
        semanticView,
        promptAssignment,
        hashes: {
            objectIdentitySha256: canonicalPlan.classifications.find((entry) =>
                entry.objectId === shard.objectId).hashes.objectIdentitySha256,
            semanticViewSha256: semanticView.hashes.semanticViewSha256,
            assignmentNonceSha256: nonceSha256,
            assignmentSha256,
            tokenSha256,
        },
    });
}

export function validateSemanticReviewAssignment(
    value,
    { plan, snapshot, scannerRecords = [] },
    path = "semanticReviewAssignment",
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
        "objectId",
        "path",
        "artifactIds",
        "semanticClass",
        "highRisk",
        "requiredReviewerCount",
        "modelShard",
        "reviewerSlot",
        "reviewerId",
        "reviewerVersion",
        "semanticView",
        "promptAssignment",
        "hashes",
    ]);
    boundedString(value.assignmentId, `${path}.assignmentId`, {
        max: 73,
        pattern: REVIEW_ASSIGNMENT_ID_RE,
    });
    boundedString(value.assignmentToken, `${path}.assignmentToken`, {
        max: 73,
        pattern: REVIEW_ASSIGNMENT_TOKEN_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "objectIdentitySha256",
        "semanticViewSha256",
        "assignmentNonceSha256",
        "assignmentSha256",
        "tokenSha256",
    ]);
    const expected = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords,
        objectId: value.objectId,
        reviewerSlot: value.reviewerSlot,
        reviewerId: value.reviewerId,
        reviewerVersion: value.reviewerVersion,
        assignmentNonceSha256: value.hashes.assignmentNonceSha256,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its wrapper-issued semantic assignment");
    }
    return expected;
}

function normalizeChecks(value, path) {
    objectShape(value, path, SEMANTIC_CHECK_NAMES);
    const checks = {};
    for (const name of SEMANTIC_CHECK_NAMES) {
        checks[name] = enumValue(value[name], `${path}.${name}`, SEMANTIC_CHECK_RESULTS);
    }
    return checks;
}

function completedPromptReview(assignment, promptReviewRecord, path) {
    if (assignment.promptAssignment === null) {
        if (promptReviewRecord !== null && promptReviewRecord !== undefined) {
            fail(path, "is allowed only for a prompt-affected assignment");
        }
        return null;
    }
    if (!promptReviewRecord) {
        fail(path, "is required for a prompt-affected assignment");
    }
    const record = validatePromptReviewRecord(
        promptReviewRecord,
        assignment.promptAssignment,
        path,
    );
    if (record.decision === "incomplete") {
        fail(path, "must be a completed normalized-view review");
    }
    return record;
}

function normalizeSemanticCandidate(candidate, assignment, path) {
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
            max: 1,
            pattern: OBJECT_ID_RE,
        }),
        artifactIds: sortedUnique(candidate.artifactIds, `${path}.artifactIds`, {
            max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
            pattern: ARTIFACT_ID_RE,
        }),
        factIds: sortedUnique(candidate.factIds, `${path}.factIds`, {
            max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
            pattern: SHA256_RE,
        }),
        evidenceIds: sortedUnique(candidate.evidenceIds, `${path}.evidenceIds`, {
            max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
            pattern: SEMANTIC_EVIDENCE_ID_RE,
        }),
    };
    if (canonicalJson(identities.objectIds)
        !== canonicalJson([assignment.objectId])) {
        fail(`${path}.objectIds`, "must exactly bind the assigned object");
    }
    const assignedArtifactIds = assignment.semanticView.derivedArtifacts
        .map((artifact) => artifact.artifactId);
    const assignedFactIds = assignment.semanticView.facts.map((fact) => fact.id);
    const evidenceById = new Map(
        assignment.semanticView.evidence.map((evidence) =>
            [evidence.evidenceId, evidence]),
    );
    if (identities.artifactIds.some((id) => !assignedArtifactIds.includes(id))) {
        fail(`${path}.artifactIds`, "references an artifact outside the assignment");
    }
    if (identities.factIds.some((id) => !assignedFactIds.includes(id))) {
        fail(`${path}.factIds`, "references a fact outside the assignment");
    }
    for (const evidenceId of identities.evidenceIds) {
        const evidence = evidenceById.get(evidenceId);
        if (!evidence
            || evidence.objectId !== assignment.objectId
            || (evidence.artifactId !== null
                && !identities.artifactIds.includes(evidence.artifactId))
            || (evidence.factId !== null
                && !identities.factIds.includes(evidence.factId))) {
            fail(`${path}.evidenceIds`, "is not bound to candidate identities");
        }
    }
    for (const artifactId of identities.artifactIds) {
        if (![...evidenceById.values()].some((evidence) =>
            identities.evidenceIds.includes(evidence.evidenceId)
            && evidence.artifactId === artifactId)) {
            fail(`${path}.evidenceIds`, `does not evidence artifact ${artifactId}`);
        }
    }
    for (const factId of identities.factIds) {
        if (![...evidenceById.values()].some((evidence) =>
            identities.evidenceIds.includes(evidence.evidenceId)
            && evidence.factId === factId)) {
            fail(`${path}.evidenceIds`, `does not evidence fact ${factId}`);
        }
    }
    return createEvasiveSemanticCandidateRecord({
        auditId: assignment.auditId,
        sourceNamespace: assignment.sourceNamespace,
        producerAssignmentId: assignment.assignmentId,
        semanticViewId: assignment.semanticView.semanticViewId,
        behavior,
        severity: enumValue(
            candidate.severity,
            `${path}.severity`,
            EVASIVE_SEMANTIC_CANDIDATE_SEVERITIES,
        ),
        confidence: enumValue(
            candidate.confidence,
            `${path}.confidence`,
            EVASIVE_SEMANTIC_CANDIDATE_CONFIDENCE_LEVELS,
        ),
        maliciousProjectFit: enumValue(
            candidate.maliciousProjectFit,
            `${path}.maliciousProjectFit`,
            EVASIVE_SEMANTIC_CANDIDATE_FIT_LEVELS,
        ),
        benignHypothesisCode: enumValue(
            candidate.benignHypothesisCode,
            `${path}.benignHypothesisCode`,
            EVASIVE_SEMANTIC_BENIGN_HYPOTHESIS_CODES,
        ),
        ...identities,
    }, path);
}

export function createSemanticCandidate(
    { assignment, candidate } = {},
    path = "semanticCandidateInput",
) {
    if (!assignment
        || assignment.contractKind !== SEMANTIC_REVIEW_ASSIGNMENT_KIND) {
        fail(`${path}.assignment`, "must be a semantic review assignment");
    }
    return normalizeSemanticCandidate(candidate, assignment, `${path}.candidate`);
}

export function validateSemanticCandidate(
    value,
    assignment,
    path = "semanticCandidate",
) {
    const stored = validateEvasiveSemanticCandidateRecord(value, path);
    const {
        schemaVersion: _schemaVersion,
        candidateId: _candidateId,
        auditId: _auditId,
        sourceNamespace: _sourceNamespace,
        producerAssignmentId: _producerAssignmentId,
        semanticViewId: _semanticViewId,
        hashes: _hashes,
        ...candidate
    } = stored;
    const expected = normalizeSemanticCandidate(candidate, assignment, path);
    if (canonicalJson(stored) !== canonicalJson(expected)) {
        fail(path, "does not match its assignment-bound semantic candidate");
    }
    return expected;
}

export function createSemanticReviewRecord({
    assignment,
    plan,
    snapshot,
    scannerRecords = [],
    assignmentToken,
    reviewerId,
    objectId,
    artifactIds,
    semanticViewId,
    semanticViewSha256,
    reviewedFactIds,
    reviewedArtifactIds,
    decision,
    checks,
    negativeEvidenceCodes,
    candidates = [],
    blockerCodes,
    promptReviewRecord = null,
} = {}, path = "semanticReviewRecordInput") {
    const canonicalAssignment = validateSemanticReviewAssignment(
        assignment,
        { plan, snapshot, scannerRecords },
        `${path}.assignment`,
    );
    if (assignmentToken !== canonicalAssignment.assignmentToken) {
        fail(`${path}.assignmentToken`, "does not match the wrapper-issued token");
    }
    if (reviewerId !== canonicalAssignment.reviewerId) {
        fail(`${path}.reviewerId`, "does not match the assigned reviewer");
    }
    if (objectId !== canonicalAssignment.objectId) {
        fail(`${path}.objectId`, "does not match the assigned object");
    }
    const normalizedArtifacts = sortedUnique(
        artifactIds,
        `${path}.artifactIds`,
        { max: EVASIVE_LIMITS.artifactReferencesPerCoverage, pattern: ARTIFACT_ID_RE },
    );
    if (canonicalJson(normalizedArtifacts)
        !== canonicalJson(canonicalAssignment.artifactIds)) {
        fail(`${path}.artifactIds`, "must exactly match assigned artifact identities");
    }
    if (semanticViewId !== canonicalAssignment.semanticView.semanticViewId) {
        fail(`${path}.semanticViewId`, "does not match the assigned semantic view");
    }
    if (semanticViewSha256
        !== canonicalAssignment.semanticView.hashes.semanticViewSha256) {
        fail(`${path}.semanticViewSha256`, "does not match the assigned semantic view");
    }
    const normalizedReviewedFactIds = sortedUnique(
        reviewedFactIds,
        `${path}.reviewedFactIds`,
        { max: SEMANTIC_COVERAGE_LIMITS.factsPerView, pattern: SHA256_RE },
    );
    const expectedFactIds = canonicalAssignment.semanticView.facts
        .map((fact) => fact.id).sort(compareStrings);
    if (normalizedReviewedFactIds.some((factId) => !expectedFactIds.includes(factId))) {
        fail(`${path}.reviewedFactIds`, "references facts outside the semantic view");
    }
    const normalizedReviewedArtifactIds = sortedUnique(
        reviewedArtifactIds,
        `${path}.reviewedArtifactIds`,
        { max: EVASIVE_LIMITS.artifactReferencesPerCoverage, pattern: ARTIFACT_ID_RE },
    );
    const expectedViewArtifactIds = canonicalAssignment.semanticView.derivedArtifacts
        .map((artifact) => artifact.artifactId).sort(compareStrings);
    if (normalizedReviewedArtifactIds.some((artifactId) =>
        !expectedViewArtifactIds.includes(artifactId))) {
        fail(
            `${path}.reviewedArtifactIds`,
            "references artifacts outside the semantic view",
        );
    }
    const normalizedDecision = enumValue(
        decision,
        `${path}.decision`,
        SEMANTIC_REVIEW_DECISIONS,
    );
    const normalizedChecks = normalizeChecks(checks, `${path}.checks`);
    const negatives = sortedUnique(
        negativeEvidenceCodes,
        `${path}.negativeEvidenceCodes`,
        {
            max: SEMANTIC_NEGATIVE_EVIDENCE_CODES.length,
            allowed: SEMANTIC_NEGATIVE_EVIDENCE_CODES,
        },
    );
    const normalizedCandidates = boundedArray(
        candidates,
        `${path}.candidates`,
        SEMANTIC_COVERAGE_LIMITS.candidatesPerReview,
    ).map((candidate, index) =>
        normalizeSemanticCandidate(
            candidate,
            canonicalAssignment,
            `${path}.candidates[${index}]`,
        )).sort((left, right) => compareStrings(left.candidateId, right.candidateId));
    if (new Set(normalizedCandidates.map((candidate) => candidate.candidateId)).size
        !== normalizedCandidates.length) {
        fail(`${path}.candidates`, "must not contain duplicate candidates");
    }
    const blockers = sortedUnique(blockerCodes, `${path}.blockerCodes`, {
        max: 2,
        allowed: [
            EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE,
            EVASIVE_BLOCKERS.SEMANTIC_TRUNCATED,
        ],
    });
    if (normalizedDecision === "incomplete") {
        if (!blockers.includes(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE)) {
            fail(`${path}.blockerCodes`, "must include semantic/incomplete");
        }
        if (normalizedCandidates.length > 0) {
            fail(`${path}.candidates`, "must be empty for incomplete reviews");
        }
    } else {
        if (blockers.length > 0
            || Object.values(normalizedChecks).includes("unresolved")) {
            fail(path, "completed reviews must resolve every check without blockers");
        }
        if (canonicalJson(normalizedReviewedFactIds) !== canonicalJson(expectedFactIds)
            || canonicalJson(normalizedReviewedArtifactIds)
                !== canonicalJson(expectedViewArtifactIds)) {
            fail(path, "completed review must cover the complete assigned semantic view");
        }
        if (!canonicalAssignment.semanticView.complete) {
            fail(path, "incomplete semantic view cannot support a completed review");
        }
        if (normalizedDecision === "no-findings") {
            if (normalizedCandidates.length > 0) {
                fail(`${path}.candidates`, "must be empty for no-findings");
            }
            const expectedNegatives = SEMANTIC_CHECK_NAMES
                .map((name) => NEGATIVE_CODE_BY_CHECK[name])
                .sort(compareStrings);
            if (canonicalJson(negatives) !== canonicalJson(expectedNegatives)) {
                fail(
                    `${path}.negativeEvidenceCodes`,
                    "must contain the exact bounded negative-evidence set",
                );
            }
        } else if (normalizedCandidates.length === 0) {
            fail(`${path}.candidates`, "must contain a structured candidate");
        }
    }
    const promptRecord = normalizedDecision === "incomplete"
        ? (promptReviewRecord
            ? validatePromptReviewRecord(
                promptReviewRecord,
                canonicalAssignment.promptAssignment,
                `${path}.promptReviewRecord`,
            ): null): completedPromptReview(
            canonicalAssignment,
            promptReviewRecord,
            `${path}.promptReviewRecord`,
        );
    const reviewSha256 = hashDomain("zerotrust-semantic-model-review", {
        assignmentId: canonicalAssignment.assignmentId,
        assignmentToken: canonicalAssignment.assignmentToken,
        reviewerId: canonicalAssignment.reviewerId,
        reviewerSlot: canonicalAssignment.reviewerSlot,
        objectId: canonicalAssignment.objectId,
        artifactIds: normalizedArtifacts,
        semanticViewId: canonicalAssignment.semanticView.semanticViewId,
        semanticViewSha256:
            canonicalAssignment.semanticView.hashes.semanticViewSha256,
        reviewedFactIds: normalizedReviewedFactIds,
        reviewedArtifactIds: normalizedReviewedArtifactIds,
        decision: normalizedDecision,
        checks: normalizedChecks,
        negativeEvidenceCodes: negatives,
        candidateIds: normalizedCandidates.map((candidate) =>
            candidate.candidateId),
        blockerCodes: blockers,
        promptReviewId: promptRecord?.reviewId || null,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        contractKind: SEMANTIC_REVIEW_RECORD_KIND,
        reviewId: `ztsmr-${reviewSha256}`,
        assignmentId: canonicalAssignment.assignmentId,
        assignmentToken: canonicalAssignment.assignmentToken,
        reviewMode: SEMANTIC_REVIEW_MODE,
        reviewerId: canonicalAssignment.reviewerId,
        reviewerSlot: canonicalAssignment.reviewerSlot,
        objectId: canonicalAssignment.objectId,
        path: canonicalAssignment.path,
        artifactIds: normalizedArtifacts,
        semanticViewId: canonicalAssignment.semanticView.semanticViewId,
        semanticViewSha256:
            canonicalAssignment.semanticView.hashes.semanticViewSha256,
        reviewedFactIds: normalizedReviewedFactIds,
        reviewedArtifactIds: normalizedReviewedArtifactIds,
        decision: normalizedDecision,
        checks: normalizedChecks,
        negativeEvidenceCodes: negatives,
        candidates: normalizedCandidates,
        blockerCodes: blockers,
        promptReviewRecord: promptRecord,
        hashes: {
            objectIdentitySha256: canonicalAssignment.hashes.objectIdentitySha256,
            semanticViewSha256:
                canonicalAssignment.semanticView.hashes.semanticViewSha256,
            assignmentSha256: canonicalAssignment.hashes.assignmentSha256,
            reviewSha256,
        },
    });
}

export function validateSemanticReviewRecord(
    value,
    { assignment, plan, snapshot, scannerRecords = [] },
    path = "semanticReviewRecord",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "reviewId",
        "assignmentId",
        "assignmentToken",
        "reviewMode",
        "reviewerId",
        "reviewerSlot",
        "objectId",
        "path",
        "artifactIds",
        "semanticViewId",
        "semanticViewSha256",
        "reviewedFactIds",
        "reviewedArtifactIds",
        "decision",
        "checks",
        "negativeEvidenceCodes",
        "candidates",
        "blockerCodes",
        "promptReviewRecord",
        "hashes",
    ]);
    boundedString(value.reviewId, `${path}.reviewId`, {
        max: 73,
        pattern: REVIEW_RECORD_ID_RE,
    });
    const expected = createSemanticReviewRecord({
        assignment,
        plan,
        snapshot,
        scannerRecords,
        assignmentToken: value.assignmentToken,
        reviewerId: value.reviewerId,
        objectId: value.objectId,
        artifactIds: value.artifactIds,
        semanticViewId: value.semanticViewId,
        semanticViewSha256: value.semanticViewSha256,
        reviewedFactIds: value.reviewedFactIds,
        reviewedArtifactIds: value.reviewedArtifactIds,
        decision: value.decision,
        checks: value.checks,
        negativeEvidenceCodes: value.negativeEvidenceCodes,
        candidates: value.candidates.map((candidate, index) => {
            const stored = validateSemanticCandidate(
                candidate,
                assignment,
                `${path}.candidates[${index}]`,
            );
            const {
                schemaVersion: _schemaVersion,
                candidateId: _candidateId,
                auditId: _auditId,
                sourceNamespace: _sourceNamespace,
                producerAssignmentId: _producerAssignmentId,
                semanticViewId: _semanticViewId,
                hashes: _hashes,
                ...input
            } = stored;
            return input;
        }),
        blockerCodes: value.blockerCodes,
        promptReviewRecord: value.promptReviewRecord,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its immutable semantic review record");
    }
    return expected;
}

function normalizeStoredScannerRecord(value, plan, path) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "scannerRecordId",
        "assignmentId",
        "assignmentToken",
        "objectId",
        "artifactId",
        "path",
        "contentSha256",
        "scannerId",
        "language",
        "byteLength",
        "lineCount",
        "tokenCount",
        "facts",
        "factIds",
        "factCount",
        "truncated",
        "blockerCodes",
        "hashes",
    ]);
    const assignment = findScannerAssignment(plan, value.assignmentId, `${path}.assignmentId`);
    if (value.schemaVersion !== 6
        || value.contractKind !== SEMANTIC_SCANNER_RECORD_KIND
        || value.assignmentToken !== assignment.assignmentToken
        || value.objectId !== assignment.objectId
        || value.artifactId !== assignment.artifactId
        || value.path !== assignment.path
        || value.contentSha256 !== assignment.contentSha256
        || value.scannerId !== assignment.scannerId
        || typeof value.language !== "string"
        || typeof value.truncated !== "boolean"
        || !Number.isSafeInteger(value.byteLength)
        || value.byteLength < 0
        || !Number.isSafeInteger(value.lineCount)
        || value.lineCount < 0
        || !Number.isSafeInteger(value.tokenCount)
        || value.tokenCount < 0) {
        fail(path, "does not match its scanner assignment");
    }
    boundedString(value.scannerRecordId, `${path}.scannerRecordId`, {
        max: 72,
        pattern: SCANNER_RECORD_ID_RE,
    });
    const facts = boundedArray(value.facts, `${path}.facts`, SCANNER_LIMITS.factsPerFile)
        .map((fact, index) =>
            validateSemanticFact(fact, `${path}.facts[${index}]`))
        .sort((left, right) => compareStrings(left.id, right.id));
    if (facts.some((fact) =>
        fact.scannerId !== assignment.scannerId
        || fact.path !== assignment.path)) {
        fail(`${path}.facts`, "do not match the assigned scanner subject");
    }
    const factIds = sortedUnique(value.factIds, `${path}.factIds`, {
        max: SCANNER_LIMITS.factsPerFile,
        pattern: SHA256_RE,
    });
    if (canonicalJson(factIds) !== canonicalJson(facts.map((fact) => fact.id))) {
        fail(`${path}.factIds`, "must exactly identify the normalized facts");
    }
    if (value.factCount !== factIds.length) fail(`${path}.factCount`, "is invalid");
    sortedUnique(value.blockerCodes, `${path}.blockerCodes`, {
        max: 32,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "scannerResultSha256",
        "recordSha256",
    ]);
    for (const key of ["scannerResultSha256", "recordSha256"]) {
        boundedString(value.hashes[key], `${path}.hashes.${key}`, {
            max: 64,
            pattern: SHA256_RE,
        });
    }
    const scannerResultSha256 = hashDomain("zerotrust-semantic-scanner-result", {
        scannerId: value.scannerId,
        language: value.language,
        path: value.path,
        sourceSha256: value.contentSha256,
        byteLength: value.byteLength,
        lineCount: value.lineCount,
        tokenCount: value.tokenCount,
        facts,
        truncated: value.truncated,
        blockers: [...value.blockerCodes].sort(compareStrings),
    });
    const recordSha256 = hashDomain("zerotrust-semantic-scanner-record", {
        assignmentId: assignment.assignmentId,
        assignmentToken: assignment.assignmentToken,
        objectId: assignment.objectId,
        artifactId: assignment.artifactId,
        scannerResultSha256,
    });
    if (value.hashes.scannerResultSha256 !== scannerResultSha256
        || value.hashes.recordSha256 !== recordSha256
        || value.scannerRecordId !== `ztsr-${recordSha256}`) {
        fail(path, "does not match its immutable scanner coverage hash");
    }
    return cloneFrozen(value);
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
        const conflictKey = record[conflictField];
        const conflict = byConflict.get(conflictKey);
        if (conflict && conflict[idField] !== record[idField]) {
            fail(path, `contains conflicting records for ${conflictField}`);
        }
        byId.set(record[idField], record);
        byConflict.set(conflictKey, record);
    }
    return [...byId.values()];
}

export function evaluateSemanticCoverage({
    snapshot,
    plan,
    scannerRecords = [],
    reviewAssignments = [],
    reviewRecords = [],
} = {}, path = "semanticCoverageEvaluationInput") {
    const current = validateAssuranceAnalysisSnapshot(snapshot, `${path}.snapshot`);
    const canonicalPlan = validateSemanticCoveragePlan(plan, current, `${path}.plan`);
    const scanners = dedupeExact(
        boundedArray(
            scannerRecords,
            `${path}.scannerRecords`,
            EVASIVE_LIMITS.semanticCoverageRecords,
        ).map((record, index) =>
            normalizeStoredScannerRecord(
                record,
                canonicalPlan,
                `${path}.scannerRecords[${index}]`,
            )),
        "scannerRecordId",
        "assignmentId",
        `${path}.scannerRecords`,
    );
    const assignments = dedupeExact(
        boundedArray(
            reviewAssignments,
            `${path}.reviewAssignments`,
            EVASIVE_LIMITS.semanticCoverageRecords * SEMANTIC_COVERAGE_LIMITS.reviewersPerObject,
        ).map((assignment, index) =>
            validateSemanticReviewAssignment(
                assignment,
                {
                    plan: canonicalPlan,
                    snapshot: current,
                    scannerRecords: scanners,
                },
                `${path}.reviewAssignments[${index}]`,
            )),
        "assignmentId",
        "assignmentId",
        `${path}.reviewAssignments`,
    );
    const assignmentById = new Map(
        assignments.map((assignment) => [assignment.assignmentId, assignment]),
    );
    const reviews = dedupeExact(
        boundedArray(
            reviewRecords,
            `${path}.reviewRecords`,
            EVASIVE_LIMITS.semanticCoverageRecords * SEMANTIC_COVERAGE_LIMITS.reviewersPerObject,
        ).map((review, index) => {
            const assignment = assignmentById.get(review?.assignmentId);
            if (!assignment) {
                fail(
                    `${path}.reviewRecords[${index}].assignmentId`,
                    "does not reference a supplied wrapper assignment",
                );
            }
            return validateSemanticReviewRecord(
                review,
                {
                    assignment,
                    plan: canonicalPlan,
                    snapshot: current,
                    scannerRecords: scanners,
                },
                `${path}.reviewRecords[${index}]`,
            );
        }),
        "reviewId",
        "assignmentId",
        `${path}.reviewRecords`,
    );

    const assignmentsByObject = new Map();
    for (const assignment of assignments) {
        if (!assignmentsByObject.has(assignment.objectId)) {
            assignmentsByObject.set(assignment.objectId, []);
        }
        assignmentsByObject.get(assignment.objectId).push(assignment);
    }
    for (const [objectId, entries] of assignmentsByObject.entries()) {
        const reviewers = entries.map((entry) => entry.reviewerId);
        const slots = entries.map((entry) => entry.reviewerSlot);
        if (new Set(reviewers).size !== reviewers.length) {
            fail(`${path}.reviewAssignments`, `reviewers for ${objectId} must be independent`);
        }
        if (new Set(slots).size !== slots.length) {
            fail(`${path}.reviewAssignments`, `reviewer slots for ${objectId} must be unique`);
        }
    }

    const scannerByAssignment = new Map(
        scanners.map((record) => [record.assignmentId, record]),
    );
    const reviewByAssignment = new Map(
        reviews.map((record) => [record.assignmentId, record]),
    );
    const candidateById = new Map();
    for (const candidate of reviews.flatMap((review) => review.candidates)) {
        const existing = candidateById.get(candidate.candidateId);
        if (existing && canonicalJson(existing) !== canonicalJson(candidate)) {
            fail(`${path}.reviewRecords`, "contain conflicting semantic candidates");
        }
        candidateById.set(candidate.candidateId, candidate);
    }
    const candidateLedger = [...candidateById.values()].sort((left, right) =>
        compareStrings(left.candidateId, right.candidateId));
    if (candidateLedger.length > EVASIVE_LIMITS.semanticCandidateRecords) {
        fail(`${path}.reviewRecords`, "semantic candidate ledger bound exceeded");
    }
    const coverageRecords = [];
    const blockerDetails = [];
    let anyTruncation = false;
    for (const classification of canonicalPlan.classifications) {
        const objectScannerAssignments = canonicalPlan.scannerAssignments
            .filter((assignment) => assignment.objectId === classification.objectId);
        const missingScannerAssignmentIds = [];
        const rootScannerUnassignable = classification.scannerRequired
            && !objectScannerAssignments.some((assignment) =>
                assignment.artifactId === null);
        if (rootScannerUnassignable) {
            missingScannerAssignmentIds.push(
                `unassigned-root:${classification.objectId}`,
            );
            anyTruncation = true;
        }
        for (const scannerAssignment of objectScannerAssignments) {
            const record = scannerByAssignment.get(scannerAssignment.assignmentId);
            if (!record || record.truncated || record.blockerCodes.length > 0) {
                missingScannerAssignmentIds.push(scannerAssignment.assignmentId);
                if (record?.truncated) anyTruncation = true;
            }
        }
        const objectAssignments = assignmentsByObject.get(classification.objectId) || [];
        const completedReviews = objectAssignments
            .map((assignment) => ({
                assignment,
                review: reviewByAssignment.get(assignment.assignmentId),
            }))
            .filter(({ review }) => review && review.decision !== "incomplete");
        const completedReviewerIds = [...new Set(
            completedReviews.map(({ assignment }) => assignment.reviewerId),
        )].sort(compareStrings);
        const promptReviewComplete = !classification.promptAffected
            || completedReviews.some(({ review }) => review.promptReviewRecord !== null);
        const missingPromptAssessment = classification.promptAssessmentRequired
            && !canonicalPlan.normalizedViews.some((view) =>
                view.objectId === classification.objectId);
        const blockedUnsupported = classification.semanticClass === "unsupported"
            && current.objectInventory.find((object) =>
                object.objectId === classification.objectId)?.status !== "inventoried";
        const resolved = !missingPromptAssessment
            && missingScannerAssignmentIds.length === 0
            && completedReviewerIds.length >= classification.requiredReviewerCount
            && promptReviewComplete
            && !blockedUnsupported;
        const recordBlockers = [];
        if (!resolved && (classification.required || blockedUnsupported
            || missingPromptAssessment)) {
            recordBlockers.push(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE);
        }
        if (missingScannerAssignmentIds.some((assignmentId) =>
            assignmentId.startsWith("unassigned-root:")
            || scannerByAssignment.get(assignmentId)?.truncated)) {
            recordBlockers.push(EVASIVE_BLOCKERS.SEMANTIC_TRUNCATED);
        }
        const status = resolved
            ? (classification.required ? "comprehensive": "bounded"): (classification.required || blockedUnsupported || missingPromptAssessment
                ? "partial": "bounded");
        const relevantScannerIds = objectScannerAssignments
            .map((assignment) => scannerByAssignment.get(assignment.assignmentId)?.scannerRecordId)
            .filter(Boolean)
            .sort(compareStrings);
        const relevantAssignmentIds = objectAssignments
            .map((assignment) => assignment.assignmentId)
            .sort(compareStrings);
        const relevantReviewIds = completedReviews
            .map(({ review }) => review.reviewId)
            .sort(compareStrings);
        const basisSha256 = hashDomain("zerotrust-semantic-object-coverage", {
            planId: canonicalPlan.planId,
            classificationId: classification.classificationId,
            scannerRecordIds: relevantScannerIds,
            assignmentIds: relevantAssignmentIds,
            reviewIds: relevantReviewIds,
            completedReviewerIds,
            promptReviewComplete,
            missingScannerAssignmentIds,
            missingPromptAssessment,
            blockedUnsupported,
            status,
            blockerCodes: recordBlockers,
        });
        coverageRecords.push(createEvasiveSemanticReviewCoverageRecord({
            auditId: current.auditId,
            sourceNamespace: current.sourceNamespace,
            path: classification.path,
            objectId: classification.objectId,
            artifactIds: classification.artifactIds,
            producer: "semantic-coverage",
            producerVersion: "1.0.0",
            status,
            evasionClasses: classification.evasionClasses,
            blockerCodes: recordBlockers,
            basisSha256,
            objectIdentitySha256: classification.hashes.objectIdentitySha256,
        }));
        if (!resolved && (classification.required || blockedUnsupported
            || missingPromptAssessment)) {
            blockerDetails.push(cloneFrozen({
                objectId: classification.objectId,
                semanticClass: classification.semanticClass,
                missingScannerAssignmentIds,
                completedReviewerIds,
                requiredReviewerCount: classification.requiredReviewerCount,
                missingPromptAssessment,
                promptReviewComplete,
                blockedUnsupported,
            }));
        }
    }
    coverageRecords.sort((left, right) =>
        compareStrings(left.semanticCoverageId, right.semanticCoverageId));
    blockerDetails.sort((left, right) => compareStrings(left.objectId, right.objectId));
    const upstreamBlockerCodes = current.blockerCodes
        .filter((code) => !SEMANTIC_STAGE_BLOCKERS.has(code));
    const complete = upstreamBlockerCodes.length === 0
        && canonicalPlan.blockerCodes.length === 0
        && canonicalPlan.truncated === false
        && blockerDetails.length === 0
        && !anyTruncation;
    const blockerCodes = complete ? []: [...new Set([
        ...upstreamBlockerCodes,
        ...canonicalPlan.blockerCodes,
        ...coverageRecords.flatMap((record) => record.blockerCodes),
        ...(anyTruncation ? [EVASIVE_BLOCKERS.SEMANTIC_TRUNCATED]: []),
        EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE,
    ])].sort(compareStrings);
    const evaluationSha256 = hashDomain("zerotrust-semantic-coverage-evaluation", {
        planId: canonicalPlan.planId,
        scannerRecordIds: scanners.map((record) => record.scannerRecordId).sort(compareStrings),
        assignmentIds: assignments.map((assignment) => assignment.assignmentId).sort(compareStrings),
        reviewIds: reviews.map((review) => review.reviewId).sort(compareStrings),
        candidateIds: candidateLedger.map((candidate) =>
            candidate.candidateId),
        semanticCoverageIds: coverageRecords
            .map((record) => record.semanticCoverageId).sort(compareStrings),
        complete,
        blockerCodes,
        blockerDetails,
    });
    return cloneFrozen({
        schemaVersion: SEMANTIC_COVERAGE_SCHEMA_REVISION,
        contractKind: SEMANTIC_COVERAGE_EVALUATION_KIND,
        evaluationId: `ztse-${evaluationSha256}`,
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        snapshotId: current.snapshotId,
        planId: canonicalPlan.planId,
        complete,
        status: complete ? "comprehensive": "partial",
        truncated: anyTruncation,
        coverageRecords,
        candidateLedger,
        blockerCodes,
        blockerDetails: blockerDetails.slice(
            0,
            SEMANTIC_COVERAGE_LIMITS.blockerDetails,
        ),
        blockerDetailsTruncated:
            blockerDetails.length > SEMANTIC_COVERAGE_LIMITS.blockerDetails,
        counts: {
            classifiedObjects: canonicalPlan.classifications.length,
            scannerAssignments: canonicalPlan.scannerAssignments.length,
            scannerRecords: scanners.length,
            modelSubjects: canonicalPlan.modelReviewShards.length,
            reviewAssignments: assignments.length,
            completedReviews: reviews.filter((review) =>
                review.decision !== "incomplete").length,
            candidates: candidateLedger.length,
            coveredObjects: coverageRecords.filter((record) =>
                ["bounded", "comprehensive"].includes(record.status)).length,
        },
        hashes: {
            evaluationSha256,
        },
    });
}

export function applySemanticCoverageToSnapshot({
    snapshot,
    evaluation,
    stageState = snapshot?.stageState,
} = {}) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    if (!evaluation
        || evaluation.schemaVersion !== 6
        || evaluation.contractKind !== SEMANTIC_COVERAGE_EVALUATION_KIND
        || evaluation.auditId !== current.auditId
        || evaluation.sourceNamespace !== current.sourceNamespace
        || evaluation.snapshotId !== current.snapshotId) {
        fail("evaluation", "does not bind to the supplied assurance snapshot");
    }
    return createAssuranceAnalysisSnapshot({
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        stageState,
        status: "incomplete",
        objectInventory: current.objectInventory,
        derivedArtifacts: current.derivedArtifacts,
        semanticReviewCoverage: evaluation.coverageRecords,
        semanticCandidateLedger: evaluation.candidateLedger,
        redTeamCoverage: current.redTeamCoverage,
        blockerCodes: evaluation.blockerCodes,
        sourceIdentitySha256: current.hashes.sourceIdentitySha256,
    });
}

export function semanticSnapshotCanAdvance(snapshot, evaluation) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    return current.stageState.current === "decoded"
        && evaluation?.complete === true
        && evaluation.truncated === false
        && evaluation.blockerCodes?.length === 0
        && evaluation.blockerDetailsTruncated === false;
}

export const __internals = Object.freeze({
    canonicalJson,
    hashDomain,
    pathParts,
    isWorkflowPath,
    isBuildPath,
    isDependencyPath,
    isGeneratedPath,
    isBinaryArchive,
    deterministicShard,
    evasionClassesForSemanticClass,
});
