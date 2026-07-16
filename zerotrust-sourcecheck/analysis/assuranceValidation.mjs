import { createHash } from "node:crypto";

import {
    ASSURANCE_BLOCKERS,
    EVASION_CLASSES,
    EVASION_CLASS_VALUES,
    computeAssurance,
} from "./assurance.mjs";
import {
    EVASIVE_BLOCKERS,
    mapEvasiveBlockerToAssuranceCode,
    validateAssuranceAnalysisSnapshot,
} from "./evasiveSchemas.mjs";
import { validateSupplyChainGraph } from "./supplyChainGraph.mjs";
import { validateEvasiveGraphPlan } from "./evasiveGraphSchemas.mjs";
import { validateEvasiveTrace } from "./evasiveTrace.mjs";

export const ASSURANCE_VALIDATION_SCHEMA_REVISION = 6;
export const ASSURANCE_VALIDATION_PLAN_KIND = "assurance-validation-plan";
export const ASSURANCE_VALIDATION_ASSIGNMENT_KIND =
    "assurance-validation-assignment";
export const ASSURANCE_VALIDATION_RECORD_KIND = "assurance-validation-record";
export const ASSURANCE_VALIDATION_EVALUATION_KIND =
    "assurance-validation-evaluation";
export const ASSURANCE_VALIDATION_ISSUER_ID =
    "zerotrust-sourcecheck-wrapper";

export const ASSURANCE_NO_FINDING_CHECKS = Object.freeze([
    "semanticCoverageComplete",
    "redTeamCategoriesComplete",
    "supplyChainComplete",
    "unsupportedObjectsResolved",
    "alternatePathsTraced",
    "dynamicTargetsResolved",
    "allActivationRootsTraced",
    "traceUntruncated",
]);

export const ASSURANCE_NO_FINDING_NEGATIVE_EVIDENCE_CODES = Object.freeze([
    "semantic-coverage-complete",
    "red-team-categories-complete",
    "supply-chain-complete",
    "no-unsupported-objects",
    "all-alternate-paths-traced",
    "no-unresolved-dynamic-targets",
    "all-activation-roots-traced",
    "trace-untruncated",
]);

export const ASSURANCE_CONFIRM_CHECKS = Object.freeze([
    "activationReachable",
    "effectReachable",
    "candidateBindingsPreserved",
    "alternatePathsConsidered",
    "dynamicTargetsConsidered",
]);

export const ASSURANCE_REFUTE_CHECKS = Object.freeze([
    "unreachable",
    "benignOnly",
    "brokenBinding",
    "neutralized",
    "insufficientEvidence",
]);

export const ASSURANCE_VALIDATION_LIMITS = Object.freeze({
    assignments: 20_001,
    records: 20_001,
    basisIds: 128,
    referencesPerAssignment: 200_000,
});

const SHA256_RE = /^[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@#-]{0,255}$/u;
const ASSIGNMENT_ID_RE = /^ztava-[a-f0-9]{64}$/u;
const ASSIGNMENT_TOKEN_RE = /^ztavt-[a-f0-9]{64}$/u;
const RECORD_ID_RE = /^ztavr-[a-f0-9]{64}$/u;
const PLAN_ID_RE = /^ztavp-[a-f0-9]{64}$/u;
const EVALUATION_ID_RE = /^ztave-[a-f0-9]{64}$/u;
const AUDIT_ID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export class AssuranceValidationContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "AssuranceValidationContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new AssuranceValidationContractError(path, message);
}

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
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

function cloneFrozen(value) {
    if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
    if (isPlainObject(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) result[key] = cloneFrozen(entry);
        return Object.freeze(result);
    }
    return value;
}

function boundedString(value, path, {
    max = 256,
    pattern = IDENTIFIER_RE,
} = {}) {
    if (typeof value !== "string" || value.length < 1 || value.length > max
        || /[\u0000-\u001f\u007f]/u.test(value)
        || (pattern && !pattern.test(value))) {
        fail(path, "has an invalid bounded string value");
    }
    return value;
}

function enumValue(value, path, allowed) {
    if (!allowed.includes(value)) fail(path, `must be one of: ${allowed.join(", ")}`);
    return value;
}

function sortedUnique(value, path, {
    max = ASSURANCE_VALIDATION_LIMITS.referencesPerAssignment,
    pattern = IDENTIFIER_RE,
} = {}) {
    if (!Array.isArray(value) || value.length > max) {
        fail(path, `must be an array with at most ${max} entries`);
    }
    const result = value.map((entry, index) =>
        boundedString(entry, `${path}[${index}]`, { max: 256, pattern }));
    if (new Set(result).size !== result.length) fail(path, "must not contain duplicates");
    return result.sort();
}

function unique(values) {
    if (typeof values === "string"
        || values === null
        || values === undefined
        || typeof values[Symbol.iterator] !== "function") {
        throw new TypeError("assurance unique values must be iterable");
    }
    return [...new Set([...values].filter(Boolean))].sort();
}

function exactArray(actual, expected, path) {
    if (canonicalJson(actual) !== canonicalJson(expected)) {
        fail(path, "must exactly match the wrapper assignment");
    }
}

function validateValidatorIds(value, path) {
    objectShape(value, path, ["noFinding", "confirm", "refute"]);
    const normalized = {
        noFinding: boundedString(value.noFinding, `${path}.noFinding`, {
            max: 128,
            pattern: IDENTIFIER_RE,
        }),
        confirm: boundedString(value.confirm, `${path}.confirm`, {
            max: 128,
            pattern: IDENTIFIER_RE,
        }),
        refute: boundedString(value.refute, `${path}.refute`, {
            max: 128,
            pattern: IDENTIFIER_RE,
        }),
    };
    if (new Set(Object.values(normalized)).size !== 3) {
        fail(path, "must contain three independent validator IDs");
    }
    return cloneFrozen(normalized);
}

function validateFoundationBinding({
    snapshot,
    graphBaseSnapshot,
    graph,
    trace,
    semanticEvaluation,
    redTeamEvaluation,
    supplyChainGraph,
}) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    if (current.stageState.current !== "traced") {
        fail("snapshot.stageState.current", "must be traced");
    }
    const graphBase = validateAssuranceAnalysisSnapshot(graphBaseSnapshot);
    if (graphBase.stageState.current !== "red-teamed") {
        fail("graphBaseSnapshot.stageState.current", "must be red-teamed");
    }
    const plan = validateEvasiveGraphPlan(graph);
    const traced = validateEvasiveTrace(trace, plan);
    if (!traced.complete || traced.blockerCodes.length > 0) {
        fail("trace", "must be complete and blocker-free");
    }
    if (plan.snapshotId !== graphBase.snapshotId
        || plan.hashes.snapshotSha256 !== graphBase.hashes.snapshotSha256
        || current.auditId !== graphBase.auditId
        || current.sourceNamespace !== graphBase.sourceNamespace
        || current.hashes.inventorySha256 !== graphBase.hashes.inventorySha256
        || current.hashes.derivedArtifactsSha256
            !== graphBase.hashes.derivedArtifactsSha256
        || current.hashes.semanticCoverageSha256
            !== graphBase.hashes.semanticCoverageSha256
        || current.hashes.semanticCandidatesSha256
            !== graphBase.hashes.semanticCandidatesSha256
        || current.hashes.redTeamCoverageSha256
            !== graphBase.hashes.redTeamCoverageSha256) {
        fail("snapshot", "does not preserve the traced graph source identities");
    }
    for (const [name, evaluation] of [
        ["semanticEvaluation", semanticEvaluation],
        ["redTeamEvaluation", redTeamEvaluation],
    ]) {
        if (!evaluation
            || evaluation.schemaVersion !== 6
            || evaluation.auditId !== current.auditId
            || evaluation.sourceNamespace !== current.sourceNamespace
            || evaluation.complete !== true
            || evaluation.truncated !== false
            || evaluation.blockerCodes?.length !== 0) {
            fail(name, "must be the completed active-audit assurance evaluation");
        }
    }
    const supplyChain = supplyChainGraph === null || supplyChainGraph === undefined
        ? null: validateSupplyChainGraph(supplyChainGraph);
    if (supplyChain
        && (supplyChain.auditId !== current.auditId
            || supplyChain.sourceNamespace !== current.sourceNamespace)) {
        fail("supplyChainGraph", "does not match the validation identity");
    }
    return {
        current,
        graphBase,
        plan,
        trace: traced,
        supplyChain,
    };
}

function supplyChainRequired(snapshot, graph) {
    return snapshot.objectInventory.some((object) =>
        object.objectKind === "dependency-metadata"
        || object.objectKind === "gitlink"
        || object.objectKind === "release-asset"
        || object.lfsPointer !== null)
        || snapshot.derivedArtifacts.some((artifact) =>
            artifact.artifactKind === "dependency-graph"
            || artifact.artifactKind === "release-comparison")
        || graph.nodes.some((node) =>
            ["package", "submodule", "lfs", "release-asset"].includes(node.kind));
}

function noFindingChecks({
    current,
    graph,
    trace,
    semanticEvaluation,
    redTeamEvaluation,
    supplyChain,
}) {
    const requiresSupplyChain = supplyChainRequired(current, graph);
    return cloneFrozen({
        semanticCoverageComplete:
            semanticEvaluation.complete === true
            && semanticEvaluation.truncated === false
            && semanticEvaluation.blockerCodes.length === 0,
        redTeamCategoriesComplete:
            redTeamEvaluation.complete === true
            && redTeamEvaluation.truncated === false
            && redTeamEvaluation.gates?.ninetyPercentSatisfied === true
            && redTeamEvaluation.gates?.mandatoryCategoriesSatisfied === true
            && redTeamEvaluation.blockerCodes.length === 0,
        supplyChainComplete:
            !requiresSupplyChain
            || (supplyChain !== null && supplyChain.blockerCodes.length === 0),
        unsupportedObjectsResolved: !graph.nodes.some((node) =>
            node.kind === "unsupported-target" || node.status === "unsupported"),
        alternatePathsTraced:
            trace.complete === true
            && trace.counts.paths === trace.paths.length
            && trace.rootCoverage.every((entry) => entry.complete),
        dynamicTargetsResolved: !graph.nodes.some((node) =>
            node.kind === "dynamic-target" || node.status === "unresolved"),
        allActivationRootsTraced:
            trace.counts.roots === trace.counts.tracedRoots
            && trace.rootCoverage.every((entry) => entry.pathIds.length > 0),
        traceUntruncated: !Object.values(trace.truncation).some(Boolean),
    });
}

function validationBasisIds({
    current,
    graph,
    trace,
    semanticEvaluation,
    redTeamEvaluation,
    supplyChain,
}) {
    return unique([
        current.snapshotId,
        graph.graphId,
        trace.traceId,
        semanticEvaluation.evaluationId,
        redTeamEvaluation.evaluationId,
        supplyChain?.graphId,
    ]);
}

function assignmentKeysForGraph(graph) {
    if (graph.findings.length === 0) return ["no-finding-assurance"];
    return graph.findings.flatMap((finding) => [
        `${finding.findingId}:confirm`,
        `${finding.findingId}:refute`,
    ]).sort();
}

export function listAssuranceValidationAssignmentKeys({ graph } = {}) {
    return cloneFrozen(assignmentKeysForGraph(validateEvasiveGraphPlan(graph)));
}

function findingContext(finding, graph, trace) {
    const nodeSet = new Set(finding.nodeIds);
    const edgeSet = new Set(finding.edgeIds);
    const evidenceSet = new Set(finding.evidenceIds);
    const paths = trace.paths.filter((path) =>
        path.candidateIds.includes(finding.findingId)
        || path.nodeIds.some((id) => nodeSet.has(id))
        || path.edgeIds.some((id) => edgeSet.has(id))
        || path.evidenceIds.some((id) => evidenceSet.has(id)));
    const nodeIds = unique([
        ...finding.nodeIds,
        ...paths.flatMap((path) => path.nodeIds),
    ]);
    const edgeIds = unique([
        ...finding.edgeIds,
        ...paths.flatMap((path) => path.edgeIds),
    ]);
    const evidenceIds = unique([
        ...finding.evidenceIds,
        ...paths.flatMap((path) => path.evidenceIds),
    ]).filter((id) => graph.evidence.some((entry) => entry.evidenceId === id));
    return cloneFrozen({
        findingId: finding.findingId,
        origin: finding.origin,
        severity: finding.severity,
        objectIds: finding.objectIds,
        artifactIds: finding.artifactIds,
        factIds: finding.factIds,
        evidenceIds,
        nodeIds,
        edgeIds,
        pathIds: paths.map((path) => path.pathId).sort(),
        effectPathIds: paths
            .filter((path) => path.status === "complete-effect")
            .map((path) => path.pathId).sort(),
        sourceRecordIds: finding.sourceRecordIds,
    });
}

function normalizeAssignmentContext(value, path = "assignment.context") {
    objectShape(value, path, [
        "findingId",
        "severity",
        "nodeIds",
        "edgeIds",
        "pathIds",
        "effectPathIds",
        "evidenceIds",
        "basisIds",
        "negativeEvidenceCodes",
    ]);
    return cloneFrozen({
        findingId: value.findingId === null
            ? null: boundedString(value.findingId, `${path}.findingId`),
        severity: value.severity === null
            ? null: enumValue(value.severity, `${path}.severity`, [
                "info", "low", "medium", "high", "critical",
            ]),
        nodeIds: sortedUnique(value.nodeIds, `${path}.nodeIds`),
        edgeIds: sortedUnique(value.edgeIds, `${path}.edgeIds`),
        pathIds: sortedUnique(value.pathIds, `${path}.pathIds`),
        effectPathIds: sortedUnique(value.effectPathIds, `${path}.effectPathIds`),
        evidenceIds: sortedUnique(value.evidenceIds, `${path}.evidenceIds`),
        basisIds: sortedUnique(value.basisIds, `${path}.basisIds`, {
            max: ASSURANCE_VALIDATION_LIMITS.basisIds,
        }),
        negativeEvidenceCodes: sortedUnique(
            value.negativeEvidenceCodes,
            `${path}.negativeEvidenceCodes`,
            { max: ASSURANCE_NO_FINDING_NEGATIVE_EVIDENCE_CODES.length },
        ),
    });
}

function createAssignment({
    auditId,
    sourceNamespace,
    planBasisSha256,
    subjectId,
    decisionType,
    validatorId,
    validatorVersion,
    assignmentNonceSha256,
    context,
}) {
    const normalized = {
        auditId: boundedString(auditId, "assignment.auditId", {
            max: 36,
            pattern: AUDIT_ID_RE,
        }).toLowerCase(),
        sourceNamespace: boundedString(
            sourceNamespace,
            "assignment.sourceNamespace",
            { max: 512, pattern: null },
        ),
        planBasisSha256: boundedString(
            planBasisSha256,
            "assignment.planBasisSha256",
            { max: 64, pattern: SHA256_RE },
        ),
        subjectId: boundedString(subjectId, "assignment.subjectId"),
        decisionType: enumValue(
            decisionType,
            "assignment.decisionType",
            ["no-finding", "confirm", "refute"],
        ),
        validatorId: boundedString(validatorId, "assignment.validatorId", {
            max: 128,
            pattern: IDENTIFIER_RE,
        }),
        validatorVersion: boundedString(
            validatorVersion,
            "assignment.validatorVersion",
            {
                max: 64,
                pattern: /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/u,
            },
        ),
        assignmentNonceSha256: boundedString(
            assignmentNonceSha256,
            "assignment.assignmentNonceSha256",
            { max: 64, pattern: SHA256_RE },
        ),
        context: normalizeAssignmentContext(context),
    };
    const assignmentSha256 = hashDomain("zerotrust-assurance-validation-assignment", {
        issuerId: ASSURANCE_VALIDATION_ISSUER_ID,
        planBasisSha256: normalized.planBasisSha256,
        subjectId: normalized.subjectId,
        decisionType: normalized.decisionType,
        validatorId: normalized.validatorId,
        validatorVersion: normalized.validatorVersion,
        assignmentNonceSha256: normalized.assignmentNonceSha256,
        context: normalized.context,
    });
    const tokenSha256 = hashDomain("zerotrust-assurance-validation-token", {
        assignmentSha256,
        assignmentNonceSha256: normalized.assignmentNonceSha256,
    });
    return cloneFrozen({
        schemaVersion: ASSURANCE_VALIDATION_SCHEMA_REVISION,
        contractKind: ASSURANCE_VALIDATION_ASSIGNMENT_KIND,
        assignmentId: `ztava-${assignmentSha256}`,
        assignmentToken: `ztavt-${tokenSha256}`,
        issuerId: ASSURANCE_VALIDATION_ISSUER_ID,
        auditId: normalized.auditId,
        sourceNamespace: normalized.sourceNamespace,
        subjectId: normalized.subjectId,
        decisionType: normalized.decisionType,
        validatorId: normalized.validatorId,
        validatorVersion: normalized.validatorVersion,
        context: normalized.context,
        hashes: {
            planBasisSha256: normalized.planBasisSha256,
            assignmentNonceSha256: normalized.assignmentNonceSha256,
            assignmentSha256,
            tokenSha256,
        },
    });
}

function validateAssignment(value, path = "assuranceValidationAssignment") {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "assignmentId",
        "assignmentToken",
        "issuerId",
        "auditId",
        "sourceNamespace",
        "subjectId",
        "decisionType",
        "validatorId",
        "validatorVersion",
        "context",
        "hashes",
    ]);
    if (value.schemaVersion !== 6
        || value.contractKind !== ASSURANCE_VALIDATION_ASSIGNMENT_KIND
        || value.issuerId !== ASSURANCE_VALIDATION_ISSUER_ID) {
        fail(path, "has an invalid assignment contract");
    }
    boundedString(value.assignmentId, `${path}.assignmentId`, {
        max: 73,
        pattern: ASSIGNMENT_ID_RE,
    });
    boundedString(value.assignmentToken, `${path}.assignmentToken`, {
        max: 73,
        pattern: ASSIGNMENT_TOKEN_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "planBasisSha256",
        "assignmentNonceSha256",
        "assignmentSha256",
        "tokenSha256",
    ]);
    for (const name of Object.keys(value.hashes)) {
        boundedString(value.hashes[name], `${path}.hashes.${name}`, {
            max: 64,
            pattern: SHA256_RE,
        });
    }
    const expected = createAssignment({
        auditId: value.auditId,
        sourceNamespace: value.sourceNamespace,
        planBasisSha256: value.hashes.planBasisSha256,
        subjectId: value.subjectId,
        decisionType: value.decisionType,
        validatorId: value.validatorId,
        validatorVersion: value.validatorVersion,
        assignmentNonceSha256: value.hashes.assignmentNonceSha256,
        context: value.context,
    });
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its wrapper-issued assignment identity");
    }
    return expected;
}

export function createAssuranceValidationPlan({
    snapshot,
    graphBaseSnapshot,
    graph,
    trace,
    semanticEvaluation,
    redTeamEvaluation,
    supplyChainGraph = null,
    validatorIds,
    validatorVersion,
    assignmentNonceSha256ByKey,
} = {}, path = "assuranceValidationPlanInput") {
    const foundation = validateFoundationBinding({
        snapshot,
        graphBaseSnapshot,
        graph,
        trace,
        semanticEvaluation,
        redTeamEvaluation,
        supplyChainGraph,
    });
    const validators = validateValidatorIds(validatorIds, `${path}.validatorIds`);
    const version = boundedString(validatorVersion, `${path}.validatorVersion`, {
        max: 64,
        pattern: /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/u,
    });
    if (!isPlainObject(assignmentNonceSha256ByKey)) {
        fail(`${path}.assignmentNonceSha256ByKey`, "must be a plain object");
    }
    const assignmentKeys = assignmentKeysForGraph(foundation.plan);
    const suppliedKeys = Object.keys(assignmentNonceSha256ByKey).sort();
    exactArray(suppliedKeys, assignmentKeys, `${path}.assignmentNonceSha256ByKey`);
    for (const key of suppliedKeys) {
        boundedString(
            assignmentNonceSha256ByKey[key],
            `${path}.assignmentNonceSha256ByKey.${key}`,
            { max: 64, pattern: SHA256_RE },
        );
    }
    const checks = noFindingChecks({
        current: foundation.current,
        graph: foundation.plan,
        trace: foundation.trace,
        semanticEvaluation,
        redTeamEvaluation,
        supplyChain: foundation.supplyChain,
    });
    const basisIds = validationBasisIds({
        current: foundation.current,
        graph: foundation.plan,
        trace: foundation.trace,
        semanticEvaluation,
        redTeamEvaluation,
        supplyChain: foundation.supplyChain,
    });
    const mode = foundation.plan.findings.length === 0 ? "no-finding": "findings";
    const blockerCodes = new Set();
    if (mode === "no-finding" && Object.values(checks).some((value) => value !== true)) {
        blockerCodes.add(EVASIVE_BLOCKERS.VALIDATION_NO_FINDING_INCOMPLETE);
    }
    if (foundation.plan.findings.some((finding) =>
        finding.evidenceIds.length === 0)) {
        blockerCodes.add(EVASIVE_BLOCKERS.VALIDATION_CANDIDATE_INCOMPLETE);
    }
    if (!checks.supplyChainComplete) blockerCodes.add(EVASIVE_BLOCKERS.SUPPLY_CHAIN_INCOMPLETE);
    const planBasisSha256 = hashDomain("zerotrust-assurance-validation-plan-basis", {
        snapshotId: foundation.current.snapshotId,
        graphId: foundation.plan.graphId,
        traceId: foundation.trace.traceId,
        semanticEvaluationId: semanticEvaluation.evaluationId,
        redTeamEvaluationId: redTeamEvaluation.evaluationId,
        supplyChainGraphId: foundation.supplyChain?.graphId || null,
        mode,
        checks,
        basisIds,
        findingIds: foundation.plan.findings.map((finding) => finding.findingId),
        validatorIds: validators,
        validatorVersion: version,
    });
    const assignments = [];
    if (mode === "no-finding") {
        assignments.push(createAssignment({
            auditId: foundation.current.auditId,
            sourceNamespace: foundation.current.sourceNamespace,
            planBasisSha256,
            subjectId: "no-finding-assurance",
            decisionType: "no-finding",
            validatorId: validators.noFinding,
            validatorVersion: version,
            assignmentNonceSha256:
                assignmentNonceSha256ByKey["no-finding-assurance"],
            context: {
                findingId: null,
                severity: null,
                nodeIds: foundation.plan.nodes.map((node) => node.nodeId),
                edgeIds: foundation.plan.edges.map((edge) => edge.edgeId),
                pathIds: foundation.trace.paths.map((entry) => entry.pathId),
                effectPathIds: foundation.trace.paths
                    .filter((entry) => entry.status === "complete-effect")
                    .map((entry) => entry.pathId),
                evidenceIds: foundation.plan.evidence.map((entry) => entry.evidenceId),
                basisIds,
                negativeEvidenceCodes:
                    [...ASSURANCE_NO_FINDING_NEGATIVE_EVIDENCE_CODES].sort(),
            },
        }));
    } else {
        for (const finding of foundation.plan.findings) {
            const context = findingContext(finding, foundation.plan, foundation.trace);
            for (const decisionType of ["confirm", "refute"]) {
                const key = `${finding.findingId}:${decisionType}`;
                assignments.push(createAssignment({
                    auditId: foundation.current.auditId,
                    sourceNamespace: foundation.current.sourceNamespace,
                    planBasisSha256,
                    subjectId: finding.findingId,
                    decisionType,
                    validatorId: validators[decisionType],
                    validatorVersion: version,
                    assignmentNonceSha256: assignmentNonceSha256ByKey[key],
                    context: {
                        findingId: finding.findingId,
                        severity: finding.severity,
                        nodeIds: context.nodeIds,
                        edgeIds: context.edgeIds,
                        pathIds: context.pathIds,
                        effectPathIds: context.effectPathIds,
                        evidenceIds: context.evidenceIds,
                        basisIds: finding.sourceRecordIds,
                        negativeEvidenceCodes: [],
                    },
                }));
            }
        }
    }
    assignments.sort((left, right) => left.assignmentId.localeCompare(right.assignmentId));
    if (assignments.length > ASSURANCE_VALIDATION_LIMITS.assignments) {
        fail(path, "assignment cap exceeded");
    }
    const planSha256 = hashDomain("zerotrust-assurance-validation-plan", {
        planBasisSha256,
        assignmentIds: assignments.map((assignment) => assignment.assignmentId),
        blockerCodes: unique(blockerCodes),
    });
    return cloneFrozen({
        schemaVersion: ASSURANCE_VALIDATION_SCHEMA_REVISION,
        contractKind: ASSURANCE_VALIDATION_PLAN_KIND,
        planId: `ztavp-${planSha256}`,
        auditId: foundation.current.auditId,
        sourceNamespace: foundation.current.sourceNamespace,
        snapshotId: foundation.current.snapshotId,
        graphId: foundation.plan.graphId,
        traceId: foundation.trace.traceId,
        mode,
        validatorIds: validators,
        validatorVersion: version,
        checks,
        basisIds,
        findingIds: foundation.plan.findings.map((finding) =>
            finding.findingId).sort(),
        assignments,
        blockerCodes: unique(blockerCodes),
        truncated: false,
        hashes: {
            graphSha256: foundation.plan.hashes.graphSha256,
            traceSha256: foundation.trace.hashes.traceSha256,
            planBasisSha256,
            planSha256,
        },
    });
}

export function validateAssuranceValidationPlan(
    value,
    inputs,
    path = "assuranceValidationPlan",
) {
    if (!isPlainObject(value)
        || value.schemaVersion !== 6
        || value.contractKind !== ASSURANCE_VALIDATION_PLAN_KIND
        || typeof value.planId !== "string"
        || !PLAN_ID_RE.test(value.planId)) {
        fail(path, "has an invalid validation plan contract");
    }
    const nonces = Object.fromEntries(value.assignments.map((assignment) => {
        const normalized = validateAssignment(assignment);
        const key = normalized.decisionType === "no-finding"
            ? "no-finding-assurance": `${normalized.subjectId}:${normalized.decisionType}`;
        return [key, normalized.hashes.assignmentNonceSha256];
    }));
    const expected = createAssuranceValidationPlan({
        ...inputs,
        validatorIds: value.validatorIds,
        validatorVersion: value.validatorVersion,
        assignmentNonceSha256ByKey: nonces,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic wrapper plan");
    }
    return expected;
}

function validateReferenceSubset(value, allowed, path) {
    const normalized = sortedUnique(value, path);
    const allowedSet = new Set(allowed);
    if (normalized.some((id) => !allowedSet.has(id))) {
        fail(path, "references an identity outside the assignment");
    }
    return normalized;
}

function normalizeNoFindingChecks(value, path) {
    objectShape(value, path, ASSURANCE_NO_FINDING_CHECKS);
    return cloneFrozen(Object.fromEntries(ASSURANCE_NO_FINDING_CHECKS.map((name) => [
        name,
        enumValue(value[name], `${path}.${name}`, ["passed", "failed", "unresolved"]),
    ])));
}

function normalizeConfirmChecks(value, path) {
    objectShape(value, path, ASSURANCE_CONFIRM_CHECKS);
    const result = {};
    for (const name of ASSURANCE_CONFIRM_CHECKS) {
        if (typeof value[name] !== "boolean") fail(`${path}.${name}`, "must be boolean");
        result[name] = value[name];
    }
    return cloneFrozen(result);
}

function normalizeRefuteChecks(value, path) {
    objectShape(value, path, ASSURANCE_REFUTE_CHECKS);
    return cloneFrozen(Object.fromEntries(ASSURANCE_REFUTE_CHECKS.map((name) => [
        name,
        enumValue(value[name], `${path}.${name}`, [
            "supports-refutation",
            "does-not-refute",
            "unresolved",
        ]),
    ])));
}

export function createAssuranceValidationRecord({
    assignment,
    assignmentToken,
    validatorId,
    conclusion,
    reviewedNodeIds = [],
    reviewedEdgeIds = [],
    reviewedPathIds = [],
    reviewedEvidenceIds = [],
    reviewedBasisIds = [],
    checks,
    negativeEvidenceCodes = [],
    blockerCodes = [],
} = {}, path = "assuranceValidationRecordInput") {
    const assigned = validateAssignment(assignment, `${path}.assignment`);
    if (assignmentToken !== assigned.assignmentToken) {
        fail(`${path}.assignmentToken`, "does not match the wrapper-issued token");
    }
    if (validatorId !== assigned.validatorId) {
        fail(`${path}.validatorId`, "does not match the assigned validator");
    }
    const reviewed = {
        nodeIds: validateReferenceSubset(
            reviewedNodeIds,
            assigned.context.nodeIds,
            `${path}.reviewedNodeIds`,
        ),
        edgeIds: validateReferenceSubset(
            reviewedEdgeIds,
            assigned.context.edgeIds,
            `${path}.reviewedEdgeIds`,
        ),
        pathIds: validateReferenceSubset(
            reviewedPathIds,
            assigned.context.pathIds,
            `${path}.reviewedPathIds`,
        ),
        evidenceIds: validateReferenceSubset(
            reviewedEvidenceIds,
            assigned.context.evidenceIds,
            `${path}.reviewedEvidenceIds`,
        ),
        basisIds: validateReferenceSubset(
            reviewedBasisIds,
            assigned.context.basisIds,
            `${path}.reviewedBasisIds`,
        ),
    };
    const negatives = sortedUnique(
        negativeEvidenceCodes,
        `${path}.negativeEvidenceCodes`,
        { max: ASSURANCE_NO_FINDING_NEGATIVE_EVIDENCE_CODES.length },
    );
    const blockers = sortedUnique(blockerCodes, `${path}.blockerCodes`, {
        max: 3,
    });
    if (blockers.some((code) => ![
        EVASIVE_BLOCKERS.VALIDATION_INCOMPLETE,
        EVASIVE_BLOCKERS.VALIDATION_NO_FINDING_INCOMPLETE,
        EVASIVE_BLOCKERS.VALIDATION_CANDIDATE_INCOMPLETE,
    ].includes(code))) {
        fail(`${path}.blockerCodes`, "contains an invalid validation blocker");
    }
    let normalizedChecks;
    let normalizedConclusion;
    if (assigned.decisionType === "no-finding") {
        normalizedChecks = normalizeNoFindingChecks(checks, `${path}.checks`);
        normalizedConclusion = enumValue(conclusion, `${path}.conclusion`, [
            "supported",
            "not-supported",
            "incomplete",
        ]);
        if (normalizedConclusion === "supported") {
            if (blockers.length > 0
                || Object.values(normalizedChecks).some((value) => value !== "passed")) {
                fail(path, "supported no-finding assurance requires every check to pass");
            }
            exactArray(
                reviewed.basisIds,
                assigned.context.basisIds,
                `${path}.reviewedBasisIds`,
            );
            exactArray(
                reviewed.nodeIds,
                assigned.context.nodeIds,
                `${path}.reviewedNodeIds`,
            );
            exactArray(
                reviewed.edgeIds,
                assigned.context.edgeIds,
                `${path}.reviewedEdgeIds`,
            );
            exactArray(
                reviewed.pathIds,
                assigned.context.pathIds,
                `${path}.reviewedPathIds`,
            );
            exactArray(
                reviewed.evidenceIds,
                assigned.context.evidenceIds,
                `${path}.reviewedEvidenceIds`,
            );
            exactArray(
                negatives,
                assigned.context.negativeEvidenceCodes,
                `${path}.negativeEvidenceCodes`,
            );
        }
    } else if (assigned.decisionType === "confirm") {
        normalizedChecks = normalizeConfirmChecks(checks, `${path}.checks`);
        normalizedConclusion = enumValue(conclusion, `${path}.conclusion`, [
            "confirmed",
            "not-confirmed",
            "unresolved",
        ]);
        if (reviewed.evidenceIds.length === 0) {
            fail(`${path}.reviewedEvidenceIds`, "must reference existing evidence");
        }
        if (normalizedConclusion === "confirmed") {
            if (blockers.length > 0
                || Object.values(normalizedChecks).some((value) => value !== true)
                || !reviewed.pathIds.some((pathId) =>
                    assigned.context.effectPathIds.includes(pathId))) {
                fail(path, "confirmed findings require a complete existing path and checks");
            }
        }
        if (negatives.length > 0) {
            fail(`${path}.negativeEvidenceCodes`, "must be empty for candidate confirmation");
        }
    } else {
        normalizedChecks = normalizeRefuteChecks(checks, `${path}.checks`);
        normalizedConclusion = enumValue(conclusion, `${path}.conclusion`, [
            "refuted",
            "not-refuted",
            "unresolved",
        ]);
        if (reviewed.evidenceIds.length === 0) {
            fail(`${path}.reviewedEvidenceIds`, "must reference existing evidence");
        }
        const supports = Object.values(normalizedChecks).filter((value) =>
            value === "supports-refutation").length;
        if (normalizedConclusion === "refuted" && supports === 0) {
            fail(`${path}.checks`, "refuted findings require a supporting refutation check");
        }
        if (normalizedConclusion === "not-refuted" && supports > 0) {
            fail(`${path}.checks`, "not-refuted findings cannot support refutation");
        }
        if (negatives.length > 0) {
            fail(`${path}.negativeEvidenceCodes`, "must be empty for candidate refutation");
        }
    }
    if (normalizedConclusion === "incomplete"
        || normalizedConclusion === "unresolved") {
        if (!blockers.includes(EVASIVE_BLOCKERS.VALIDATION_INCOMPLETE)) {
            fail(`${path}.blockerCodes`, "must include validation/incomplete");
        }
    } else if (blockers.length > 0) {
        fail(`${path}.blockerCodes`, "completed decisions must not contain blockers");
    }
    const recordSha256 = hashDomain("zerotrust-assurance-validation-record", {
        assignmentId: assigned.assignmentId,
        assignmentToken: assigned.assignmentToken,
        validatorId: assigned.validatorId,
        subjectId: assigned.subjectId,
        decisionType: assigned.decisionType,
        conclusion: normalizedConclusion,
        reviewed,
        checks: normalizedChecks,
        negativeEvidenceCodes: negatives,
        blockerCodes: blockers,
    });
    return cloneFrozen({
        schemaVersion: ASSURANCE_VALIDATION_SCHEMA_REVISION,
        contractKind: ASSURANCE_VALIDATION_RECORD_KIND,
        recordId: `ztavr-${recordSha256}`,
        assignmentId: assigned.assignmentId,
        assignmentToken: assigned.assignmentToken,
        validatorId: assigned.validatorId,
        subjectId: assigned.subjectId,
        decisionType: assigned.decisionType,
        conclusion: normalizedConclusion,
        reviewed,
        checks: normalizedChecks,
        negativeEvidenceCodes: negatives,
        blockerCodes: blockers,
        hashes: {
            assignmentSha256: assigned.hashes.assignmentSha256,
            recordSha256,
        },
    });
}

export function validateAssuranceValidationRecord(
    value,
    assignment,
    path = "assuranceValidationRecord",
) {
    if (!isPlainObject(value)
        || value.schemaVersion !== 6
        || value.contractKind !== ASSURANCE_VALIDATION_RECORD_KIND
        || typeof value.recordId !== "string"
        || !RECORD_ID_RE.test(value.recordId)) {
        fail(path, "has an invalid validation record contract");
    }
    const expected = createAssuranceValidationRecord({
        assignment,
        assignmentToken: value.assignmentToken,
        validatorId: value.validatorId,
        conclusion: value.conclusion,
        reviewedNodeIds: value.reviewed.nodeIds,
        reviewedEdgeIds: value.reviewed.edgeIds,
        reviewedPathIds: value.reviewed.pathIds,
        reviewedEvidenceIds: value.reviewed.evidenceIds,
        reviewedBasisIds: value.reviewed.basisIds,
        checks: value.checks,
        negativeEvidenceCodes: value.negativeEvidenceCodes,
        blockerCodes: value.blockerCodes,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its immutable validation record");
    }
    return expected;
}

function blockerClass(code) {
    if (code === EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT) {
        return EVASION_CLASSES.UNSUPPORTED_OR_OPAQUE_ARTIFACTS;
    }
    if (code === EVASIVE_BLOCKERS.SUPPLY_CHAIN_INCOMPLETE) {
        return EVASION_CLASSES.DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION;
    }
    if (code === EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED) {
        return EVASION_CLASSES.DYNAMIC_CODE_AND_EXTERNAL_PAYLOAD_LOADING;
    }
    return EVASION_CLASSES.INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION;
}

function computeValidationAssurance(plan, blockerCodes) {
    const coverage = Object.fromEntries(
        EVASION_CLASS_VALUES.map((evasionClass) => [evasionClass, "comprehensive"]),
    );
    if (!plan.checks.supplyChainComplete) {
        coverage[EVASION_CLASSES.DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION] =
            "partial";
        coverage[EVASION_CLASSES.RELEASE_SOURCE_AND_ARTIFACT_DIVERGENCE] =
            "partial";
    }
    if (!plan.checks.unsupportedObjectsResolved) {
        coverage[EVASION_CLASSES.UNSUPPORTED_OR_OPAQUE_ARTIFACTS] = "partial";
    }
    if (!plan.checks.dynamicTargetsResolved) {
        coverage[EVASION_CLASSES.DYNAMIC_CODE_AND_EXTERNAL_PAYLOAD_LOADING] =
            "partial";
    }
    const blockers = unique(blockerCodes).map((code) => ({
        code: mapEvasiveBlockerToAssuranceCode(code),
        evasionClass: blockerClass(code),
    }));
    const deduped = [...new Map(blockers.map((blocker) => [
        `${blocker.code}\0${blocker.evasionClass}`,
        blocker,
    ])).values()];
    return computeAssurance({
        schemaVersion: 6,
        artifactSupport: plan.checks.unsupportedObjectsResolved
            ? "supported": "unsupported",
        coverage,
        blockers: deduped,
    });
}

export function evaluateAssuranceValidation({
    plan,
    planInputs,
    records = [],
} = {}, path = "assuranceValidationEvaluationInput") {
    const canonicalPlan = validateAssuranceValidationPlan(
        plan,
        planInputs,
        `${path}.plan`,
    );
    if (!Array.isArray(records)
        || records.length > ASSURANCE_VALIDATION_LIMITS.records) {
        fail(`${path}.records`, "exceeds the validation record cap");
    }
    const assignmentById = new Map(
        canonicalPlan.assignments.map((assignment) =>
            [assignment.assignmentId, assignment]),
    );
    const recordByAssignment = new Map();
    for (const [index, raw] of records.entries()) {
        const assignment = assignmentById.get(raw?.assignmentId);
        if (!assignment) {
            fail(`${path}.records[${index}].assignmentId`, "is not wrapper-issued");
        }
        const record = validateAssuranceValidationRecord(
            raw,
            assignment,
            `${path}.records[${index}]`,
        );
        const existing = recordByAssignment.get(record.assignmentId);
        if (existing && canonicalJson(existing) !== canonicalJson(record)) {
            fail(`${path}.records`, "contains changed duplicate assignment records");
        }
        recordByAssignment.set(record.assignmentId, record);
    }
    const blockerCodes = new Set(canonicalPlan.blockerCodes);
    const missingAssignmentIds = canonicalPlan.assignments
        .filter((assignment) => !recordByAssignment.has(assignment.assignmentId))
        .map((assignment) => assignment.assignmentId);
    if (missingAssignmentIds.length > 0) {
        blockerCodes.add(EVASIVE_BLOCKERS.VALIDATION_INCOMPLETE);
    }
    const findingOutcomes = [];
    let noFindingOutcome = null;
    if (canonicalPlan.mode === "no-finding") {
        const assignment = canonicalPlan.assignments[0];
        const record = recordByAssignment.get(assignment.assignmentId);
        noFindingOutcome = record?.conclusion || "incomplete";
        if (noFindingOutcome !== "supported") {
            blockerCodes.add(EVASIVE_BLOCKERS.VALIDATION_NO_FINDING_INCOMPLETE);
        }
    } else {
        for (const findingId of canonicalPlan.findingIds) {
            const assignments = canonicalPlan.assignments.filter((assignment) =>
                assignment.subjectId === findingId);
            const confirm = recordByAssignment.get(
                assignments.find((entry) =>
                    entry.decisionType === "confirm").assignmentId,
            );
            const refute = recordByAssignment.get(
                assignments.find((entry) =>
                    entry.decisionType === "refute").assignmentId,
            );
            let outcome = "unresolved";
            if (confirm?.conclusion === "confirmed"
                && refute?.conclusion === "not-refuted") {
                outcome = "validated";
            } else if (confirm?.conclusion === "not-confirmed"
                && refute?.conclusion === "refuted") {
                outcome = "refuted";
            }
            if (outcome === "unresolved") {
                blockerCodes.add(EVASIVE_BLOCKERS.VALIDATION_CANDIDATE_INCOMPLETE);
            }
            findingOutcomes.push(cloneFrozen({
                findingId,
                severity: assignments[0].context.severity,
                confirmRecordId: confirm?.recordId || null,
                refuteRecordId: refute?.recordId || null,
                outcome,
            }));
        }
    }
    for (const record of recordByAssignment.values()) {
        for (const code of record.blockerCodes) blockerCodes.add(code);
    }
    const complete = missingAssignmentIds.length === 0
        && blockerCodes.size === 0
        && (canonicalPlan.mode === "no-finding"
            ? noFindingOutcome === "supported": findingOutcomes.every((finding) =>
                finding.outcome === "validated" || finding.outcome === "refuted"));
    if (!complete) blockerCodes.add(EVASIVE_BLOCKERS.VALIDATION_INCOMPLETE);
    const assurance = computeValidationAssurance(canonicalPlan, [...blockerCodes]);
    const evaluationSha256 = hashDomain(
        "zerotrust-assurance-validation-evaluation",
        {
            planId: canonicalPlan.planId,
            recordIds: [...recordByAssignment.values()]
                .map((record) => record.recordId).sort(),
            missingAssignmentIds,
            noFindingOutcome,
            findingOutcomes,
            blockerCodes: unique(blockerCodes),
            complete,
            assuranceLevel: assurance.assuranceLevel,
        },
    );
    return cloneFrozen({
        schemaVersion: ASSURANCE_VALIDATION_SCHEMA_REVISION,
        contractKind: ASSURANCE_VALIDATION_EVALUATION_KIND,
        evaluationId: `ztave-${evaluationSha256}`,
        auditId: canonicalPlan.auditId,
        sourceNamespace: canonicalPlan.sourceNamespace,
        snapshotId: canonicalPlan.snapshotId,
        planId: canonicalPlan.planId,
        mode: canonicalPlan.mode,
        complete,
        noFindingOutcome,
        findingOutcomes,
        missingAssignmentIds,
        blockerCodes: unique(blockerCodes),
        assurance,
        counts: {
            assignments: canonicalPlan.assignments.length,
            records: recordByAssignment.size,
            findings: canonicalPlan.findingIds.length,
            validatedFindings: findingOutcomes.filter((finding) =>
                finding.outcome === "validated").length,
            refutedFindings: findingOutcomes.filter((finding) =>
                finding.outcome === "refuted").length,
            unresolvedFindings: findingOutcomes.filter((finding) =>
                finding.outcome === "unresolved").length,
        },
        hashes: { evaluationSha256 },
    });
}

export function validateAssuranceValidationEvaluation(
    value,
    inputs,
    path = "assuranceValidationEvaluation",
) {
    if (!isPlainObject(value)
        || value.schemaVersion !== 6
        || value.contractKind !== ASSURANCE_VALIDATION_EVALUATION_KIND
        || typeof value.evaluationId !== "string"
        || !EVALUATION_ID_RE.test(value.evaluationId)) {
        fail(path, "has an invalid validation evaluation contract");
    }
    const expected = evaluateAssuranceValidation(inputs, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match the recomputed validation gates");
    }
    return expected;
}

export function assuranceValidationCanAdvance(plan, evaluation) {
    return plan?.schemaVersion === 6
        && evaluation?.schemaVersion === 6
        && evaluation.planId === plan.planId
        && evaluation.complete === true
        && evaluation.blockerCodes.length === 0
        && evaluation.counts.assignments === evaluation.counts.records
        && evaluation.counts.unresolvedFindings === 0;
}

export const __internals = Object.freeze({
    ASSURANCE_BLOCKERS,
    canonicalJson,
    hashDomain,
    noFindingChecks,
    supplyChainRequired,
    validateAssignment,
});
