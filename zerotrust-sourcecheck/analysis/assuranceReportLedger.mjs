import {
    EVASION_CLASS_VALUES,
    computeAssurance,
    validateAssuranceResult,
} from "./assurance.mjs";
import {
    FINDINGS_ARTIFACT_SCHEMA_REVISION,
    REPORT_LEDGER_LIMITS,
    canonicalJson,
    normalizeOperatorDecisions,
    sha256Canonical,
} from "./reportLedger.mjs";
import { validateAssuranceAnalysisSnapshot } from "./evasiveSchemas.mjs";
import { validateEvasiveGraphPlan } from "./evasiveGraphSchemas.mjs";
import { validateEvasiveTrace } from "./evasiveTrace.mjs";

export const ASSURANCE_REPORT_FLOW = "evasive-assurance";
export const ASSURANCE_NO_SUPPORTED_BEHAVIOR_VERDICT =
    "no supported malicious behavior found";

const SEVERITIES = Object.freeze(["info", "low", "medium", "high", "critical"]);
const SEVERITY_RANK = Object.freeze(
    Object.fromEntries(SEVERITIES.map((severity, index) => [severity, index])),
);
const FORBIDDEN_KEYS = new Set([
    "sourceText",
    "source_text",
    "snippet",
    "excerptText",
    "excerpt_text",
    "quotedEvidence",
    "quoted_evidence",
    "markdown",
    "markdownBody",
    "markdown_body",
    "reportBody",
    "report_body",
    "prompt",
    "modelOutput",
    "model_output",
]);

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function cloneFrozen(value) {
    if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
    if (isPlainObject(value)) {
        return Object.freeze(Object.fromEntries(
            Object.entries(value).map(([key, entry]) => [key, cloneFrozen(entry)]),
        ));
    }
    return value;
}

function sourceIdentity(context) {
    if (context.localPath) {
        return {
            kind: "local",
            path: context.localPath,
            localSlug: context.localReportSlug,
            localTimestamp: context.localReportTimestamp,
        };
    }
    return {
        kind: "github",
        owner: context.canonicalOwner,
        repo: context.canonicalRepo,
        resolvedSha: context.resolvedSha,
        rootTreeSha: context.rootTreeSha || null,
    };
}

function severityCounts(findings) {
    return Object.fromEntries(SEVERITIES.map((severity) => [
        severity,
        findings.filter((finding) => finding.severity === severity).length,
    ]));
}

function highestSeverity(findings) {
    return findings.reduce((highest, finding) =>
        SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]
            ? finding.severity: highest, "info");
}

function requireValidatedState(value) {
    if (!isPlainObject(value) || value.schemaVersion !== 6) {
        throw new TypeError("assurance report finalization requires assurance state");
    }
    if (!["validated", "finalized"].includes(value.stageState?.current)) {
        throw new TypeError(
            `assurance report finalization requires validated state (current: ${value.stageState?.current || "missing"})`,
        );
    }
    const snapshot = validateAssuranceAnalysisSnapshot(value.analysisSnapshot);
    const graph = validateEvasiveGraphPlan(value.graphPlan);
    const trace = validateEvasiveTrace(value.graphTrace, graph);
    const validation = value.assuranceValidationEvaluation;
    if (snapshot.auditId !== value.auditId
        || snapshot.sourceNamespace !== value.sourceNamespace
        || snapshot.stageState.current !== value.stageState.current
        || graph.auditId !== value.auditId
        || graph.sourceNamespace !== value.sourceNamespace
        || trace.auditId !== value.auditId
        || trace.sourceNamespace !== value.sourceNamespace
        || validation?.schemaVersion !== 6
        || validation.auditId !== value.auditId
        || validation.sourceNamespace !== value.sourceNamespace
        || validation.complete !== true
        || validation.blockerCodes?.length !== 0
        || validation.counts?.unresolvedFindings !== 0) {
        throw new TypeError(
            "assurance report finalization requires one complete identity-bound assurance validation",
        );
    }
    const assurance = validateAssuranceResult(validation.assurance);
    const recomputedAssurance = computeAssurance({
        schemaVersion: assurance.schemaVersion,
        artifactSupport: assurance.artifactSupport,
        coverage: assurance.coverage,
        blockers: assurance.blockers,
    });
    if (canonicalJson(assurance) !== canonicalJson(recomputedAssurance)) {
        throw new TypeError("assurance result is not deterministic");
    }
    return { snapshot, graph, trace, validation, assurance };
}

export function computeAssuranceFindingsDecision(value) {
    const { graph, validation, assurance } = requireValidatedState(value);
    const findingById = new Map(graph.findings.map((finding) => [
        finding.findingId,
        finding,
    ]));
    const activeFindings = [];
    const refutedFindingIds = [];
    for (const outcome of validation.findingOutcomes || []) {
        const finding = findingById.get(outcome.findingId);
        if (!finding || finding.severity !== outcome.severity) {
            throw new TypeError(
                `assurance outcome ${outcome.findingId} does not match the graph`,
            );
        }
        if (outcome.outcome === "validated") activeFindings.push(finding);
        else if (outcome.outcome === "refuted") refutedFindingIds.push(finding.findingId);
        else throw new TypeError("assurance validated state contains an unresolved finding");
    }
    if (validation.mode === "no-finding") {
        if (graph.findings.length !== 0
            || validation.noFindingOutcome !== "supported"
            || activeFindings.length !== 0) {
            throw new TypeError("assurance no-finding validation is inconsistent");
        }
    } else if (validation.findingOutcomes.length !== graph.findings.length) {
        throw new TypeError("assurance finding validation does not cover every graph finding");
    }
    activeFindings.sort((left, right) =>
        SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
        || left.findingId.localeCompare(right.findingId));
    refutedFindingIds.sort();
    const counts = severityCounts(activeFindings);
    const verdict = activeFindings.length > 0
        ? highestSeverity(activeFindings): ASSURANCE_NO_SUPPORTED_BEHAVIOR_VERDICT;
    const assuranceComplete = [
        "comprehensive-static",
        "comprehensive-static-with-supply-chain",
    ].includes(assurance.assuranceLevel);
    const base = {
        schemaVersion: 6,
        verdict,
        activeFindingIds: activeFindings.map((finding) => finding.findingId),
        refutedFindingIds,
        severityCounts: counts,
        complete: true,
        assurance: {
            level: assurance.assuranceLevel,
            complete: assuranceComplete,
        },
        validationEvaluationId: validation.evaluationId,
    };
    return cloneFrozen({
        outcomeId: `zto-${sha256Canonical(base)}`,
        ...base,
    });
}

function sanitizeCoverageRecord(record, idField) {
    return {
        [idField]: record[idField],
        objectId: record.objectId,
        path: record.path,
        artifactIds: [...record.artifactIds],
        producer: record.producer,
        producerVersion: record.producerVersion,
        status: record.status,
        evasionClasses: [...record.evasionClasses],
        blockerCodes: [...record.blockerCodes],
        hashes: {
            basisSha256: record.hashes.basisSha256,
            objectIdentitySha256: record.hashes.objectIdentitySha256,
            subjectSetSha256: record.hashes.subjectSetSha256,
            coverageSha256: record.hashes.coverageSha256,
        },
    };
}

function sanitizeCandidate(candidate, origin) {
    return {
        candidateId: candidate.candidateId,
        origin,
        ...(candidate.categoryId ? { categoryId: candidate.categoryId }: {}),
        producerAssignmentId: candidate.producerAssignmentId,
        ...(candidate.semanticViewId ? { semanticViewId: candidate.semanticViewId }: {}),
        behavior: {
            trigger: candidate.behavior.trigger,
            capability: candidate.behavior.capability,
            action: candidate.behavior.action,
            target: candidate.behavior.target,
        },
        severity: candidate.severity,
        confidence: candidate.confidence,
        maliciousProjectFit: candidate.maliciousProjectFit,
        benignHypothesisCode: candidate.benignHypothesisCode,
        objectIds: [...candidate.objectIds],
        artifactIds: [...candidate.artifactIds],
        factIds: [...candidate.factIds],
        evidenceIds: [...candidate.evidenceIds],
        ...(candidate.graphNodeIds
            ? { graphNodeIds: [...candidate.graphNodeIds] }: {}),
        ...(candidate.graphEdgeIds
            ? { graphEdgeIds: [...candidate.graphEdgeIds] }: {}),
        hashes: structuredClone(candidate.hashes),
    };
}

function sanitizeGraph(graph) {
    return {
        graphId: graph.graphId,
        snapshotId: graph.snapshotId,
        counts: {
            nodes: graph.nodes.length,
            edges: graph.edges.length,
            evidence: graph.evidence.length,
            findings: graph.findings.length,
            conflicts: graph.conflicts.length,
            unresolvedTargets: graph.unresolvedTargetNodeIds.length,
        },
        nodes: graph.nodes.map((node) => ({
            nodeId: node.nodeId,
            kind: node.kind,
            identityKind: node.identityKind,
            identity: node.identity,
            status: node.status,
            bindings: structuredClone(node.bindings),
            hashes: structuredClone(node.hashes),
        })),
        edges: graph.edges.map((edge) => ({
            edgeId: edge.edgeId,
            kind: edge.kind,
            fromNodeId: edge.fromNodeId,
            toNodeId: edge.toNodeId,
            bindings: structuredClone(edge.bindings),
            hashes: structuredClone(edge.hashes),
        })),
        evidence: graph.evidence.map((entry) => ({
            evidenceId: entry.evidenceId,
            evidenceKind: entry.evidenceKind,
            objectId: entry.objectId,
            artifactId: entry.artifactId,
            factId: entry.factId,
            supplyChainNodeId: entry.supplyChainNodeId,
            path: entry.path,
            startLine: entry.startLine,
            endLine: entry.endLine,
            excerptHash: entry.excerptHash,
            contentSha256: entry.contentSha256,
        })),
        findings: graph.findings.map((finding) => ({
            findingId: finding.findingId,
            origin: finding.origin,
            severity: finding.severity,
            objectIds: [...finding.objectIds],
            artifactIds: [...finding.artifactIds],
            factIds: [...finding.factIds],
            evidenceIds: [...finding.evidenceIds],
            nodeIds: [...finding.nodeIds],
            edgeIds: [...finding.edgeIds],
            sourceRecordIds: [...finding.sourceRecordIds],
            hashes: structuredClone(finding.hashes),
        })),
        conflicts: graph.conflicts.map((conflict) => ({
            conflictId: conflict.conflictId,
            reasonCode: conflict.reasonCode,
            edgeKind: conflict.edgeKind,
            endpointNodeIds: [...conflict.endpointNodeIds],
            recordIds: conflict.records.map((record) => record.edgeId),
            hashes: structuredClone(conflict.hashes),
        })),
        unresolvedTargetNodeIds: [...graph.unresolvedTargetNodeIds],
        blockerCodes: [...graph.blockerCodes],
        truncation: structuredClone(graph.truncation),
        hashes: structuredClone(graph.hashes),
    };
}

function sanitizeTrace(trace) {
    return {
        traceId: trace.traceId,
        graphId: trace.graphId,
        complete: trace.complete,
        counts: structuredClone(trace.counts),
        paths: trace.paths.map((path) => ({
            pathId: path.pathId,
            rootNodeId: path.rootNodeId,
            status: path.status,
            nodeIds: [...path.nodeIds],
            edgeIds: [...path.edgeIds],
            effectNodeIds: [...path.effectNodeIds],
            candidateIds: [...path.candidateIds],
            evidenceIds: [...path.evidenceIds],
            unresolvedCodes: [...path.unresolvedCodes],
            hashes: structuredClone(path.hashes),
        })),
        rootCoverage: trace.rootCoverage.map((entry) => ({
            rootNodeId: entry.rootNodeId,
            pathIds: [...entry.pathIds],
            complete: entry.complete,
        })),
        cycles: trace.cycles.map((cycle) => ({
            cycleId: cycle.cycleId,
            rootNodeId: cycle.rootNodeId,
            nodeIds: [...cycle.nodeIds],
            edgeIds: [...cycle.edgeIds],
            repeatedNodeId: cycle.repeatedNodeId,
            hashes: structuredClone(cycle.hashes),
        })),
        blockerCodes: [...trace.blockerCodes],
        truncation: structuredClone(trace.truncation),
        hashes: structuredClone(trace.hashes),
    };
}

function sanitizeAssuranceValidation(state) {
    const plan = state.assuranceValidationPlan;
    const evaluation = state.assuranceValidationEvaluation;
    return {
        planId: plan.planId,
        evaluationId: evaluation.evaluationId,
        mode: evaluation.mode,
        complete: evaluation.complete,
        checks: structuredClone(plan.checks),
        basisIds: [...plan.basisIds],
        findingIds: [...plan.findingIds],
        blockerCodes: [...evaluation.blockerCodes],
        noFindingOutcome: evaluation.noFindingOutcome,
        findingOutcomes: evaluation.findingOutcomes.map((outcome) => ({
            findingId: outcome.findingId,
            severity: outcome.severity,
            confirmRecordId: outcome.confirmRecordId,
            refuteRecordId: outcome.refuteRecordId,
            outcome: outcome.outcome,
        })),
        missingAssignmentIds: [...evaluation.missingAssignmentIds],
        counts: structuredClone(evaluation.counts),
        records: state.assuranceValidationRecords.map((record) => ({
            recordId: record.recordId,
            assignmentId: record.assignmentId,
            validatorId: record.validatorId,
            subjectId: record.subjectId,
            decisionType: record.decisionType,
            conclusion: record.conclusion,
            reviewed: structuredClone(record.reviewed),
            checks: structuredClone(record.checks),
            negativeEvidenceCodes: [...record.negativeEvidenceCodes],
            blockerCodes: [...record.blockerCodes],
            hashes: structuredClone(record.hashes),
        })),
        hashes: structuredClone(evaluation.hashes),
    };
}

function sanitizeSupplyChain(graph) {
    if (!graph) {
        return {
            present: false,
            status: "not-required-or-not-present",
            blockerCodes: [],
            blockerDetails: [],
        };
    }
    return {
        present: true,
        graphId: graph.graphId,
        status: graph.status,
        counts: structuredClone(graph.counts),
        blockerCodes: [...graph.blockerCodes],
        blockerDetails: (graph.blockerDetails || []).map((entry) => ({
            code: entry.code,
            subjectId: entry.subjectId || null,
        })),
        hashes: structuredClone(graph.hashes),
    };
}

function evasionSummary(assurance, semanticRecords, redTeamRecords) {
    return EVASION_CLASS_VALUES.map((evasionClass) => ({
        evasionClass,
        assuranceCoverage: assurance.coverage[evasionClass],
        semanticCoverageRecords: semanticRecords.filter((record) =>
            record.evasionClasses.includes(evasionClass)).length,
        redTeamCoverageRecords: redTeamRecords.filter((record) =>
            record.evasionClasses.includes(evasionClass)).length,
        assuranceBlockerCodes: assurance.blockers
            .filter((blocker) => blocker.evasionClass === evasionClass)
            .map((blocker) => blocker.code),
    }));
}

function knownSourceStrings(state) {
    const candidates = [
        ...(state.semanticCoverageEvaluation?.candidateLedger || []),
        ...(state.redTeamEvaluation?.candidateLedger || []),
    ];
    return [
        ...state.analysisSnapshot.objectInventory.map((object) => object.path),
        ...candidates.flatMap((candidate) => Object.values(candidate.behavior)),
    ];
}

function normalizeAssuranceOperatorDecisions(value, decision, state) {
    for (const entry of value || []) {
        if (typeof entry?.operator_rationale === "string"
            && /\b(?:safe|clean)\b/iu.test(entry.operator_rationale)) {
            throw new TypeError(
                "assurance operator_rationale must not use safe/clean verdict language",
            );
        }
    }
    return normalizeOperatorDecisions(value, {
        decisionSnapshot: {
            canonicalFindings: decision.activeFindingIds.map((canonicalId) => ({
                canonicalId,
            })),
        },
        remediationPlan: null,
        knownSourceStrings: knownSourceStrings(state),
    });
}

function assertSourceTextFree(value, path = "assuranceFindingsArtifact") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) =>
            assertSourceTextFree(entry, `${path}[${index}]`));
        return;
    }
    if (typeof value === "string") {
        if (/[\u0000-\u001f\u007f]/u.test(value)) {
            throw new TypeError(`${path} contains a control character`);
        }
        return;
    }
    if (!isPlainObject(value)) return;
    for (const [key, entry] of Object.entries(value)) {
        if (FORBIDDEN_KEYS.has(key)) {
            throw new TypeError(`${path}.${key} is not source-text-free`);
        }
        assertSourceTextFree(entry, `${path}.${key}`);
    }
}

function renderManifestFor(document) {
    return {
        flow: document.flow,
        verdict: document.verdict.value,
        activeFindingIds: document.verdict.activeFindingIds,
        severityCounts: document.verdict.severityCounts,
        assuranceLevel: document.assurance.assuranceLevel,
        assuranceComplete: document.assurance.complete,
        assuranceBasis: document.assurance.basis,
        validationEvaluationId:
            document.coverage.assuranceValidation.evaluationId,
        graphId: document.graph.graphId,
        traceId: document.trace.traceId,
        operatorDecisions: document.operatorDecisions,
    };
}

export function buildAssuranceFindingsArtifact({
    context,
    reportIdentity,
    assuranceState,
    operatorDecisions = [],
} = {}) {
    const normalized = requireValidatedState(assuranceState);
    if (context?.auditId !== assuranceState.auditId) {
        throw new TypeError("assurance report state does not match the active audit");
    }
    const decision = computeAssuranceFindingsDecision(assuranceState);
    const semanticRecords = (
        assuranceState.semanticCoverageEvaluation?.coverageRecords || []
    ).map((record) => sanitizeCoverageRecord(record, "semanticCoverageId"));
    const redTeamRecords = (
        assuranceState.redTeamEvaluation?.coverageRecords || []
    ).map((record) => sanitizeCoverageRecord(record, "redTeamCoverageId"));
    const normalizedDecisions = normalizeAssuranceOperatorDecisions(
        operatorDecisions,
        decision,
        assuranceState,
    );
    const base = {
        schemaVersion: 6,
        artifactSchemaRevision: FINDINGS_ARTIFACT_SCHEMA_REVISION,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: ASSURANCE_REPORT_FLOW,
        auditId: assuranceState.auditId,
        mode: context.mode,
        sourceIdentity: sourceIdentity(context),
        reportIdentity: structuredClone(reportIdentity),
        verdict: {
            value: decision.verdict,
            trusted: true,
            deterministic: true,
            outcomeId: decision.outcomeId,
            activeFindingIds: [...decision.activeFindingIds],
            refutedFindingIds: [...decision.refutedFindingIds],
            severityCounts: structuredClone(decision.severityCounts),
        },
        assurance: {
            ...structuredClone(normalized.assurance),
            complete: decision.assurance.complete,
        },
        stage: {
            input: assuranceState.stageState.current,
            history: [...assuranceState.stageState.history],
            final: "finalized",
        },
        coverage: {
            snapshot: {
                snapshotId: normalized.snapshot.snapshotId,
                status: normalized.snapshot.status,
                blockerCodes: [...normalized.snapshot.blockerCodes],
                counts: {
                    objects: normalized.snapshot.objectInventory.length,
                    derivedArtifacts: normalized.snapshot.derivedArtifacts.length,
                    semanticCoverageRecords:
                        normalized.snapshot.semanticReviewCoverage.length,
                    redTeamCoverageRecords:
                        normalized.snapshot.redTeamCoverage.length,
                    semanticCandidates:
                        normalized.snapshot.semanticCandidateLedger.length,
                },
                hashes: structuredClone(normalized.snapshot.hashes),
            },
            semantic: {
                planId: assuranceState.semanticCoveragePlan?.planId || null,
                evaluationId:
                    assuranceState.semanticCoverageEvaluation?.evaluationId || null,
                complete: assuranceState.semanticCoverageEvaluation?.complete === true,
                status: assuranceState.semanticCoverageEvaluation?.status || null,
                truncated:
                    assuranceState.semanticCoverageEvaluation?.truncated === true,
                counts: structuredClone(
                    assuranceState.semanticCoverageEvaluation?.counts || {},
                ),
                blockerCodes: [
                    ...(assuranceState.semanticCoverageEvaluation?.blockerCodes || []),
                ],
                records: semanticRecords,
            },
            redTeam: {
                planId: assuranceState.redTeamPlan?.planId || null,
                evaluationId: assuranceState.redTeamEvaluation?.evaluationId || null,
                complete: assuranceState.redTeamEvaluation?.complete === true,
                status: assuranceState.redTeamEvaluation?.status || null,
                truncated: assuranceState.redTeamEvaluation?.truncated === true,
                gates: structuredClone(assuranceState.redTeamEvaluation?.gates || {}),
                blockerCodes: [
                    ...(assuranceState.redTeamEvaluation?.blockerCodes || []),
                ],
                blockerDetails: (
                    assuranceState.redTeamEvaluation?.blockerDetails || []
                ).map((entry) => ({
                    categoryId: entry.categoryId,
                    roleId: entry.roleId,
                    mandatory: entry.mandatory,
                    assignmentId: entry.assignmentId,
                    reviewId: entry.reviewId,
                    reason: entry.reason,
                })),
                records: redTeamRecords,
            },
            evasionClasses: evasionSummary(
                normalized.assurance,
                semanticRecords,
                redTeamRecords,
            ),
            assuranceValidation: sanitizeAssuranceValidation(assuranceState),
            supplyChain: sanitizeSupplyChain(assuranceState.supplyChainGraph),
        },
        candidateLedgers: {
            semantic: (
                assuranceState.semanticCoverageEvaluation?.candidateLedger || []
            ).map((candidate) => sanitizeCandidate(candidate, "semantic")),
            redTeam: (
                assuranceState.redTeamEvaluation?.candidateLedger || []
            ).map((candidate) => sanitizeCandidate(candidate, "red-team")),
        },
        graph: sanitizeGraph(normalized.graph),
        trace: sanitizeTrace(normalized.trace),
        operatorDecisions: normalizedDecisions,
        blockers: [
            ...normalized.assurance.blockers.map((blocker) => ({
                source: "assurance",
                code: blocker.code,
                evasionClass: blocker.evasionClass,
            })),
            ...(assuranceState.supplyChainGraph?.blockerCodes || []).map((code) => ({
                source: "supply-chain",
                code,
            })),
        ],
    };
    const withManifest = {
        ...base,
        renderManifestSha256: sha256Canonical(renderManifestFor(base)),
    };
    const document = {
        ...withManifest,
        documentId: `ztfindings-${sha256Canonical(withManifest)}`,
    };
    assertSourceTextFree(document);
    return cloneFrozen(document);
}

export function serializeAssuranceFindingsArtifact(document) {
    assertSourceTextFree(document);
    const serialized = `${canonicalJson(document)}\n`;
    if (Buffer.byteLength(serialized, "utf8") > REPORT_LEDGER_LIMITS.findingsBytes) {
        throw new RangeError(
            `FINDINGS.json exceeds ${REPORT_LEDGER_LIMITS.findingsBytes} bytes`,
        );
    }
    return serialized;
}

function escapeMarkdown(value) {
    return String(value)
        .replace(/\\/gu, "\\\\")
        .replace(/([`*_[\]<>|])/gu, "\\$1");
}

function deterministicSummary(document) {
    const counts = document.verdict.severityCounts;
    const active = Object.values(counts).reduce((sum, count) => sum + count, 0);
    return `The validated assurance state produced the findings verdict `
        + `${document.verdict.value}. It contains ${active} supported active finding`
        + `${active === 1 ? "": "s"} (${counts.critical} critical, ${counts.high} high, `
        + `${counts.medium} medium, ${counts.low} low, ${counts.info} info). `
        + `${document.assurance.wording.summary}`;
}

function deterministicRecommendation(document) {
    if (["critical", "high"].includes(document.verdict.value)) {
        return "Do not perform host execution until the supported critical/high behavior is removed or explicitly accepted and a fresh audit finalizes.";
    }
    if (document.verdict.value === "medium") {
        return "Review the supported medium behavior before host execution and re-audit after any change.";
    }
    if (["low", "info"].includes(document.verdict.value)) {
        return "Review the supported low/info behavior and its identity-bound evidence before host execution.";
    }
    return "No supported malicious behavior was established; interpret that verdict only together with the recorded assurance level, basis, and limitations.";
}

function operatorDecisionLines(document) {
    return document.operatorDecisions.map((decision) => {
        const rationale = decision.operatorRationale
            ? `; user-supplied rationale=${escapeMarkdown(decision.operatorRationale.text)}`: "";
        return `- ${decision.findingId}: action=${decision.action}; `
            + `rationale-category=${decision.rationaleCategory}${rationale}`;
    }).join("\n");
}

export function renderAssuranceFindingsMarkdown({ document, findingsSha256 } = {}) {
    if (!/^[a-f0-9]{64}$/u.test(String(findingsSha256 || ""))) {
        throw new TypeError("assurance report rendering requires the FINDINGS.json SHA-256");
    }
    const activeSet = new Set(document.verdict.activeFindingIds);
    const rows = document.graph.findings
        .filter((finding) => activeSet.has(finding.findingId))
        .map((finding) =>
            `| ${finding.findingId} | validated | ${finding.severity} | `
            + `${finding.origin} | ${finding.evidenceIds.length} | `
            + `${finding.nodeIds.length} | ${finding.edgeIds.length} |`)
        .join("\n");
    const evasionRows = document.coverage.evasionClasses.map((entry) =>
        `| ${entry.evasionClass} | ${entry.assuranceCoverage} | `
        + `${entry.semanticCoverageRecords} | ${entry.redTeamCoverageRecords} | `
        + `${entry.assuranceBlockerCodes.join(", ") || "none"} |`).join("\n");
    const supplyBlockers = document.coverage.supplyChain.blockerCodes.length > 0
        ? document.coverage.supplyChain.blockerCodes
            .map((code) => `- ${escapeMarkdown(code)}`).join("\n"): "- none";
    const validation = document.coverage.assuranceValidation;
    const markdown = `# zerotrust-sourcecheck assurance report

- **Audit ID:** ${document.auditId}
- **Mode:** ${document.mode}
- **Findings verdict:** ${document.verdict.value}
- **Trusted findings verdict:** ${document.verdict.trusted}
- **Assurance level:** ${document.assurance.assuranceLevel}
- **Assurance complete:** ${document.assurance.complete}
- **Assurance label:** ${document.assurance.wording.label}
- **Outcome ID:** ${document.verdict.outcomeId}
- **FINDINGS.json SHA-256:** ${findingsSha256}
- **Ledger render SHA-256:** ${document.renderManifestSha256}
- **assurance stage at finalization:** ${document.stage.input}

## Executive summary

${deterministicSummary(document)}

## Findings verdict and assurance

${document.assurance.wording.distinction}

${document.assurance.wording.limitation}

## Validated active findings

<!-- BEGIN Assurance TRUSTED FINDING ROWS -->
| Finding ID | State | Severity | Origin | Evidence IDs | Node IDs | Edge IDs |
|---|---|---|---|---:|---:|---:|
${rows}
<!-- END Assurance TRUSTED FINDING ROWS -->

${rows ? "": "No validated active findings were recorded."}

## assurance stage and coverage

- **Snapshot ID:** ${document.coverage.snapshot.snapshotId}
- **Objects / derived artifacts:** ${document.coverage.snapshot.counts.objects} / ${document.coverage.snapshot.counts.derivedArtifacts}
- **Semantic evaluation:** ${document.coverage.semantic.evaluationId}; complete=${document.coverage.semantic.complete}; truncated=${document.coverage.semantic.truncated}
- **Red-team evaluation:** ${document.coverage.redTeam.evaluationId}; complete=${document.coverage.redTeam.complete}; truncated=${document.coverage.redTeam.truncated}
- **Red-team assignment coverage:** ${document.coverage.redTeam.gates.assignmentCoveragePercent ?? 0}%
- **Semantic / red-team candidates:** ${document.candidateLedgers.semantic.length} / ${document.candidateLedgers.redTeam.length}

## Evasion-class assurance summary

| Evasion class | Assurance coverage | Semantic records | Red-team records | Assurance blockers |
|---|---|---:|---:|---|
${evasionRows}

## Evasive graph and trace

- **Graph ID:** ${document.graph.graphId}
- **Graph nodes / edges / evidence / findings / conflicts:** ${document.graph.counts.nodes} / ${document.graph.counts.edges} / ${document.graph.counts.evidence} / ${document.graph.counts.findings} / ${document.graph.counts.conflicts}
- **Trace ID:** ${document.trace.traceId}
- **Trace roots / traced roots / paths / effect paths / unresolved paths:** ${document.trace.counts.roots} / ${document.trace.counts.tracedRoots} / ${document.trace.counts.paths} / ${document.trace.counts.effectPaths} / ${document.trace.counts.unresolvedPaths}
- **Trace complete:** ${document.trace.complete}

## Assurance validation

- **Plan / evaluation:** ${validation.planId} / ${validation.evaluationId}
- **Mode:** ${validation.mode}
- **Complete:** ${validation.complete}
- **Assignments / records:** ${validation.counts.assignments} / ${validation.counts.records}
- **Validated / refuted / unresolved findings:** ${validation.counts.validatedFindings} / ${validation.counts.refutedFindings} / ${validation.counts.unresolvedFindings}
- **No-finding outcome:** ${validation.noFindingOutcome ?? "n/a"}

## Supply-chain blockers

${supplyBlockers}

## Assurance basis

- **Static coverage:** ${document.assurance.basis.staticCoverage}
- **Supply-chain coverage:** ${document.assurance.basis.supplyChainCoverage}
- **Blocker cap:** ${document.assurance.basis.blockerCap ?? "none"}
- **Analysis scope:** ${document.assurance.basis.analysisScope}
- **Host build evidence:** ${document.assurance.basis.hostBuildEvidence}

## Operator decisions

<!-- BEGIN Assurance STRUCTURED OPERATOR DECISIONS -->
${operatorDecisionLines(document) || "- none"}
<!-- END Assurance STRUCTURED OPERATOR DECISIONS -->

Any rationale above is explicitly user-supplied operator context. It is not assurance evidence and did not affect the findings verdict or assurance computation.

## Recommendation

${deterministicRecommendation(document)}
`;
    if (/\b(?:safe|clean)\b/iu.test(markdown)) {
        throw new TypeError("assurance report wording must not use safe/clean language");
    }
    return markdown;
}

export function assertAssuranceMarkdownFindingsConsistency(markdown, document) {
    const verdicts = [...String(markdown).matchAll(
        /^- \*\*Findings verdict:\*\* (.+)$/gmu,
    )].map((match) => match[1]);
    if (verdicts.length !== 1 || verdicts[0] !== document.verdict.value) {
        throw new TypeError("assurance REPORT.md findings verdict does not match FINDINGS.json");
    }
    const levels = [...String(markdown).matchAll(
        /^- \*\*Assurance level:\*\* (.+)$/gmu,
    )].map((match) => match[1]);
    if (levels.length !== 1 || levels[0] !== document.assurance.assuranceLevel) {
        throw new TypeError("assurance REPORT.md assurance level does not match FINDINGS.json");
    }
    const completion = [...String(markdown).matchAll(
        /^- \*\*Assurance complete:\*\* (true|false)$/gmu,
    )].map((match) => match[1] === "true");
    if (completion.length !== 1 || completion[0] !== document.assurance.complete) {
        throw new TypeError("assurance REPORT.md assurance completion does not match FINDINGS.json");
    }
    if (document.renderManifestSha256 !== sha256Canonical(renderManifestFor(document))) {
        throw new TypeError("assurance FINDINGS.json render manifest is invalid");
    }
    const begin = "<!-- BEGIN Assurance TRUSTED FINDING ROWS -->";
    const end = "<!-- END Assurance TRUSTED FINDING ROWS -->";
    const start = String(markdown).indexOf(begin);
    const finish = String(markdown).indexOf(end);
    if (start < 0 || finish < start) {
        throw new TypeError("assurance REPORT.md finding-row markers are missing");
    }
    const observedRows = String(markdown)
        .slice(start + begin.length, finish)
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.startsWith("|"))
        .slice(2)
        .map((line) => {
            const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
            if (cells.length !== 7) {
                throw new TypeError("assurance REPORT.md finding row has the wrong column count");
            }
            return {
                findingId: cells[0],
                state: cells[1],
                severity: cells[2],
                origin: cells[3],
                evidenceCount: cells[4],
                nodeCount: cells[5],
                edgeCount: cells[6],
            };
        });
    const activeSet = new Set(document.verdict.activeFindingIds);
    const expectedRows = document.graph.findings
        .filter((finding) => activeSet.has(finding.findingId))
        .map((finding) => ({
            findingId: finding.findingId,
            state: "validated",
            severity: finding.severity,
            origin: finding.origin,
            evidenceCount: String(finding.evidenceIds.length),
            nodeCount: String(finding.nodeIds.length),
            edgeCount: String(finding.edgeIds.length),
        }));
    if (canonicalJson(observedRows) !== canonicalJson(expectedRows)) {
        throw new TypeError("assurance REPORT.md finding rows do not match FINDINGS.json");
    }
    const summary = `## Executive summary\n\n${deterministicSummary(document)}`;
    if (!String(markdown).includes(summary)) {
        throw new TypeError("assurance REPORT.md deterministic summary does not match");
    }
    const decisions = "<!-- BEGIN Assurance STRUCTURED OPERATOR DECISIONS -->\n"
        + `${operatorDecisionLines(document) || "- none"}\n`
        + "<!-- END Assurance STRUCTURED OPERATOR DECISIONS -->";
    if (!String(markdown).includes(decisions)) {
        throw new TypeError("assurance REPORT.md operator decisions do not match");
    }
    return true;
}
