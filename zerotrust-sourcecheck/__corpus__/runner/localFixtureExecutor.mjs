import { createHash, randomUUID } from "node:crypto";
import {
    readFileSync,
    readdirSync,
    statSync,
} from "node:fs";
import nodePath from "node:path";

import { BehaviorGraph } from "../../analysis/behaviorGraph.mjs";
import { dedupeFindings } from "../../analysis/dedupe.mjs";
import { extractFactsFromText } from "../../analysis/extractFacts.mjs";
import {
    buildAnalysisIndexSnapshot,
    createAnalysisIndexState,
    recordIndexEnumeration,
    recordIndexedFile,
} from "../../analysis/indexState.mjs";
import {
    createPluginRunnerState,
    runAnalysisPlugins,
} from "../../analysis/plugins/runner.mjs";
import {
    ANALYSIS_SCHEMA_REVISION,
    computeFindingId,
} from "../../analysis/schemas.mjs";
import { buildTrustedDecisionSnapshot } from "../../analysis/scoring.mjs";
import { mergeBehaviorGraphs } from "../../analysis/graphMerge.mjs";
import { traceBehaviorGraph } from "../../analysis/traceGraph.mjs";
import {
    FIXTURE_PLUGIN,
    FIXTURE_PLUGIN_ID,
    MARKER_FACT_NAME,
    __internals as pluginInternals,
} from "./fixturePlugin.mjs";
import {
    parseMarkerLine,
    validateFixtureText,
} from "./fixtureSyntax.mjs";
import { applyMetamorphicTransforms } from "./metamorphicTransforms.mjs";

export const LOCAL_FINDINGS_ARTIFACT_SCHEMA_REVISION = 1;

function walkFiles(root) {
    const output = [];
    for (const entry of readdirSync(root, { withFileTypes: true })) {
        const absolute = nodePath.join(root, entry.name);
        if (entry.isDirectory()) output.push(...walkFiles(absolute));
        else if (entry.isFile() && entry.name.endsWith(".ztfixture")) output.push(absolute);
    }
    return output.sort();
}

function relativePath(root, absolute) {
    return nodePath.relative(root, absolute).replace(/\\/gu, "/");
}

function markerFact(marker) {
    const value = [marker.kind, ...marker.args].join("|");
    const fact = {
        kind: marker.kind === "fact" ? "execution-registration": "config-key",
        path: marker.path,
        line: marker.line,
        endLine: marker.line,
        excerptHash: createHash("sha256").update(marker.raw, "utf8").digest("hex"),
        name: MARKER_FACT_NAME,
        value,
    };
    fact.id = createHash("sha256")
        .update(`${fact.kind}\0${fact.path}\0${fact.line}\0${fact.name}\0${fact.value}`)
        .digest("hex");
    return fact;
}

function fixtureDocuments(fixtureRoot) {
    const absoluteFiles = walkFiles(fixtureRoot);
    if (absoluteFiles.length === 0) throw new Error("local fixture contains no .ztfixture files");
    return absoluteFiles.map((absolute) => ({
        path: relativePath(fixtureRoot, absolute),
        text: readFileSync(absolute, "utf8"),
    }));
}

function buildIndex(fixtureRoot, auditId, { transforms = [] } = {}) {
    const documents = fixtureDocuments(fixtureRoot);
    const transformed = transforms.length > 0
        ? applyMetamorphicTransforms(documents, transforms): documents;
    const state = createAnalysisIndexState({ auditId, sourceKind: "local-source" });
    const sources = transformed.map(({ path, text }) => {
        const markers = validateFixtureText(text, path);
        return {
            path,
            text,
            markers,
            size: Buffer.byteLength(text, "utf8"),
            contentSha256: createHash("sha256").update(text, "utf8").digest("hex"),
        };
    });
    recordIndexEnumeration(state, {
        entries: sources.map((source) => ({
            path: source.path,
            size: source.size,
            blobSha: null,
        })),
        complete: true,
    });
    for (const source of sources) {
        const extracted = extractFactsFromText({ path: source.path, text: source.text });
        recordIndexedFile(state, {
            path: source.path,
            size: source.size,
            classification: "text",
            classificationComplete: true,
            contentSha256: source.contentSha256,
            blobSha: null,
            facts: [
                ...extracted.facts,
                ...source.markers.map(markerFact),
            ],
            factsOverflow: extracted.overflow,
            lineCount: Math.max(1, source.text.split(/\r?\n/u).length),
            invisibleUnicodeScanComplete: true,
            invisibleUnicodeMatchCount: 0,
        });
    }
    return { state, sources, markers: sources.flatMap((source) => source.markers) };
}

function findingFromMarker(marker, {
    auditId,
    sourceNamespace,
    indexState,
    graphDocument,
}) {
    const [,
        state,
        severity,
        confidence,
        maliciousProjectFit,
        action,
        capability,
        target,
        tagList,
    ] = marker.args;
    const indexedFile = indexState.files[indexState.fileIndex.get(marker.path)];
    const evidence = {
        path: marker.path,
        startLine: marker.line,
        endLine: marker.line,
        blobSha: indexedFile.blobSha || indexedFile.contentSha256,
        excerptHash: createHash("sha256").update(marker.raw, "utf8").digest("hex"),
        producer: FIXTURE_PLUGIN_ID,
        coverageScope: "local_source",
    };
    const sourceIdentity = {
        type: "local-file",
        namespace: sourceNamespace,
        path: marker.path,
        contentSha256: indexedFile.contentSha256,
        blobSha: indexedFile.blobSha || indexedFile.contentSha256,
    };
    const behaviorSignature = {
        action,
        capability,
        target,
        trigger: "fixture-activation",
    };
    return {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId,
        id: computeFindingId(sourceIdentity, behaviorSignature),
        sourceIdentity,
        behaviorSignature,
        title: "Inert synthetic behavior shape",
        summary: "Evaluation-only generic behavior chain represented by inert marker declarations.",
        severity,
        confidence,
        maliciousProjectFit,
        state,
        evidence: [evidence],
        nodeIds: graphDocument.nodes.map((node) => node.id),
        edgeIds: graphDocument.edges.map((edge) => edge.id),
        producer: FIXTURE_PLUGIN_ID,
        tags: tagList.split(",").filter(Boolean),
    };
}

function validationSnapshot(auditId, findings, traceSnapshot) {
    const adjudications = findings.map((finding) => {
        const nodeIds = new Set(finding.nodeIds);
        const edgeIds = new Set(finding.edgeIds);
        const associated = traceSnapshot.chains.filter((chain) =>
            chain.steps.some((step) => step.nodeIds.some((id) => nodeIds.has(id)))
            || chain.links.some((link) => link.edgeIds.some((id) => edgeIds.has(id))));
        return {
            findingId: finding.id,
            decision: finding.state,
            chainIds: finding.state === "validated"
                ? associated.filter((chain) => chain.status === "complete").map((chain) => chain.id): [],
        };
    });
    return {
        auditId,
        adjudications,
    };
}

function blockerCode(blocker) {
    return blocker?.code || blocker?.kind || "unspecified-blocker";
}

function failedArtifact({
    auditId,
    sourceNamespace,
    indexSnapshot,
    pluginSnapshot,
}) {
    const blockers = pluginSnapshot.blockers.map((entry) => ({
        code: entry.kind || "plugin-failed",
        pluginId: entry.pluginId,
    }));
    return Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        artifactSchemaRevision: LOCAL_FINDINGS_ARTIFACT_SCHEMA_REVISION,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: "corpus-local",
        auditId,
        sourceIdentity: { kind: "local", path: sourceNamespace },
        stage: {
            input: "acquired",
            history: ["acquired"],
            final: "acquired",
        },
        coverage: {
            analysisIndex: indexSnapshot,
            analysisPlugins: pluginSnapshot,
        },
        stateCounts: {
            candidate: 0,
            validating: 0,
            validated: 0,
            refuted: 0,
            unresolved: 0,
        },
        canonicalFindings: [],
        graph: null,
        blockers,
        verdict: {
            value: "incomplete",
            trusted: false,
            deterministic: true,
        },
        assurance: {
            level: "partial",
        },
        evaluation: {
            counts: {
                candidate: 0,
                validated: 0,
                refuted: 0,
                unresolved: 0,
            },
            failureStage: "prepare",
            failureReason: blockers.map(blockerCode).join(",") || "plugin-coverage-incomplete",
            assuranceLevel: "partial",
        },
    });
}

function explicitBlockers(markers) {
    const entries = markers
        .filter((marker) => marker.kind === "blocker")
        .map((marker) => ({
            stage: marker.args[0],
            code: marker.args[1],
        }));
    const stages = new Set(entries.map((entry) => entry.stage));
    if (stages.size > 1) {
        throw new Error("fixture blocker declarations must use one failure stage");
    }
    const stage = entries[0]?.stage || null;
    if (stage && !["prepare", "scan", "trace", "validate", "finalize"].includes(stage)) {
        throw new Error(`invalid fixture blocker stage: ${stage}`);
    }
    return { stage, entries };
}

function finalStageForFailure(stage) {
    return {
        prepare: "acquired",
        scan: "prepared",
        trace: "scanned",
        validate: "traced",
        finalize: "validated",
    }[stage] || "acquired";
}

function withExplicitBlockers(document, blockerState) {
    if (blockerState.entries.length === 0) return document;
    const final = finalStageForFailure(blockerState.stage);
    const history = [
        "acquired",
        "prepared",
        "scanned",
        "traced",
        "validated",
    ];
    const finalIndex = history.indexOf(final);
    const blockers = blockerState.entries.map((entry) => ({
        code: entry.code,
        corpusFixture: true,
    }));
    return Object.freeze({
        ...document,
        stage: {
            input: final,
            history: history.slice(0, finalIndex + 1),
            final,
        },
        blockers: [...document.blockers, ...blockers],
        verdict: {
            value: "incomplete",
            trusted: false,
            deterministic: true,
        },
        assurance: {
            level: "partial",
        },
        evaluation: {
            ...document.evaluation,
            failureStage: blockerState.stage,
            failureReason: blockerState.entries.map((entry) => entry.code).join(","),
            assuranceLevel: "partial",
        },
    });
}

export function executeLocalFixture({
    fixtureRoot,
    slug,
    auditId = randomUUID(),
    transforms = [],
} = {}) {
    if (!fixtureRoot || !statSync(fixtureRoot).isDirectory()) {
        throw new Error("fixtureRoot must be a local fixture directory");
    }
    const sourceNamespace = `corpus:${slug}`;
    const indexed = buildIndex(fixtureRoot, auditId, { transforms });
    const blockerState = explicitBlockers(indexed.markers);
    const indexSnapshot = buildAnalysisIndexSnapshot(indexed.state);
    const behaviorGraph = new BehaviorGraph({ auditId });
    const pluginState = createPluginRunnerState({
        auditId,
        registry: [FIXTURE_PLUGIN],
    });
    const pluginSnapshot = runAnalysisPlugins({
        auditId,
        indexState: indexed.state,
        behaviorGraph,
        state: pluginState,
        sourceNamespace,
        registry: [FIXTURE_PLUGIN],
    });
    if (!pluginSnapshot.coverageComplete) {
        return failedArtifact({
            auditId,
            sourceNamespace,
            indexSnapshot,
            pluginSnapshot,
        });
    }

    const graphDocument = behaviorGraph.toDocument();
    const findings = indexed.markers
        .filter((marker) => marker.kind === "finding")
        .map((marker) => findingFromMarker(marker, {
            auditId,
            sourceNamespace,
            indexState: indexed.state,
            graphDocument,
        }));
    const merged = mergeBehaviorGraphs({
        auditId,
        sourceNamespace,
        indexState: indexed.state,
        graphs: [graphDocument],
        findings,
    });
    const traceSnapshot = traceBehaviorGraph(merged);
    const validation = validationSnapshot(auditId, findings, traceSnapshot);
    const deduped = dedupeFindings({
        auditId,
        findings,
        traceSnapshot,
        validationSnapshot: validation,
    });
    const decision = buildTrustedDecisionSnapshot({
        auditId,
        findings,
        traceSnapshot,
        validationSnapshot: validation,
        dedupeResult: deduped,
        coverage: {
            acquisitionComplete: true,
            indexComplete: indexSnapshot.complete === true,
            pluginCoverageComplete: pluginSnapshot.coverageComplete === true,
            councilComplete: true,
            traceComplete: traceSnapshot.coverageComplete === true,
            validationComplete: true,
            cacheTrackingComplete: true,
        },
    });
    const blockers = [
        ...traceSnapshot.blockers,
        ...decision.blockers,
    ];
    const counts = {
        candidate: findings.length,
        validated: findings.filter((finding) => finding.state === "validated").length,
        refuted: findings.filter((finding) => finding.state === "refuted").length,
        unresolved: findings.filter((finding) => finding.state === "unresolved").length,
    };
    const document = Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        artifactSchemaRevision: LOCAL_FINDINGS_ARTIFACT_SCHEMA_REVISION,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: "corpus-local",
        auditId,
        sourceIdentity: { kind: "local", path: sourceNamespace },
        stage: {
            input: "validated",
            history: [
                "acquired",
                "prepared",
                "scanned",
                "traced",
                "validated",
                "finalized",
            ],
            final: "finalized",
        },
        coverage: {
            decision: decision.coverage,
            analysisIndex: indexSnapshot,
            analysisPlugins: pluginSnapshot,
            validation: {
                requiredFindingIds: findings.map((finding) => finding.id),
                counts: {
                    adjudications: findings.length,
                },
                completion: {
                    complete: true,
                },
            },
        },
        stateCounts: decision.stateCounts,
        severityCounts: decision.severityCounts,
        canonicalFindings: decision.canonicalFindings,
        aliases: decision.aliases,
        graph: traceSnapshot,
        blockers,
        verdict: {
            value: decision.overallVerdictEligibility.recommendedVerdict,
            trusted: decision.overallVerdictEligibility.trustedDecisionEligible,
            deterministic: true,
        },
        assurance: {
            level: "bounded-static",
        },
        decision,
        evaluation: {
            counts,
            failureStage: null,
            failureReason: null,
            assuranceLevel: "bounded-static",
        },
    });
    return withExplicitBlockers(document, blockerState);
}

export const __internals = Object.freeze({
    walkFiles,
    relativePath,
    fixtureDocuments,
    parseMarkerLine,
    validateFixtureText,
    markerFact,
    buildIndex,
    findingFromMarker,
    validationSnapshot,
    blockerCode,
    failedArtifact,
    explicitBlockers,
    finalStageForFailure,
    withExplicitBlockers,
    stableId: pluginInternals.stableId,
});
