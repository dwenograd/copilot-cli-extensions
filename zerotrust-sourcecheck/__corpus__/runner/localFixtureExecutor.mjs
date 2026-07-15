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
    ANALYSIS_SCHEMA_VERSION,
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

export const LOCAL_FINDINGS_ARTIFACT_VERSION = 1;
const MARKER_LINE_RE = /^marker\.(fact|node|edge|finding)\((.*)\);?$/u;
const ARGUMENT_RE = /"([a-z0-9][a-z0-9._:/@,-]{0,127})"/gu;
const SAFE_BYTES_RE = /^[\x09\x0a\x0d\x20-\x7e]*$/u;
const EXPECTED_ARGUMENTS = Object.freeze({
    fact: 3,
    node: 4,
    edge: 5,
    finding: 9,
});

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

function parseMarkerLine(line, { path, lineNumber }) {
    const trimmed = line.trim();
    if (!trimmed) return null;
    const match = MARKER_LINE_RE.exec(trimmed);
    if (!match) throw new Error(`${path}:${lineNumber}: invalid inert marker syntax`);
    const args = [...match[2].matchAll(ARGUMENT_RE)].map((entry) => entry[1]);
    const reconstructed = args.map((entry) => `"${entry}"`).join(",");
    if (reconstructed !== match[2] || args.length !== EXPECTED_ARGUMENTS[match[1]]) {
        throw new Error(`${path}:${lineNumber}: invalid inert marker arguments`);
    }
    return Object.freeze({
        kind: match[1],
        args: Object.freeze(args),
        path,
        line: lineNumber,
        raw: trimmed,
    });
}

function validateFixtureText(text, path) {
    if (!SAFE_BYTES_RE.test(text)) {
        throw new Error(`${path}: fixture must contain printable ASCII only`);
    }
    if (/https?:|file:|data:/iu.test(text)) {
        throw new Error(`${path}: fixture must not contain URLs or payload schemes`);
    }
    const markers = [];
    for (const [index, line] of text.split(/\r?\n/u).entries()) {
        const marker = parseMarkerLine(line, { path, lineNumber: index + 1 });
        if (marker) markers.push(marker);
    }
    return markers;
}

function markerFact(marker) {
    const value = [marker.kind, ...marker.args].join("|");
    const fact = {
        kind: marker.kind === "fact" ? "execution-registration" : "config-key",
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

function buildIndex(fixtureRoot, auditId) {
    const absoluteFiles = walkFiles(fixtureRoot);
    if (absoluteFiles.length === 0) throw new Error("local fixture contains no .ztfixture files");
    const state = createAnalysisIndexState({ auditId, sourceKind: "local-source" });
    const sources = absoluteFiles.map((absolute) => {
        const path = relativePath(fixtureRoot, absolute);
        const text = readFileSync(absolute, "utf8");
        const markers = validateFixtureText(text, path);
        return {
            absolute,
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
    const [
        ,
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
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
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
                ? associated.filter((chain) => chain.status === "complete").map((chain) => chain.id)
                : [],
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
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        artifactVersion: LOCAL_FINDINGS_ARTIFACT_VERSION,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: "corpus-local-v1",
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
        evaluation: {
            counts: {
                candidate: 0,
                validated: 0,
                refuted: 0,
                unresolved: 0,
            },
            failureStage: "prepare",
            failureReason: blockers.map(blockerCode).join(",") || "plugin-coverage-incomplete",
        },
    });
}

export function executeLocalFixture({
    fixtureRoot,
    slug,
    auditId = randomUUID(),
} = {}) {
    if (!fixtureRoot || !statSync(fixtureRoot).isDirectory()) {
        throw new Error("fixtureRoot must be a local fixture directory");
    }
    const sourceNamespace = `corpus:${slug}`;
    const indexed = buildIndex(fixtureRoot, auditId);
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
    return Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        artifactVersion: LOCAL_FINDINGS_ARTIFACT_VERSION,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: "corpus-local-v1",
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
        decision,
        evaluation: {
            counts,
            failureStage: null,
            failureReason: null,
        },
    });
}

export const __internals = Object.freeze({
    walkFiles,
    relativePath,
    parseMarkerLine,
    validateFixtureText,
    markerFact,
    buildIndex,
    findingFromMarker,
    validationSnapshot,
    blockerCode,
    failedArtifact,
    stableId: pluginInternals.stableId,
});
