import { createHash } from "node:crypto";
import { afterEach, test } from "node:test";
import assert from "node:assert/strict";

import { BehaviorGraph } from "../analysis/behaviorGraph.mjs";
import { buildCachePayload } from "../analysis/cache.mjs";
import { extractFactsFromText } from "../analysis/extractFacts.mjs";
import { __internals as reportLedgerInternals } from "../analysis/reportLedger.mjs";
import {
    createAnalysisIndexState,
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import {
    PLUGIN_REGISTRY,
    buildPluginCacheRecords,
    createPluginRunnerState,
    runAnalysisPlugins,
    validatePluginFact,
} from "../analysis/plugins/index.mjs";
import {
    __internals as enforcementInternals,
    activateAudit,
    getAnalysisPluginSnapshot,
    getAnalysisPluginCacheRecords,
    getAnalysisStageState,
    getBehaviorGraphDocument,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
    recordResolvedSha,
} from "../enforcement.mjs";
import { buildInstructionPacket } from "../packet.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const COMMIT = "a".repeat(40);

const SOURCES = Object.freeze({
    "package.json": JSON.stringify({
        scripts: {
            postinstall: "powershell -EncodedCommand REDACTED",
        },
        activationEvents: ["onStartupFinished"],
        contributes: { commands: [{ command: "sample.run" }] },
    }, null, 2),
    ".github/workflows/release.yml": [
        "on:",
        "  pull_request_target:",
        "jobs:",
        "  build:",
        "    uses: actions/checkout@v4",
        "    run: powershell ./publish.ps1",
    ].join("\n"),
    "pyproject.toml": [
        "[build-system]",
        'build-backend = "setuptools.build_meta"',
    ].join("\n"),
    "Cargo.toml": [
        "[package]",
        'build = "build.rs"',
    ].join("\n"),
    "build.rs": 'fn main() { Command::new("sh"); }',
    "sample.csproj": [
        '<Project Sdk="Microsoft.NET.Sdk">',
        '  <Target Name="BeforeBuild">',
        '    <Exec Command="powershell ./build.ps1" />',
        "  </Target>",
        "</Project>",
    ].join("\n"),
    "scripts/install.ps1": 'Start-Process("cmd.exe")',
    "Makefile": "all:\n\t@echo build",
    ".devcontainer/devcontainer.json": JSON.stringify({
        build: { dockerfile: "Dockerfile" },
        postCreateCommand: "npm install",
    }, null, 2),
});

function buildIndex({
    auditId = AUDIT_ID,
    sourceKind = "api-direct",
    sources = SOURCES,
} = {}) {
    const state = createAnalysisIndexState({ auditId, sourceKind });
    const entries = Object.entries(sources).map(([path, text], index) => ({
        path,
        size: Buffer.byteLength(text),
        blobSha: createHash("sha1").update(`blob-${index}`).digest("hex"),
    }));
    recordIndexEnumeration(state, { entries, complete: true });
    for (const [index, [path, text]] of Object.entries(sources).entries()) {
        const extraction = extractFactsFromText({ path, text });
        recordIndexedFile(state, {
            path,
            size: Buffer.byteLength(text),
            classification: "text",
            classificationComplete: true,
            contentSha256: createHash("sha256").update(text).digest("hex"),
            blobSha: entries[index].blobSha,
            facts: extraction.facts,
            factsOverflow: extraction.overflow,
            lineCount: extraction.lineCount,
            invisibleUnicodeScanComplete: true,
        });
    }
    return state;
}

afterEach(() => {
    enforcementInternals.activeAudits.clear();
});

test("built-in registry covers all required deterministic activation ecosystems", () => {
    assert.deepEqual(
        PLUGIN_REGISTRY.map((plugin) => plugin.id),
        [
            "builtin.cargo-build",
            "builtin.cmake-make",
            "builtin.container-devcontainer",
            "builtin.dotnet-msbuild",
            "builtin.extension-activation",
            "builtin.github-actions",
            "builtin.node-lifecycle",
            "builtin.python-packaging",
            "builtin.shell-launch",
        ],
    );
});

test("runner consumes normalized manifests/facts and emits only evidence-bound graph seeds", () => {
    const indexState = buildIndex();
    const graph = new BehaviorGraph({ auditId: AUDIT_ID });
    const state = createPluginRunnerState({ auditId: AUDIT_ID });
    const first = runAnalysisPlugins({
        auditId: AUDIT_ID,
        indexState,
        behaviorGraph: graph,
        state,
        sourceNamespace: `github.com/example/repo@${COMMIT}`,
    });

    assert.equal(first.coverageComplete, true);
    assert.equal(first.counts.registered, 9);
    assert.equal(first.counts.detected, 9);
    assert.ok(first.plugins.every((plugin) =>
        plugin.completed && !plugin.failed && !plugin.truncated));
    assert.ok(first.plugins.every((plugin) => plugin.warningCount >= 1));
    assert.ok(first.plugins.every((plugin) => plugin.factCount >= 1));
    assert.equal(first.factCount, first.facts.length);
    assert.equal(first.factsTruncated, false);
    assert.ok(first.facts.every((fact) =>
        fact.pluginId && fact.kind && fact.name && fact.path && fact.excerptHash));
    assert.ok(first.facts.every((fact) =>
        !Object.hasOwn(fact, "sourceText") && !Object.hasOwn(fact, "snippet")));
    const reportPlugins = reportLedgerInternals.compactPlugins(first);
    assert.equal(reportPlugins.factCount, first.factCount);
    assert.ok(reportPlugins.facts.every((fact) =>
        fact.id
        && fact.kind
        && fact.pluginId
        && fact.pluginVersion
        && fact.producer === fact.pluginId
        && fact.sourceIdentity
        && fact.path
        && fact.excerptHash));
    assert.ok(reportPlugins.facts.every((fact) =>
        !Object.hasOwn(fact, "name") && !Object.hasOwn(fact, "value")));
    const cacheRecords = buildPluginCacheRecords(state);
    assert.ok(cacheRecords.every((record) =>
        Object.keys(record).sort().join(",")
            === "edges,facts,findings,nodes,pluginId,pluginVersion,sourceBlobs,validationDecisions"));
    assert.ok(state.plugins.flatMap((record) => record.facts)
        .every((fact) => validatePluginFact(fact).id === fact.id));
    const cachePayload = buildCachePayload({
        sourceIdentity: {
            kind: "github",
            owner: "example",
            repo: "repo",
            sourceSha: COMMIT,
        },
        indexState,
        stageState: {
            current: "prepared",
            history: ["acquired", "prepared"],
        },
        pluginRecords: cacheRecords,
    });
    assert.equal(cachePayload.pluginRecords.length, 9);

    const document = graph.toDocument();
    assert.ok(document.nodes.length >= 18);
    assert.ok(document.edges.length >= 9);
    for (const entry of [...document.nodes, ...document.edges]) {
        assert.equal(entry.auditId, AUDIT_ID);
        assert.ok(entry.evidence.length >= 1);
        for (const evidence of entry.evidence) {
            assert.match(evidence.blobSha, /^[a-f0-9]{40}$/u);
            assert.match(evidence.excerptHash, /^[a-f0-9]{64}$/u);
            assert.equal(evidence.coverageScope, "mandatory");
        }
    }
    assert.ok(document.nodes.every((node) =>
        node.sourceIdentity?.contentSha256?.length === 64));
    const serialized = JSON.stringify(document);
    assert.doesNotMatch(serialized, /EncodedCommand REDACTED|sourceText|rawSource|verdict/iu);
    const factEvidence = new Set(cacheRecords.flatMap((record) =>
        record.facts.flatMap((fact) => fact.evidence.map((evidence) =>
            JSON.stringify(evidence)))));
    assert.ok([...document.nodes, ...document.edges].every((entry) =>
        entry.evidence.every((evidence) => factEvidence.has(JSON.stringify(evidence)))));
    assert.doesNotMatch(
        JSON.stringify(cacheRecords),
        /EncodedCommand REDACTED|sourceText|rawSource|verdict/iu,
    );

    const second = runAnalysisPlugins({
        auditId: AUDIT_ID,
        indexState,
        behaviorGraph: graph,
        state,
        sourceNamespace: `github.com/example/repo@${COMMIT}`,
    });
    assert.equal(second.runCount, 1);
    assert.equal(graph.nodeCount, document.nodes.length);
    assert.equal(graph.edgeCount, document.edges.length);
});

test("detected ecosystem overflow is independently recorded as a preparation gap", () => {
    const indexState = buildIndex({
        sources: { "package.json": SOURCES["package.json"] },
    });
    const nodePlugin = PLUGIN_REGISTRY.filter((plugin) =>
        plugin.id === "builtin.node-lifecycle");
    const graph = new BehaviorGraph({ auditId: AUDIT_ID });
    const state = createPluginRunnerState({
        auditId: AUDIT_ID,
        registry: nodePlugin,
    });
    const result = runAnalysisPlugins({
        auditId: AUDIT_ID,
        indexState,
        behaviorGraph: graph,
        state,
        registry: nodePlugin,
        sourceNamespace: `github.com/example/repo@${COMMIT}`,
        limits: { nodesPerPlugin: 1, edgesPerPlugin: 1 },
    });

    assert.equal(result.coverageComplete, false);
    assert.equal(result.plugins[0].supported, true);
    assert.equal(result.plugins[0].detected, true);
    assert.equal(result.plugins[0].completed, false);
    assert.equal(result.plugins[0].failed, false);
    assert.equal(result.plugins[0].truncated, true);
    assert.match(result.blockers[0].kind, /truncated/u);
});

test("enforcement runs plugins before acquired advances to prepared", () => {
    const sessionId = "v5-plugin-enforcement";
    activateAudit({
        sessionId,
        buildPath: process.cwd(),
        mode: "audit_source",
        expectedClonePath: `${process.cwd()}\\unused`,
        owner: "example",
        repo: "repo",
    });
    assert.equal(recordResolvedSha(sessionId, COMMIT), true);
    const audit = enforcementInternals.activeAudits.get(sessionId);
    const text = SOURCES["package.json"];
    const extraction = extractFactsFromText({ path: "package.json", text });
    mutateAnalysisIndexState(sessionId, (indexState) => {
        recordIndexEnumeration(indexState, {
            entries: [{
                path: "package.json",
                size: Buffer.byteLength(text),
                blobSha: "b".repeat(40),
            }],
            complete: true,
        });
        recordIndexedFile(indexState, {
            path: "package.json",
            size: Buffer.byteLength(text),
            classification: "text",
            classificationComplete: true,
            contentSha256: createHash("sha256").update(text).digest("hex"),
            blobSha: "b".repeat(40),
            facts: extraction.facts,
            factsOverflow: extraction.overflow,
            lineCount: extraction.lineCount,
            invisibleUnicodeScanComplete: true,
        });
    });

    assert.equal(audit.analysisStageState.current, "acquired");
    const prepared = maybeAdvanceAnalysisPrepared(sessionId);
    assert.equal(prepared.analysisPlugins.coverageComplete, true);
    assert.equal(prepared.analysisPlugins.counts.detected, 2);
    assert.equal(prepared.analysisStageState.current, "prepared");
    assert.equal(getAnalysisStageState(sessionId).current, "prepared");
    assert.ok(getBehaviorGraphDocument(sessionId).nodes.length > 0);
    assert.equal(getAnalysisPluginSnapshot(sessionId).runCount, 1);
    assert.ok(getAnalysisPluginCacheRecords(sessionId)
        .every((record) => record.facts.every((fact) =>
            fact.sourceIdentity.path === "package.json")));
});

test("packets pin plugin coverage, no-verdict behavior, and prepared-stage boundary", () => {
    const packet = buildInstructionPacket({
        mode: "audit_source",
        parsed: {
            owner: "example",
            repo: "repo",
            kind: "repo",
            canonicalUrl: "https://github.com/example/repo",
            ref: null,
        },
        buildRoot: process.cwd(),
        expectedClonePath: `${process.cwd()}\\unused`,
        auditId: AUDIT_ID,
        focusWrapped: "",
        injectionPreamble: "",
        injectionWarnings: [],
        scrubNote: "",
        privateRepoAck: true,
        placeholderSha: false,
        subAgentInstruction: "",
    });

    assert.match(packet, /analysisPlugins\.coverageComplete === true/u);
    assert.match(packet, /seeds the active BehaviorGraph/u);
    assert.match(packet, /never receive or emit source text, findings, validation decisions, or verdicts/u);
    assert.match(packet, /remains at stage `prepared`/u);
});
