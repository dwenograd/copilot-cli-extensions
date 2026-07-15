import { createHash } from "node:crypto";
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import {
    BehaviorGraph,
    computeFindingId,
    mergeBehaviorGraphs,
    traceBehaviorGraph,
} from "../analysis/index.mjs";
import {
    __internals as enforcementInternals,
    activateAudit,
    advanceAnalysisStage,
    getAnalysisStageState,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
    traceAnalysisGraph,
} from "../enforcement.mjs";
import {
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import {
    mutateCouncilLedgerState,
    __internals as stateInternals,
} from "../safeWrappers/state.mjs";
import { traceBehaviorGraphHandler } from "../safeWrappers/traceWrapper.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_AUDIT_ID = "22222222-2222-4222-8222-222222222222";
const NAMESPACE = `github.com/example/repo@${"a".repeat(40)}`;
const PRODUCER = "static-scanner";

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function sha1(value) {
    return createHash("sha1").update(value).digest("hex");
}

function indexedFixture(paths) {
    const files = [];
    const facts = [];
    const byPath = new Map();
    for (const [index, path] of paths.entries()) {
        const contentSha256 = sha256(`content:${path}`);
        const blobSha = sha1(`blob:${path}`);
        const excerptHash = sha256(`excerpt:${path}`);
        const fact = {
            id: sha256(`fact:${path}`),
            kind: "sink-hint",
            path,
            line: 1,
            endLine: 1,
            excerptHash,
            name: "behavior",
        };
        files.push({
            path,
            size: index + 1,
            blobSha,
            status: "indexed-text",
            classification: "text",
            contentSha256,
            lineCount: 10,
        });
        facts.push(fact);
        byPath.set(path, { contentSha256, blobSha, excerptHash });
    }
    return {
        state: {
            auditId: AUDIT_ID,
            sourceKind: "api-direct",
            files,
            facts,
        },
        byPath,
    };
}

function sourceIdentity(path, fixture, overrides = {}) {
    const identity = fixture.byPath.get(path);
    return {
        type: "git-blob",
        namespace: NAMESPACE,
        path,
        contentSha256: identity.contentSha256,
        blobSha: identity.blobSha,
        ...overrides,
    };
}

function evidence(path, fixture, overrides = {}) {
    const identity = fixture.byPath.get(path);
    return {
        path,
        startLine: 1,
        endLine: 1,
        blobSha: identity.blobSha,
        excerptHash: identity.excerptHash,
        producer: PRODUCER,
        coverageScope: "mandatory",
        ...overrides,
    };
}

function node(id, kind, path, fixture, {
    label = `${kind} prose`,
    tags = [],
    producer = PRODUCER,
    includeIdentity = true,
    includeEvidence = true,
    behaviorSignature,
    auditId = AUDIT_ID,
} = {}) {
    return {
        schemaVersion: 5,
        auditId,
        id,
        kind,
        label,
        producer,
        evidence: includeEvidence ? [evidence(path, fixture, { producer })] : [],
        ...(includeIdentity ? { sourceIdentity: sourceIdentity(path, fixture) } : {}),
        ...(behaviorSignature ? { behaviorSignature } : {}),
        ...(tags.length > 0 ? { tags } : {}),
    };
}

function edge(id, kind, from, to, path, fixture, {
    producer = PRODUCER,
    includeEvidence = true,
    auditId = AUDIT_ID,
    tags = [],
} = {}) {
    return {
        schemaVersion: 5,
        auditId,
        id,
        kind,
        from,
        to,
        producer,
        evidence: includeEvidence ? [evidence(path, fixture, { producer })] : [],
        ...(tags.length > 0 ? { tags } : {}),
    };
}

function graph(nodes, edges, auditId = AUDIT_ID) {
    return {
        schemaVersion: 5,
        auditId,
        nodes,
        edges,
    };
}

function mergeAndTrace(document, fixture, options = {}) {
    const merged = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [document],
        ...options,
    });
    return { merged, traced: traceBehaviorGraph(merged, options.traceOptions) };
}

function addLinearChain(builder, fixture, {
    prefix,
    specs,
    edgeKinds,
}) {
    const ids = specs.map((_, index) => `${prefix}.n${index}`);
    for (const [index, spec] of specs.entries()) {
        builder.nodes.push(node(ids[index], spec.kind, spec.path, fixture, {
            tags: spec.tags,
        }));
    }
    for (let index = 0; index < edgeKinds.length; index += 1) {
        builder.edges.push(edge(
            `${prefix}.e${index}`,
            edgeKinds[index],
            ids[index],
            ids[index + 1],
            specs[index].path,
            fixture,
        ));
    }
}

test("traces all prioritized named chains and preserves explicit cross-file topology", () => {
    const paths = [
        "install.json", "fetch.mjs", "decode.mjs", "execute.mjs",
        "credential.mjs", "transform.mjs", "send.mjs",
        "startup.mjs", "persist.mjs",
        "instruction.mjs", "tool.mjs", "filesystem.mjs",
        "workflow.yml", "secret.yml", "external.yml",
    ];
    const fixture = indexedFixture(paths);
    const builder = { nodes: [], edges: [] };
    addLinearChain(builder, fixture, {
        prefix: "install",
        specs: [
            { kind: "activation", path: "install.json", tags: ["package-install"] },
            { kind: "transform", path: "fetch.mjs", tags: ["remote-fetch"] },
            { kind: "transform", path: "decode.mjs", tags: ["base64-decode"] },
            { kind: "sink", path: "execute.mjs", tags: ["process-spawn", "execute"] },
        ],
        edgeKinds: ["invokes", "transforms", "flows-to"],
    });
    addLinearChain(builder, fixture, {
        prefix: "credential",
        specs: [
            { kind: "activation", path: "credential.mjs", tags: ["runtime"] },
            { kind: "sensitive-source", path: "credential.mjs", tags: ["credential-read"] },
            { kind: "transform", path: "transform.mjs", tags: ["encode-transform"] },
            { kind: "sink", path: "send.mjs", tags: ["external-send"] },
        ],
        edgeKinds: ["reads-from", "flows-to", "flows-to"],
    });
    addLinearChain(builder, fixture, {
        prefix: "startup",
        specs: [
            { kind: "trigger", path: "startup.mjs", tags: ["startup"] },
            { kind: "capability", path: "startup.mjs", tags: ["process-spawn"] },
            { kind: "persistence", path: "persist.mjs", tags: ["scheduled-task"] },
        ],
        edgeKinds: ["triggers", "persists-as"],
    });
    addLinearChain(builder, fixture, {
        prefix: "ai",
        specs: [
            { kind: "trigger", path: "instruction.mjs", tags: ["ai-instruction"] },
            { kind: "capability", path: "tool.mjs", tags: ["tool-invocation"] },
            { kind: "sink", path: "filesystem.mjs", tags: ["filesystem-write"] },
        ],
        edgeKinds: ["triggers", "flows-to"],
    });
    addLinearChain(builder, fixture, {
        prefix: "ci",
        specs: [
            { kind: "trigger", path: "workflow.yml", tags: ["github-actions", "workflow"] },
            { kind: "sensitive-source", path: "secret.yml", tags: ["secret-reference"] },
            { kind: "sink", path: "external.yml", tags: ["external-webhook"] },
        ],
        edgeKinds: ["reads-from", "flows-to"],
    });

    const { merged, traced } = mergeAndTrace(
        graph(builder.nodes, builder.edges),
        fixture,
    );
    assert.equal(merged.coverageComplete, true);
    assert.equal(traced.coverageComplete, true);
    assert.deepEqual(
        traced.chains.map((chain) => chain.pattern),
        [
            "install-fetch-decode-execute",
            "credential-read-transform-send",
            "startup-persistence",
            "ai-instruction-tool-effect",
            "ci-trigger-secret-external-sink",
        ],
    );
    assert.ok(traced.chains.every((chain) => chain.status === "complete"));
    assert.ok(traced.chains.every((chain) => chain.crossFile));
    assert.ok(traced.chains.every((chain) => /^ztc-v5-[a-f0-9]{64}$/u.test(chain.id)));
});

test("chain IDs ignore labels, producers, and model-selected graph IDs", () => {
    const fixture = indexedFixture(["a.mjs", "b.mjs", "c.mjs"]);
    const makeGraph = (prefix, producer, prose) => graph([
        node(`${prefix}.start`, "activation", "a.mjs", fixture, {
            producer,
            label: `${prose} activation`,
            tags: ["package-install"],
        }),
        node(`${prefix}.cap`, "capability", "b.mjs", fixture, {
            producer,
            label: `${prose} capability`,
            tags: ["process-spawn"],
        }),
        node(`${prefix}.sink`, "sink", "c.mjs", fixture, {
            producer,
            label: `${prose} sink`,
            tags: ["execute"],
        }),
    ], [
        edge(`${prefix}.e1`, "invokes", `${prefix}.start`, `${prefix}.cap`, "a.mjs", fixture, {
            producer,
        }),
        edge(`${prefix}.e2`, "flows-to", `${prefix}.cap`, `${prefix}.sink`, "b.mjs", fixture, {
            producer,
        }),
    ]);
    const first = mergeAndTrace(makeGraph("one", "role-one", "alarming prose"), fixture);
    const second = mergeAndTrace(makeGraph("two", "role-two", "benign prose"), fixture);
    assert.equal(first.traced.chains[0].id, second.traced.chains[0].id);
    assert.doesNotMatch(JSON.stringify(first.traced), /alarming prose/u);
});

test("duplicate graph inputs and repeated traces are idempotent", () => {
    const fixture = indexedFixture(["a.mjs", "b.mjs"]);
    const document = graph([
        node("n.start", "activation", "a.mjs", fixture, { tags: ["startup"] }),
        node("n.persist", "persistence", "b.mjs", fixture, { tags: ["autostart"] }),
    ], [
        edge("e.persist", "triggers", "n.start", "n.persist", "a.mjs", fixture),
    ]);
    const merged = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [document, structuredClone(document)],
    });
    const first = traceBehaviorGraph(merged);
    const second = traceBehaviorGraph(merged);
    assert.equal(merged.counts.inputGraphs, 2);
    assert.equal(merged.counts.uniqueGraphs, 1);
    assert.equal(merged.counts.nodes, 2);
    assert.equal(merged.counts.edges, 1);
    assert.deepEqual(second, first);
});

test("deterministic plugin seeds and council fragments merge without inventing connecting edges", () => {
    const fixture = indexedFixture(["plugin.mjs", "council.mjs"]);
    const plugin = graph([
        node("plugin.start", "activation", "plugin.mjs", fixture, {
            tags: ["package-install"],
            producer: "builtin.node-lifecycle",
        }),
        node("plugin.cap", "capability", "plugin.mjs", fixture, {
            tags: ["package-lifecycle"],
            producer: "builtin.node-lifecycle",
        }),
    ], [
        edge(
            "plugin.edge",
            "invokes",
            "plugin.start",
            "plugin.cap",
            "plugin.mjs",
            fixture,
            { producer: "builtin.node-lifecycle" },
        ),
    ]);
    const council = graph([
        node("council.start", "trigger", "council.mjs", fixture, {
            tags: ["startup"],
            producer: "council-role",
        }),
        node("council.cap", "capability", "council.mjs", fixture, {
            tags: ["process-spawn"],
            producer: "council-role",
        }),
        node("council.persist", "persistence", "council.mjs", fixture, {
            tags: ["scheduled-task"],
            producer: "council-role",
        }),
    ], [
        edge(
            "council.e1",
            "triggers",
            "council.start",
            "council.cap",
            "council.mjs",
            fixture,
            { producer: "council-role" },
        ),
        edge(
            "council.e2",
            "persists-as",
            "council.cap",
            "council.persist",
            "council.mjs",
            fixture,
            { producer: "council-role" },
        ),
    ]);
    const merged = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [
            { kind: "plugin", document: plugin },
            { kind: "council", document: council },
        ],
    });
    const traced = traceBehaviorGraph(merged);
    assert.equal(merged.coverageComplete, true);
    assert.equal(merged.counts.mergedGraphs, 2);
    assert.equal(traced.counts.chains, 2);
    assert.ok(traced.chains.some((chain) => chain.pattern === "startup-persistence"));
    assert.ok(traced.chains.some((chain) =>
        chain.status === "unresolved"
        && chain.steps.some((step) => step.nodeIds.includes("plugin.start"))));
    assert.ok(traced.chains.every((chain) =>
        !(chain.steps.some((step) => step.nodeIds.includes("plugin.start"))
            && chain.steps.some((step) => step.nodeIds.includes("council.persist")))));
});

test("council fragments inherit exact source/evidence identity from their findings", () => {
    const fixture = indexedFixture(["candidate.mjs"]);
    const producer = "council-role";
    const ref = evidence("candidate.mjs", fixture, {
        producer,
        coverageScope: "council_sample",
    });
    const source = sourceIdentity("candidate.mjs", fixture);
    const behaviorSignature = {
        trigger: "package-install",
        capability: "process-spawn",
        action: "execute",
        target: "shell",
    };
    const nodes = [
        node("c.start", "activation", "candidate.mjs", fixture, {
            producer,
            includeIdentity: false,
            includeEvidence: false,
        }),
        node("c.cap", "capability", "candidate.mjs", fixture, {
            producer,
            includeIdentity: false,
            includeEvidence: false,
        }),
        node("c.sink", "sink", "candidate.mjs", fixture, {
            producer,
            includeIdentity: false,
            includeEvidence: false,
        }),
    ];
    const edges = [
        edge("c.e1", "activates", "c.start", "c.cap", "candidate.mjs", fixture, {
            producer,
            includeEvidence: false,
        }),
        edge("c.e2", "flows-to", "c.cap", "c.sink", "candidate.mjs", fixture, {
            producer,
            includeEvidence: false,
        }),
    ];
    const finding = {
        schemaVersion: 5,
        auditId: AUDIT_ID,
        id: computeFindingId(source, behaviorSignature),
        sourceIdentity: source,
        behaviorSignature,
        title: "candidate",
        summary: "candidate behavior",
        severity: "high",
        confidence: "medium",
        maliciousProjectFit: "likely",
        state: "candidate",
        evidence: [ref],
        nodeIds: nodes.map((entry) => entry.id),
        edgeIds: edges.map((entry) => entry.id),
        producer,
        tags: ["candidate"],
    };
    const merged = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [graph(nodes, edges)],
        findings: [finding],
    });
    const traced = traceBehaviorGraph(merged);
    assert.equal(merged.coverageComplete, true);
    assert.equal(traced.coverageComplete, true);
    assert.equal(traced.chains[0].status, "complete");
    assert.deepEqual(traced.chains[0].evidence, [{
        path: "candidate.mjs",
        startLine: 1,
        endLine: 1,
        blobSha: fixture.byPath.get("candidate.mjs").blobSha,
        excerptHash: fixture.byPath.get("candidate.mjs").excerptHash,
    }]);
});

test("contradictory and incompatible edges are quarantined for validation", () => {
    const fixture = indexedFixture(["a.mjs", "b.mjs", "c.mjs"]);
    const document = graph([
        node("n.start", "activation", "a.mjs", fixture),
        node("n.transform", "transform", "b.mjs", fixture),
        node("n.cap", "capability", "c.mjs", fixture),
        node("n.sink", "sink", "c.mjs", fixture),
    ], [
        edge("e.start", "activates", "n.start", "n.transform", "a.mjs", fixture),
        edge("e.forward", "flows-to", "n.transform", "n.cap", "b.mjs", fixture),
        edge("e.reverse", "flows-to", "n.cap", "n.transform", "c.mjs", fixture),
        edge("e.invalid", "flows-to", "n.sink", "n.start", "c.mjs", fixture),
    ]);
    const { merged, traced } = mergeAndTrace(document, fixture);
    assert.equal(merged.coverageComplete, false);
    assert.equal(traced.coverageComplete, false);
    assert.ok(merged.conflicts.some((entry) =>
        entry.reasonCode === "contradictory-edge-direction"));
    assert.ok(merged.conflicts.some((entry) =>
        entry.reasonCode === "incompatible-edge-transition"));
    assert.ok(traced.validationQueue.length >= 2);
    assert.ok(traced.chains.every((chain) =>
        !chain.links.some((link) =>
            link.edgeIds.includes("e.forward")
            || link.edgeIds.includes("e.reverse")
            || link.edgeIds.includes("e.invalid"))));
});

test("cycles remain bounded unresolved chains without making trace accounting incomplete", () => {
    const fixture = indexedFixture(["a.mjs", "b.mjs", "c.mjs"]);
    const document = graph([
        node("n.start", "activation", "a.mjs", fixture),
        node("n.cap", "capability", "b.mjs", fixture),
        node("n.transform", "transform", "c.mjs", fixture),
    ], [
        edge("e.start", "activates", "n.start", "n.cap", "a.mjs", fixture),
        edge("e.next", "invokes", "n.cap", "n.transform", "b.mjs", fixture),
        edge("e.cycle", "flows-to", "n.transform", "n.cap", "c.mjs", fixture),
    ]);
    const { merged, traced } = mergeAndTrace(document, fixture);
    assert.equal(merged.coverageComplete, true);
    assert.equal(traced.coverageComplete, true);
    assert.equal(traced.counts.cycles, 1);
    assert.equal(traced.chains[0].status, "unresolved");
    assert.deepEqual(traced.chains[0].unresolvedReasons, ["cycle-detected"]);
});

test("missing referenced nodes and identity mismatches make merge coverage incomplete", () => {
    const fixture = indexedFixture(["a.mjs", "b.mjs"]);
    const missing = graph([
        node("n.start", "activation", "a.mjs", fixture),
    ], [
        edge("e.missing", "flows-to", "n.start", "n.absent", "a.mjs", fixture),
    ]);
    const missingResult = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [missing],
    });
    assert.equal(missingResult.coverageComplete, false);
    assert.equal(missingResult.counts.unresolvedReferences, 1);

    const mismatched = graph([
        node("n.start", "activation", "a.mjs", fixture, {
            behaviorSignature: {
                action: "execute",
                capability: "process-spawn",
                target: "shell",
            },
        }),
        node("n.sink", "sink", "b.mjs", fixture, {
            tags: ["execute"],
        }),
    ], [
        edge("e.sink", "flows-to", "n.start", "n.sink", "a.mjs", fixture),
    ]);
    mismatched.nodes[0].sourceIdentity.namespace = "github.com/other/repo@"
        + "b".repeat(40);
    const mismatchResult = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [mismatched],
    });
    assert.equal(mismatchResult.coverageComplete, false);
    assert.ok(mismatchResult.counts.identityMismatches >= 1);

    const evidenceMismatch = graph([
        node("n.evidence", "activation", "a.mjs", fixture),
    ], []);
    evidenceMismatch.nodes[0].evidence[0].excerptHash = "f".repeat(64);
    const evidenceMismatchResult = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [evidenceMismatch],
    });
    assert.equal(evidenceMismatchResult.coverageComplete, false);
    assert.ok(evidenceMismatchResult.blockers.some((blocker) =>
        blocker.reasonCode === "evidence-reference-not-indexed"));

    const auditMismatch = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [graph([
            node("n.other", "activation", "a.mjs", fixture, {
                auditId: OTHER_AUDIT_ID,
            }),
        ], [], OTHER_AUDIT_ID)],
    });
    assert.equal(auditMismatch.coverageComplete, false);
    assert.equal(auditMismatch.counts.mergedGraphs, 0);
});

test("graph and chain caps are explicit truncation blockers", () => {
    const fixture = indexedFixture(["a.mjs", "b.mjs", "c.mjs"]);
    const document = graph([
        node("n.start", "activation", "a.mjs", fixture),
        node("n.one", "sink", "b.mjs", fixture),
        node("n.two", "sink", "c.mjs", fixture),
    ], [
        edge("e.one", "flows-to", "n.start", "n.one", "a.mjs", fixture),
        edge("e.two", "flows-to", "n.start", "n.two", "a.mjs", fixture),
    ]);
    const nodeCapped = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [document],
        limits: { nodes: 2 },
    });
    assert.equal(nodeCapped.coverageComplete, false);
    assert.equal(nodeCapped.truncation.nodes, true);

    const graphCapped = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [
            graph([node("g1.start", "activation", "a.mjs", fixture)], []),
            graph([node("g2.start", "activation", "b.mjs", fixture)], []),
        ],
        limits: { graphs: 1 },
    });
    assert.equal(graphCapped.coverageComplete, false);
    assert.equal(graphCapped.truncation.graphs, true);

    const edgeCapped = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [document],
        limits: { edges: 1 },
    });
    assert.equal(edgeCapped.coverageComplete, false);
    assert.equal(edgeCapped.truncation.edges, true);

    const merged = mergeBehaviorGraphs({
        auditId: AUDIT_ID,
        sourceNamespace: NAMESPACE,
        indexState: fixture.state,
        graphs: [document],
    });
    const chainCapped = traceBehaviorGraph(merged, {
        limits: { chains: 1 },
    });
    assert.equal(chainCapped.coverageComplete, false);
    assert.equal(chainCapped.truncation.chains, true);
    assert.equal(chainCapped.chains.length, 1);
});

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

function buildLocalIndex(sessionId, path = "src/a.mjs") {
    const text = "const value = 1;";
    const excerptHash = sha256("const");
    const fact = {
        id: sha256(`sink-hint\0${path}\0${1}\0behavior\0`),
        kind: "sink-hint",
        path,
        line: 1,
        endLine: 1,
        excerptHash,
        name: "behavior",
    };
    mutateAnalysisIndexState(sessionId, (state) => {
        recordIndexEnumeration(state, {
            entries: [{ path, size: Buffer.byteLength(text), blobSha: null }],
            complete: true,
        });
        recordIndexedFile(state, {
            path,
            size: Buffer.byteLength(text),
            classification: "text",
            classificationComplete: true,
            contentSha256: sha256(text),
            blobSha: null,
            facts: [fact],
            lineCount: 1,
            invisibleUnicodeScanComplete: true,
        });
    });
    return {
        path,
        contentSha256: sha256(text),
        excerptHash,
    };
}

function councilFinding(auditId, indexed, producer = "trace-role") {
    const source = {
        type: "local-file",
        namespace: `local-audit:${auditId}`,
        path: indexed.path,
        contentSha256: indexed.contentSha256,
        blobSha: indexed.contentSha256,
    };
    const ref = {
        path: indexed.path,
        startLine: 1,
        endLine: 1,
        blobSha: indexed.contentSha256,
        excerptHash: indexed.excerptHash,
        producer,
        coverageScope: "local_source",
    };
    const behaviorSignature = {
        trigger: "startup",
        capability: "process-spawn",
        action: "persist",
        target: "scheduled-task",
        persistence: "scheduled-task",
    };
    const nodes = [
        {
            schemaVersion: 5,
            auditId,
            id: "trace.start",
            kind: "activation",
            label: "start",
            producer,
            evidence: [],
        },
        {
            schemaVersion: 5,
            auditId,
            id: "trace.cap",
            kind: "capability",
            label: "capability",
            producer,
            evidence: [],
        },
        {
            schemaVersion: 5,
            auditId,
            id: "trace.persist",
            kind: "persistence",
            label: "persistence",
            producer,
            evidence: [],
        },
    ];
    const edges = [
        {
            schemaVersion: 5,
            auditId,
            id: "trace.e1",
            kind: "activates",
            from: "trace.start",
            to: "trace.cap",
            producer,
            evidence: [],
        },
        {
            schemaVersion: 5,
            auditId,
            id: "trace.e2",
            kind: "persists-as",
            from: "trace.cap",
            to: "trace.persist",
            producer,
            evidence: [],
        },
    ];
    return {
        nodes,
        edges,
        finding: {
            schemaVersion: 5,
            auditId,
            id: computeFindingId(source, behaviorSignature),
            sourceIdentity: source,
            behaviorSignature,
            title: "startup persistence",
            summary: "startup reaches persistence",
            severity: "high",
            confidence: "medium",
            maliciousProjectFit: "likely",
            state: "candidate",
            evidence: [ref],
            nodeIds: nodes.map((entry) => entry.id),
            edgeIds: edges.map((entry) => entry.id),
            producer,
            tags: ["persistence"],
        },
    };
}

beforeEach(() => {
    enforcementInternals.activeAudits.clear();
    stateInternals.councilLedgers.clear();
});

test("trace stage exposes blockers before scan and advances scanned to traced idempotently", async () => {
    const sessionId = "v5-behavior-stage";
    const role = { id: "trace-role", category: "A", mandatory: true };
    const auditId = activateAudit({
        sessionId,
        buildPath: process.cwd(),
        mode: "audit_local_source_council",
        localPath: process.platform === "win32" ? "C:\\source\\trace" : "/source/trace",
        expectedReportPath: process.platform === "win32"
            ? `${process.cwd()}\\_reports\\local-trace-20260713235500`
            : `${process.cwd()}/_reports/local-trace-20260713235500`,
        councilRoleManifest: [role],
    });
    const indexed = buildLocalIndex(sessionId);
    assert.equal(maybeAdvanceAnalysisPrepared(sessionId).analysisStageState.current, "prepared");
    const early = parse(await traceBehaviorGraphHandler({
        audit_id: auditId,
    }, { sessionId }));
    assert.equal(early.ok, true);
    assert.equal(early.coverageComplete, false);
    assert.equal(early.analysisStageAfter, "prepared");
    assert.ok(early.blockers.some((blocker) => blocker.code === "scan-stage-incomplete"));

    const candidate = councilFinding(auditId, indexed);
    mutateCouncilLedgerState(sessionId, {
        auditId,
        roles: [role],
    }, (state) => {
        for (const entry of candidate.nodes) state.behaviorGraph.addNode(entry);
        for (const entry of candidate.edges) state.behaviorGraph.addEdge(entry);
        state.findingLedger.addCandidate(candidate.finding);
        state.submissions.set(role.id, {
            digest: "d".repeat(64),
            candidateCount: 1,
            coveragePerformedCount: 1,
            findingIds: [candidate.finding.id],
        });
        state.finalization = {
            successfulRoleIds: [role.id],
            failedRoleIds: [],
            deterministicBaselineComplete: true,
            digest: "f".repeat(64),
        };
    });
    advanceAnalysisStage(sessionId, {
        auditId,
        from: "prepared",
        to: "scanned",
    });
    const first = parse(await traceBehaviorGraphHandler({
        audit_id: auditId,
    }, { sessionId }));
    assert.equal(first.ok, true);
    assert.equal(first.coverageComplete, true);
    assert.equal(first.analysisStageAfter, "traced");
    assert.equal(first.chains[0].pattern, "startup-persistence");
    assert.equal(getAnalysisStageState(sessionId).current, "traced");

    const second = traceAnalysisGraph(sessionId, { auditId });
    assert.equal(second.idempotent, true);
    assert.equal(second.chains[0].id, first.chains[0].id);
});

test("scanned cannot advance to traced through the generic stage API without trace gates", () => {
    const sessionId = "v5-behavior-stage-gate";
    const auditId = activateAudit({
        sessionId,
        buildPath: process.cwd(),
        mode: "audit_local_source_council",
        localPath: process.platform === "win32" ? "C:\\source\\trace-gate" : "/source/trace-gate",
        expectedReportPath: process.platform === "win32"
            ? `${process.cwd()}\\_reports\\local-trace-gate-20260713235500`
            : `${process.cwd()}/_reports/local-trace-gate-20260713235500`,
        councilRoleManifest: [{ id: "trace-role", category: "A", mandatory: true }],
    });
    buildLocalIndex(sessionId);
    maybeAdvanceAnalysisPrepared(sessionId);
    advanceAnalysisStage(sessionId, {
        auditId,
        from: "prepared",
        to: "scanned",
    });
    assert.throws(
        () => advanceAnalysisStage(sessionId, {
            auditId,
            from: "scanned",
            to: "traced",
        }),
        /analysis trace incomplete/u,
    );
});

test("trace wrapper rejects audit identity mismatch", async () => {
    const sessionId = "v5-behavior-identity";
    activateAudit({
        sessionId,
        buildPath: process.cwd(),
        mode: "audit_local_source_council",
        localPath: process.platform === "win32" ? "C:\\source\\identity" : "/source/identity",
        expectedReportPath: process.platform === "win32"
            ? `${process.cwd()}\\_reports\\local-identity-20260713235500`
            : `${process.cwd()}/_reports/local-identity-20260713235500`,
        councilRoleManifest: [{ id: "trace-role", category: "A", mandatory: true }],
    });
    const result = parse(await traceBehaviorGraphHandler({
        audit_id: OTHER_AUDIT_ID,
    }, { sessionId }));
    assert.equal(result.ok, false);
    assert.match(result.error, /does not match/u);
});
