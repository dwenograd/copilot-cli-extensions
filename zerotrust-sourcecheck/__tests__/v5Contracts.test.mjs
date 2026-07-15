import { test } from "node:test";
import assert from "node:assert/strict";

import {
    ANALYSIS_SCHEMA_VERSION,
    GRAPH_EDGE_KINDS,
    GRAPH_NODE_KINDS,
    LIMITS,
    BehaviorGraph,
    ContractValidationError,
    FindingLedger,
    computeFindingId,
    normalizeBehaviorSignature,
    validateBehaviorGraphDocument,
    validateCandidateFinding,
    validateEvidenceReference,
    validateGraphEdge,
    validateGraphNode,
    validateMetadataCacheDocument,
    validatePluginOutput,
    validateValidationDecision,
} from "../analysis/index.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";

function evidence(overrides = {}) {
    return {
        path: "src/loader.mjs",
        startLine: 10,
        endLine: 14,
        blobSha: "b".repeat(40),
        excerptHash: "e".repeat(64),
        producer: "static-scanner",
        coverageScope: "mandatory",
        ...overrides,
    };
}

function sourceIdentity(overrides = {}) {
    return {
        type: "git-blob",
        namespace: `github.com/example/repo@${"a".repeat(40)}`,
        path: "src/loader.mjs",
        contentSha256: "c".repeat(64),
        blobSha: "b".repeat(40),
        ...overrides,
    };
}

function behaviorSignature(overrides = {}) {
    return {
        action: "Execute",
        capability: "Process Spawn",
        target: "Shell",
        trigger: "Package Install",
        mechanism: "Child Process",
        qualifiers: ["hidden-window", "encoded-argument"],
        ...overrides,
    };
}

function finding(overrides = {}) {
    const source = overrides.sourceIdentity || sourceIdentity();
    const behavior = overrides.behaviorSignature || behaviorSignature();
    return {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: AUDIT_ID,
        id: computeFindingId(source, behavior),
        sourceIdentity: source,
        behaviorSignature: behavior,
        title: "Install hook launches a hidden shell",
        summary: "A package-install trigger reaches a process-spawn capability.",
        severity: "high",
        confidence: "medium",
        maliciousProjectFit: "likely",
        state: "candidate",
        evidence: [evidence()],
        nodeIds: ["node.trigger", "node.capability"],
        edgeIds: ["edge.trigger-capability"],
        producer: "static-scanner",
        tags: ["process-spawn"],
        ...overrides,
    };
}

function graphNode(id, kind, overrides = {}) {
    return {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: AUDIT_ID,
        id,
        kind,
        label: `${kind} node`,
        producer: "static-scanner",
        evidence: [evidence()],
        ...overrides,
    };
}

function graphEdge(overrides = {}) {
    return {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: AUDIT_ID,
        id: "edge.trigger-capability",
        kind: "triggers",
        from: "node.trigger",
        to: "node.capability",
        producer: "static-scanner",
        evidence: [evidence()],
        ...overrides,
    };
}

function decision(overrides = {}) {
    return {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: AUDIT_ID,
        findingId: finding().id,
        validator: "behavior-validator",
        decision: "validated",
        severity: "critical",
        confidence: "high",
        maliciousProjectFit: "strong",
        rationaleCode: "confirmed-execution-chain",
        rationale: "The trigger, transform, and sink form a complete execution chain.",
        evidence: [evidence({ startLine: 20, endLine: 22, excerptHash: "f".repeat(64) })],
        ...overrides,
    };
}

test("v5 evidence references are bounded pointers and reject embedded source text", () => {
    const normalized = validateEvidenceReference(evidence({ path: "src\\loader.mjs" }));
    assert.equal(normalized.path, "src/loader.mjs");
    assert.equal(normalized.blobSha, "b".repeat(40));
    assert.throws(
        () => validateEvidenceReference({ ...evidence(), sourceText: "malicious()" }),
        ContractValidationError,
    );
    assert.throws(
        () => validateEvidenceReference(evidence({ endLine: LIMITS.line + 1 })),
        /endLine/,
    );
    assert.throws(
        () => validateEvidenceReference(evidence({ excerptHash: "not-a-hash" })),
        /excerptHash/,
    );
});

test("v5 behavior signatures normalize semantic tokens and reject prose/location fields", () => {
    const normalized = normalizeBehaviorSignature({
        action: " Execute ",
        capability: "Process Spawn",
        target: "Shell",
        qualifiers: ["zeta", "alpha"],
    });
    assert.deepEqual(normalized, {
        action: "execute",
        capability: "process-spawn",
        target: "shell",
        qualifiers: ["alpha", "zeta"],
    });
    assert.throws(
        () => normalizeBehaviorSignature({
            action: "execute",
            capability: "process-spawn",
            target: "shell",
            line: 17,
        }),
        /unknown field/,
    );
    assert.throws(
        () => normalizeBehaviorSignature({
            action: "this is prose, not a token",
            capability: "process-spawn",
            target: "shell",
        }),
        /semantic token/,
    );
});

test("v5 finding IDs depend on collision-resistant source identity and normalized behavior only", () => {
    const first = finding();
    const proseAndLinesChanged = finding({
        title: "Different prose",
        summary: "Different explanation",
        evidence: [evidence({ startLine: 900, endLine: 901 })],
    });
    assert.equal(first.id, proseAndLinesChanged.id);
    assert.equal(validateCandidateFinding(proseAndLinesChanged).id, first.id);

    const reordered = behaviorSignature({
        qualifiers: ["encoded-argument", "hidden-window"],
    });
    assert.equal(
        computeFindingId(sourceIdentity(), behaviorSignature()),
        computeFindingId(sourceIdentity(), reordered),
    );
    assert.notEqual(
        first.id,
        computeFindingId(sourceIdentity({ contentSha256: "d".repeat(64) }), behaviorSignature()),
    );
    assert.notEqual(
        first.id,
        computeFindingId(sourceIdentity(), behaviorSignature({ target: "browser" })),
    );
});

test("v5 candidate findings strictly separate severity, confidence, and malicious project-fit", () => {
    const normalized = validateCandidateFinding(finding());
    assert.equal(normalized.severity, "high");
    assert.equal(normalized.confidence, "medium");
    assert.equal(normalized.maliciousProjectFit, "likely");
    assert.throws(
        () => validateCandidateFinding(finding({ confidence: "critical" })),
        /confidence/,
    );
    assert.throws(
        () => validateCandidateFinding(finding({ id: `ztf-v5-${"0".repeat(64)}` })),
        /must be derived/,
    );
    assert.throws(
        () => validateCandidateFinding({ ...finding(), unexpected: true }),
        /unknown field/,
    );
    assert.throws(
        () => validateCandidateFinding(finding({
            evidence: Array.from({ length: LIMITS.evidencePerItem + 1 }, () => evidence()),
        })),
        /at most/,
    );
});

test("v5 graph contracts enumerate every node kind and reject unknown edge kinds", () => {
    for (const [index, kind] of GRAPH_NODE_KINDS.entries()) {
        const node = validateGraphNode(graphNode(`node.kind-${index}`, kind));
        assert.equal(node.kind, kind);
    }
    for (const [index, kind] of GRAPH_EDGE_KINDS.entries()) {
        const edge = validateGraphEdge(graphEdge({
            id: `edge.kind-${index}`,
            kind,
        }));
        assert.equal(edge.kind, kind);
    }
    assert.throws(
        () => validateGraphNode(graphNode("node.bad", "command")),
        /must be one of/,
    );
    assert.throws(
        () => validateGraphEdge(graphEdge({ kind: "related-to" })),
        /must be one of/,
    );
});

test("v5 graph documents enforce unique IDs, audit binding, and valid endpoints", () => {
    const document = validateBehaviorGraphDocument({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: AUDIT_ID,
        nodes: [
            graphNode("node.trigger", "trigger"),
            graphNode("node.capability", "capability"),
        ],
        edges: [graphEdge()],
    });
    assert.equal(document.nodes.length, 2);
    assert.equal(document.edges.length, 1);
    assert.throws(
        () => validateBehaviorGraphDocument({
            ...document,
            edges: [graphEdge({ to: "node.missing" })],
        }),
        /unknown node/,
    );
    assert.throws(
        () => validateBehaviorGraphDocument({
            ...document,
            nodes: [graphNode("node.trigger", "trigger"), graphNode("node.trigger", "sink")],
        }),
        /duplicate node id/,
    );
});

test("BehaviorGraph is bounded, audit-bound, and idempotent only for identical entries", () => {
    const graph = new BehaviorGraph({ auditId: AUDIT_ID, maxNodes: 2, maxEdges: 1 });
    graph.addNode(graphNode("node.trigger", "trigger"));
    graph.addNode(graphNode("node.trigger", "trigger"));
    graph.addNode(graphNode("node.capability", "capability"));
    graph.addEdge(graphEdge());
    assert.equal(graph.nodeCount, 2);
    assert.equal(graph.edgeCount, 1);
    assert.throws(
        () => graph.addNode(graphNode("node.trigger", "sink")),
        /conflicting/,
    );
    assert.throws(
        () => graph.addEdge(graphEdge({ id: "edge.missing", to: "node.missing" })),
        /unknown node/,
    );
    assert.equal(graph.toDocument().auditId, AUDIT_ID);
});

test("validation decisions are strict and finding ledger enforces legal state transitions", () => {
    const ledger = new FindingLedger({ auditId: AUDIT_ID });
    const candidate = ledger.addCandidate(finding());
    assert.equal(candidate.state, "candidate");
    assert.throws(
        () => ledger.applyValidationDecision(decision()),
        /not in validating state/,
    );
    assert.throws(
        () => ledger.beginValidation(candidate.id, {
            auditId: "22222222-2222-4222-8222-222222222222",
        }),
        /does not match/,
    );
    ledger.beginValidation(candidate.id, { auditId: AUDIT_ID });
    const validated = ledger.applyValidationDecision(
        validateValidationDecision(decision()),
    );
    assert.equal(validated.state, "validated");
    assert.equal(validated.severity, "critical");
    assert.equal(validated.confidence, "high");
    assert.equal(validated.maliciousProjectFit, "strong");
    assert.equal(validated.evidence.length, 2);
    assert.throws(
        () => ledger.beginValidation(candidate.id, { auditId: AUDIT_ID }),
        /illegal finding state transition/,
    );
});

test("unresolved findings may be explicitly revalidated but validated/refuted findings are terminal", () => {
    const ledger = new FindingLedger({ auditId: AUDIT_ID });
    const candidate = ledger.addCandidate(finding());
    ledger.beginValidation(candidate.id, { auditId: AUDIT_ID });
    ledger.applyValidationDecision(decision({
        decision: "unresolved",
        severity: "medium",
        confidence: "low",
        maliciousProjectFit: "ambiguous",
    }));
    assert.equal(ledger.getFinding(candidate.id).state, "unresolved");
    assert.equal(
        ledger.beginValidation(candidate.id, { auditId: AUDIT_ID }).state,
        "validating",
    );
});

test("metadata cache documents are bounded typed records with canonical timestamps", () => {
    const document = validateMetadataCacheDocument({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: AUDIT_ID,
        namespace: "npm.registry",
        key: "package.example",
        sourceIdentity: sourceIdentity({ type: "dependency", path: "example@1.0.0" }),
        producer: "dependency-plugin",
        capturedAt: "2026-07-14T00:00:00.000Z",
        expiresAt: "2026-07-15T00:00:00.000Z",
        entries: [
            { key: "deprecated", type: "boolean", value: false },
            { key: "maintainers", type: "string-list", value: ["alice", "bob"] },
        ],
    });
    assert.equal(document.entries.length, 2);
    assert.throws(
        () => validateMetadataCacheDocument({
            ...document,
            entries: [
                { key: "duplicate", type: "boolean", value: true },
                { key: "duplicate", type: "boolean", value: false },
            ],
        }),
        /duplicate key/,
    );
    assert.throws(
        () => validateMetadataCacheDocument({
            ...document,
            capturedAt: "2026-07-14",
        }),
        /canonical ISO-8601/,
    );
});

test("plugin output validates every nested contract, bounds output, and requires candidate state", () => {
    const output = validatePluginOutput({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: AUDIT_ID,
        pluginId: "builtin.behavior",
        pluginVersion: "5.0.0",
        producer: "builtin.behavior",
        coverageScope: "mandatory",
        nodes: [
            graphNode("node.trigger", "trigger"),
            graphNode("node.capability", "capability"),
        ],
        edges: [graphEdge()],
        findings: [finding()],
        validationDecisions: [],
        metadataDocuments: [],
        warnings: [],
    });
    assert.equal(output.findings.length, 1);
    assert.throws(
        () => validatePluginOutput({
            ...output,
            findings: [finding({ state: "validated" })],
        }),
        /must start in candidate state/,
    );
    assert.throws(
        () => validatePluginOutput({
            ...output,
            warnings: Array.from(
                { length: LIMITS.pluginWarnings + 1 },
                () => "bounded warning",
            ),
        }),
        /at most/,
    );
    assert.throws(
        () => validatePluginOutput({ ...output, rawSource: "do not accept" }),
        /unknown field/,
    );
});

