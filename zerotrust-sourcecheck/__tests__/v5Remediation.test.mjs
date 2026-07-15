import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
    FindingLedger,
    computeFindingId,
    generateRemediationPlan,
    validateRemediationPlan,
} from "../analysis/index.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const NAMESPACE = `github.com/example/repo@${"a".repeat(40)}`;

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function evidence(path = "src/entry.mjs", line = 10) {
    return {
        path,
        startLine: line,
        endLine: line,
        blobSha: "b".repeat(40),
        excerptHash: sha256(`${path}:${line}`),
        producer: "static-scanner",
        coverageScope: "mandatory",
    };
}

function chain({
    id,
    edgeIds,
    nodePrefix = id,
    effectNodeId = `${nodePrefix}.effect`,
    path = "src/entry.mjs",
    status = "complete",
}) {
    const links = edgeIds.map((edgeId, index) => ({
        kind: index === 0 ? "activates" : "flows-to",
        edgeIds: [edgeId],
        evidence: [evidence(path, 10 + index)],
    }));
    return {
        id,
        pattern: "behavior-chain",
        status,
        steps: [
            {
                kind: "activation",
                nodeIds: [`${nodePrefix}.activation`],
                paths: [path],
                tags: [],
                evidence: [evidence(path, 10)],
            },
            ...(edgeIds.length > 1 ? [{
                kind: "capability",
                nodeIds: [`${nodePrefix}.capability`],
                paths: [path],
                tags: [],
                evidence: [evidence(path, 11)],
            }] : []),
            {
                kind: "sink",
                nodeIds: [effectNodeId],
                paths: [path],
                tags: [],
                evidence: [evidence(path, 12)],
            },
        ],
        links,
        evidence: [evidence(path, 10)],
        effectKinds: ["sink"],
        unresolvedReasons: status === "complete" ? [] : ["no-explicit-effect-edge"],
    };
}

function canonicalFinding({
    canonicalId,
    findingId,
    stateClass = "validated",
    chainIds = [],
    validatedChainIds = chainIds,
    trustedValidatedChain = stateClass === "validated",
    path = "src/entry.mjs",
}) {
    return {
        canonicalId,
        title: "DO-NOT-PERSIST source-derived title",
        summary: "DO-NOT-PERSIST source-derived summary",
        signature: {
            activationVector: "package-install",
            capability: "process-spawn",
            effect: { action: "execute", target: "shell" },
            graphNeighborhood: [],
        },
        stateClass,
        aliases: [{
            findingId,
            state: stateClass,
            severity: "high",
            confidence: "high",
            maliciousProjectFit: "likely",
            sourcePath: path,
            producer: "static-scanner",
            chainIds,
            completeChainIds: chainIds,
            validationChainIds: validatedChainIds,
            validatedChainIds,
        }],
        evidence: [evidence(path)],
        chainIds,
        validatedChainIds,
        truncation: {
            aliases: false,
            evidence: false,
            paths: false,
            producers: false,
            chains: false,
            nodeIds: false,
            edgeIds: false,
        },
        scores: { trustedValidatedChain },
    };
}

function decisionSnapshot(canonicalFindings) {
    return {
        schemaVersion: 5,
        auditId: AUDIT_ID,
        decisionId: `ztd-v5-${sha256("decision")}`,
        canonicalFindings,
    };
}

function traceSnapshot(chains, {
    coverageComplete = true,
    truncation = {},
} = {}) {
    return {
        schemaVersion: 5,
        auditId: AUDIT_ID,
        inputFingerprint: sha256("trace"),
        coverageComplete,
        truncation: {
            chains: false,
            branches: false,
            depth: false,
            cycles: false,
            validationItems: false,
            evidence: false,
            paths: false,
            semanticBindings: false,
            ...truncation,
        },
        chains,
    };
}

test("minimal edge break targets one evidence-bound edge and clears the known chain", () => {
    const findingId = `ztf-v5-${"1".repeat(64)}`;
    const complete = chain({
        id: "chain.minimal",
        edgeIds: ["edge.activate", "edge.effect"],
    });
    const plan = generateRemediationPlan({
        auditId: AUDIT_ID,
        decisionSnapshot: decisionSnapshot([
            canonicalFinding({
                canonicalId: "canonical.minimal",
                findingId,
                chainIds: [complete.id],
            }),
        ]),
        traceSnapshot: traceSnapshot([complete]),
    });

    assert.equal(plan.candidates.length, 1);
    assert.deepEqual(plan.candidates[0].target.edgeIds, ["edge.effect"]);
    assert.ok(plan.candidates[0].target.evidence.length > 0);
    assert.deepEqual(
        Object.keys(plan.candidates[0].target.evidence[0]).sort(),
        ["blobSha", "endLine", "excerptHash", "path", "startLine"],
    );
    assert.equal(
        plan.candidates[0].staticVerification.outcome,
        "breaks-all-known-chains",
    );
    assert.equal(plan.candidates[0].staticVerification.maliciousChainRemains, false);
    assert.equal(plan.candidates[0].staticVerification.fixClaimAllowed, true);
    assert.doesNotMatch(JSON.stringify(plan), /DO-NOT-PERSIST/u);
});

test("alternate activation-to-effect path prevents a fixed claim", () => {
    const first = chain({
        id: "chain.first",
        edgeIds: ["edge.first.activate", "edge.first.effect"],
        nodePrefix: "first",
        effectNodeId: "shared.effect",
    });
    const alternate = chain({
        id: "chain.alternate",
        edgeIds: ["edge.alt.activate", "edge.alt.effect"],
        nodePrefix: "alternate",
        effectNodeId: "shared.effect",
        path: "src/alternate.mjs",
    });
    const plan = generateRemediationPlan({
        auditId: AUDIT_ID,
        decisionSnapshot: decisionSnapshot([
            canonicalFinding({
                canonicalId: "canonical.alternate",
                findingId: `ztf-v5-${"2".repeat(64)}`,
                chainIds: [first.id, alternate.id],
            }),
        ]),
        traceSnapshot: traceSnapshot([first, alternate]),
    });

    const candidate = plan.candidates[0];
    assert.equal(candidate.staticVerification.outcome, "alternate-path-remains");
    assert.equal(candidate.staticVerification.maliciousChainRemains, true);
    assert.equal(candidate.staticVerification.fixClaimAllowed, false);
    assert.equal(candidate.staticVerification.alternateChainIds.length, 1);
});

test("shared edge records high legitimate-functionality risk", () => {
    const target = chain({
        id: "chain.target",
        edgeIds: ["edge.shared"],
        nodePrefix: "target",
        effectNodeId: "target.effect",
    });
    const legitimate = chain({
        id: "chain.legitimate",
        edgeIds: ["edge.shared"],
        nodePrefix: "legitimate",
        effectNodeId: "legitimate.effect",
        path: "src/legitimate.mjs",
    });
    const plan = generateRemediationPlan({
        auditId: AUDIT_ID,
        decisionSnapshot: decisionSnapshot([
            canonicalFinding({
                canonicalId: "canonical.shared-risk",
                findingId: `ztf-v5-${"3".repeat(64)}`,
                chainIds: [target.id],
            }),
        ]),
        traceSnapshot: traceSnapshot([target, legitimate]),
    });

    assert.equal(plan.candidates[0].legitimateFunctionalityRisk.level, "high");
    assert.deepEqual(
        plan.candidates[0].legitimateFunctionalityRisk.riskCodes,
        ["shared-with-other-complete-chain"],
    );
    assert.deepEqual(
        plan.candidates[0].legitimateFunctionalityRisk.sharedChainIds,
        [legitimate.id],
    );
});

test("unresolved finding gets investigation guidance and refuted finding gets nothing", () => {
    const unresolved = canonicalFinding({
        canonicalId: "canonical.unresolved",
        findingId: `ztf-v5-${"4".repeat(64)}`,
        stateClass: "unresolved",
        chainIds: [],
        validatedChainIds: [],
        trustedValidatedChain: false,
    });
    const refuted = canonicalFinding({
        canonicalId: "canonical.refuted",
        findingId: `ztf-v5-${"5".repeat(64)}`,
        stateClass: "refuted",
        chainIds: [],
        validatedChainIds: [],
        trustedValidatedChain: false,
    });
    const plan = generateRemediationPlan({
        auditId: AUDIT_ID,
        decisionSnapshot: decisionSnapshot([unresolved, refuted]),
        traceSnapshot: traceSnapshot([]),
    });

    assert.equal(plan.candidates.length, 0);
    assert.equal(plan.investigationGuidance.length, 1);
    assert.equal(
        plan.investigationGuidance[0].canonicalFindingId,
        unresolved.canonicalId,
    );
    assert.equal(plan.investigationGuidance[0].confidentPatchAllowed, false);
    assert.ok(!JSON.stringify(plan).includes(refuted.canonicalId));
});

test("incomplete graph never authorizes a fixed claim", () => {
    const complete = chain({
        id: "chain.incomplete-coverage",
        edgeIds: ["edge.incomplete"],
    });
    const plan = generateRemediationPlan({
        auditId: AUDIT_ID,
        decisionSnapshot: decisionSnapshot([
            canonicalFinding({
                canonicalId: "canonical.incomplete",
                findingId: `ztf-v5-${"6".repeat(64)}`,
                chainIds: [complete.id],
            }),
        ]),
        traceSnapshot: traceSnapshot([complete], {
            coverageComplete: false,
            truncation: { branches: true },
        }),
    });

    assert.equal(plan.coverageComplete, false);
    assert.equal(plan.candidates[0].staticVerification.outcome, "graph-incomplete");
    assert.equal(plan.candidates[0].staticVerification.maliciousChainRemains, null);
    assert.equal(plan.candidates[0].staticVerification.fixClaimAllowed, false);
});

test("ledger remediation is idempotent and duplicate candidates are refused", () => {
    const sourceIdentity = {
        type: "git-blob",
        namespace: NAMESPACE,
        path: "src/entry.mjs",
        contentSha256: sha256("content"),
        blobSha: "b".repeat(40),
    };
    const behaviorSignature = {
        trigger: "package-install",
        capability: "process-spawn",
        action: "execute",
        target: "shell",
    };
    const findingId = computeFindingId(sourceIdentity, behaviorSignature);
    const ledger = new FindingLedger({ auditId: AUDIT_ID });
    ledger.addCandidate({
        schemaVersion: 5,
        auditId: AUDIT_ID,
        id: findingId,
        sourceIdentity,
        behaviorSignature,
        title: "Validated behavior chain",
        summary: "A complete chain reaches an execution effect.",
        severity: "high",
        confidence: "high",
        maliciousProjectFit: "likely",
        state: "candidate",
        evidence: [evidence()],
        nodeIds: ["node.activation", "node.effect"],
        edgeIds: ["edge.ledger"],
        producer: "static-scanner",
    });
    ledger.beginValidation(findingId, { auditId: AUDIT_ID });
    ledger.applyValidationDecision({
        schemaVersion: 5,
        auditId: AUDIT_ID,
        findingId,
        validator: "validation-adjudicator",
        decision: "validated",
        severity: "high",
        confidence: "high",
        maliciousProjectFit: "likely",
        rationaleCode: "validated-complete-chain",
        rationale: "Independent static validation established the complete chain.",
        evidence: [evidence()],
    });
    const complete = chain({
        id: "chain.ledger",
        edgeIds: ["edge.ledger"],
    });
    const plan = generateRemediationPlan({
        auditId: AUDIT_ID,
        decisionSnapshot: decisionSnapshot([
            canonicalFinding({
                canonicalId: "canonical.ledger",
                findingId,
                chainIds: [complete.id],
            }),
        ]),
        traceSnapshot: traceSnapshot([complete]),
    });

    assert.equal(ledger.setRemediationPlan(plan).idempotent, false);
    assert.equal(ledger.setRemediationPlan(plan).idempotent, true);
    assert.equal(ledger.toDocument().remediation.id, plan.id);
    assert.throws(() => validateRemediationPlan({
        ...plan,
        candidates: [plan.candidates[0], plan.candidates[0]],
    }), /duplicate candidate id/u);
});
