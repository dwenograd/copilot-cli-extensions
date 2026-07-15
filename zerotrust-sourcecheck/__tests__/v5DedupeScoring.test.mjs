import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
    buildTrustedDecisionSnapshot,
    computeFindingId,
    dedupeFindings,
    scoreCanonicalFinding,
} from "../analysis/index.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const COMPLETE_COVERAGE = Object.freeze({
    acquisitionComplete: true,
    indexComplete: true,
    pluginCoverageComplete: true,
    councilComplete: true,
    traceComplete: true,
    validationComplete: true,
    cacheTrackingComplete: true,
});

function source(path, fill) {
    return {
        type: "git-blob",
        namespace: `github.com/example/repo@${"a".repeat(40)}`,
        path,
        contentSha256: fill.repeat(64),
        blobSha: fill.repeat(40),
    };
}

function behavior(overrides = {}) {
    return {
        trigger: "package-install",
        capability: "process-spawn",
        action: "execute",
        target: "shell",
        ...overrides,
    };
}

function evidence(path, fill, producer) {
    return {
        path,
        startLine: 10,
        endLine: 10,
        blobSha: fill.repeat(40),
        excerptHash: fill.repeat(64),
        producer,
        coverageScope: "council_sample",
    };
}

function finding({
    path,
    fill,
    producer,
    behaviorSignature = behavior(),
    state = "validated",
    severity = "high",
    confidence = "medium",
    maliciousProjectFit = "likely",
    suffix,
    title = "Same prose is deliberately irrelevant",
} = {}) {
    const sourceIdentity = source(path, fill);
    return {
        schemaVersion: 5,
        auditId: AUDIT_ID,
        id: computeFindingId(sourceIdentity, behaviorSignature),
        sourceIdentity,
        behaviorSignature,
        title,
        summary: "Line numbers and narrative wording do not define dedupe identity.",
        severity,
        confidence,
        maliciousProjectFit,
        state,
        evidence: [evidence(path, fill, producer)],
        nodeIds: [`${suffix}.activation`, `${suffix}.capability`, `${suffix}.effect`],
        edgeIds: [`${suffix}.activates`, `${suffix}.flows`],
        producer,
    };
}

function chain(suffix, {
    status = "complete",
    pattern = "install-fetch-decode-execute",
    effectKinds = ["sink"],
    unresolvedReasons = [],
} = {}) {
    return {
        id: `chain.${suffix}`,
        pattern,
        priority: 1,
        status,
        crossFile: false,
        steps: [
            { kind: "activation", nodeIds: [`${suffix}.activation`] },
            { kind: "capability", nodeIds: [`${suffix}.capability`] },
            { kind: "sink", nodeIds: [`${suffix}.effect`] },
        ],
        links: [
            { kind: "activates", edgeIds: [`${suffix}.activates`] },
            { kind: "flows-to", edgeIds: [`${suffix}.flows`] },
        ],
        evidence: [],
        paths: [],
        effectKinds,
        unresolvedReasons,
        validationIds: [],
    };
}

function trace(chains) {
    return {
        schemaVersion: 5,
        auditId: AUDIT_ID,
        inputFingerprint: "trace-fingerprint",
        coverageComplete: true,
        truncation: {},
        chains,
    };
}

function validation(findings, chainsBySuffix = {}) {
    return {
        schemaVersion: 5,
        auditId: AUDIT_ID,
        inputFingerprint: "validation-fingerprint",
        adjudications: findings
            .filter((entry) => entry.state === "validated" || entry.state === "refuted")
            .map((entry) => {
                const suffix = entry.nodeIds[0].split(".")[0];
                return {
                    findingId: entry.id,
                    decision: entry.state,
                    chainIds: entry.state === "validated" && chainsBySuffix[suffix]
                        ? [chainsBySuffix[suffix].id]
                        : [],
                };
            }),
    };
}

test("semantic duplicates across files merge by behavior and graph neighborhood", () => {
    const first = finding({
        path: "src/install.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "one",
    });
    const second = finding({
        path: "lib/bootstrap.mjs",
        fill: "c",
        producer: "role-two",
        suffix: "two",
        title: "Completely different prose",
    });
    const firstChain = chain("one");
    const secondChain = chain("two");
    const result = dedupeFindings({
        auditId: AUDIT_ID,
        findings: [first, second],
        traceSnapshot: trace([firstChain, secondChain]),
        validationSnapshot: validation(
            [first, second],
            { one: firstChain, two: secondChain },
        ),
    });
    assert.equal(result.counts.canonicalFindings, 1);
    assert.equal(result.counts.aliasesMerged, 1);
    assert.deepEqual(
        result.canonicalFindings[0].independentPaths,
        ["lib/bootstrap.mjs", "src/install.mjs"],
    );
    assert.equal(result.canonicalFindings[0].provenance.crossValidationCount, 2);
});

test("similar prose with materially different behavior does not merge", () => {
    const shell = finding({
        path: "src/a.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "one",
    });
    const browser = finding({
        path: "src/b.mjs",
        fill: "c",
        producer: "role-two",
        suffix: "two",
        behaviorSignature: behavior({ target: "browser" }),
    });
    const result = dedupeFindings({
        auditId: AUDIT_ID,
        findings: [shell, browser],
        traceSnapshot: trace([chain("one"), chain("two")]),
    });
    assert.equal(result.counts.canonicalFindings, 2);
});

test("severe singleton remains severe without consensus averaging", () => {
    const singleton = finding({
        path: "src/only.mjs",
        fill: "b",
        producer: "solo-role",
        suffix: "solo",
        severity: "critical",
    });
    const onlyChain = chain("solo");
    const snapshot = buildTrustedDecisionSnapshot({
        auditId: AUDIT_ID,
        findings: [singleton],
        traceSnapshot: trace([onlyChain]),
        validationSnapshot: validation([singleton], { solo: onlyChain }),
        coverage: COMPLETE_COVERAGE,
    });
    assert.equal(
        snapshot.canonicalFindings[0].scores.impactSeverity.level,
        "critical",
    );
    assert.equal(snapshot.overallVerdictEligibility.recommendedVerdict, "critical");
});

test("contradictory or contested chains are not merged", () => {
    const complete = finding({
        path: "src/complete.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "one",
        state: "unresolved",
    });
    const contested = finding({
        path: "src/contested.mjs",
        fill: "c",
        producer: "role-two",
        suffix: "two",
        state: "unresolved",
    });
    const result = dedupeFindings({
        auditId: AUDIT_ID,
        findings: [complete, contested],
        traceSnapshot: trace([
            chain("one"),
            chain("two", {
                status: "contested",
                unresolvedReasons: ["conflicting-edge"],
            }),
        ]),
    });
    assert.equal(result.counts.canonicalFindings, 2);
});

test("refuted findings remain auditable but are excluded from active verdict counts", () => {
    const refuted = finding({
        path: "src/refuted.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "refuted",
        state: "refuted",
        severity: "critical",
    });
    const snapshot = buildTrustedDecisionSnapshot({
        auditId: AUDIT_ID,
        findings: [refuted],
        traceSnapshot: trace([chain("refuted")]),
        validationSnapshot: validation([refuted]),
        coverage: COMPLETE_COVERAGE,
    });
    assert.equal(snapshot.stateCounts.refuted, 1);
    assert.equal(snapshot.severityCounts.refuted.critical, 1);
    assert.equal(snapshot.severityCounts.active.critical, 0);
    assert.equal(snapshot.canonicalFindings.length, 1);
    assert.equal(snapshot.overallVerdictEligibility.noRedFlagsEligible, true);
});

test("unresolved critical candidates stay prominent and forbid no-red-flags", () => {
    const unresolved = finding({
        path: "src/unresolved.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "unresolved",
        state: "unresolved",
        severity: "critical",
        confidence: "low",
    });
    const snapshot = buildTrustedDecisionSnapshot({
        auditId: AUDIT_ID,
        findings: [unresolved],
        traceSnapshot: trace([chain("unresolved")]),
        coverage: COMPLETE_COVERAGE,
    });
    assert.equal(snapshot.severityCounts.active.critical, 1);
    assert.equal(snapshot.overallVerdictEligibility.noRedFlagsEligible, false);
    assert.equal(snapshot.overallVerdictEligibility.recommendedVerdict, "incomplete");
    assert.ok(snapshot.blockers.some((blocker) =>
        blocker.code === "unresolved-severe-finding"));

    const policyOverride = buildTrustedDecisionSnapshot({
        auditId: AUDIT_ID,
        findings: [unresolved],
        traceSnapshot: trace([chain("unresolved")]),
        coverage: COMPLETE_COVERAGE,
        policy: { allowNoRedFlagsWithUnresolvedSevere: true },
    });
    assert.equal(
        policyOverride.overallVerdictEligibility.noRedFlagsEligible,
        true,
    );
});

test("project-fit likelihood remains separate from impact and evidence confidence", () => {
    const base = finding({
        path: "src/fit.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "fit",
        maliciousProjectFit: "unlikely",
    });
    const strongFit = { ...base, maliciousProjectFit: "strong" };
    const lowFitScore = scoreCanonicalFinding(dedupeFindings({
        auditId: AUDIT_ID,
        findings: [base],
        traceSnapshot: trace([chain("fit")]),
        validationSnapshot: validation([base], { fit: chain("fit") }),
    }).canonicalFindings[0]);
    const strongFitScore = scoreCanonicalFinding(dedupeFindings({
        auditId: AUDIT_ID,
        findings: [strongFit],
        traceSnapshot: trace([chain("fit")]),
        validationSnapshot: validation([strongFit], { fit: chain("fit") }),
    }).canonicalFindings[0]);
    assert.equal(lowFitScore.impactSeverity.level, strongFitScore.impactSeverity.level);
    assert.equal(
        lowFitScore.evidenceConfidence.level,
        strongFitScore.evidenceConfidence.level,
    );
    assert.equal(lowFitScore.maliciousProjectFitLikelihood.level, "unlikely");
    assert.equal(strongFitScore.maliciousProjectFitLikelihood.level, "strong");
});

test("independent duplicate paths increase confidence without changing severity", () => {
    const first = finding({
        path: "src/a.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "one",
        confidence: "low",
    });
    const second = finding({
        path: "src/b.mjs",
        fill: "c",
        producer: "role-two",
        suffix: "two",
        confidence: "low",
    });
    const firstChain = chain("one");
    const secondChain = chain("two");
    const single = buildTrustedDecisionSnapshot({
        auditId: AUDIT_ID,
        findings: [first],
        traceSnapshot: trace([firstChain]),
        validationSnapshot: validation([first], { one: firstChain }),
        coverage: COMPLETE_COVERAGE,
    }).canonicalFindings[0];
    const duplicated = buildTrustedDecisionSnapshot({
        auditId: AUDIT_ID,
        findings: [first, second],
        traceSnapshot: trace([firstChain, secondChain]),
        validationSnapshot: validation(
            [first, second],
            { one: firstChain, two: secondChain },
        ),
        coverage: COMPLETE_COVERAGE,
    }).canonicalFindings[0];
    assert.equal(single.scores.evidenceConfidence.level, "low");
    assert.equal(duplicated.scores.evidenceConfidence.level, "high");
    assert.equal(
        single.scores.impactSeverity.level,
        duplicated.scores.impactSeverity.level,
    );
});

test("caps are explicit, fail closed, and retain the severe singleton first", () => {
    const critical = finding({
        path: "src/critical.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "critical",
        severity: "critical",
    });
    const low = finding({
        path: "src/low.mjs",
        fill: "c",
        producer: "role-two",
        suffix: "low",
        severity: "low",
        behaviorSignature: behavior({ target: "log-file" }),
    });
    const snapshot = buildTrustedDecisionSnapshot({
        auditId: AUDIT_ID,
        findings: [low, critical],
        traceSnapshot: trace([chain("critical"), chain("low")]),
        validationSnapshot: validation([low, critical], {
            critical: chain("critical"),
            low: chain("low"),
        }),
        coverage: COMPLETE_COVERAGE,
        limits: { canonicalFindings: 1 },
    });
    assert.equal(snapshot.canonicalFindings.length, 1);
    assert.equal(snapshot.canonicalFindings[0].scores.impactSeverity.level, "critical");
    assert.equal(snapshot.truncation.canonicalFindings, true);
    assert.equal(snapshot.overallVerdictEligibility.trustedDecisionEligible, false);
});

test("every incomplete stage or tracking gate forbids a no-red-flags conclusion", () => {
    for (const gate of Object.keys(COMPLETE_COVERAGE)) {
        const snapshot = buildTrustedDecisionSnapshot({
            auditId: AUDIT_ID,
            findings: [],
            coverage: { ...COMPLETE_COVERAGE, [gate]: false },
        });
        assert.equal(snapshot.overallVerdictEligibility.noRedFlagsEligible, false, gate);
        assert.equal(snapshot.overallVerdictEligibility.recommendedVerdict, "incomplete", gate);
        assert.ok(snapshot.blockers.some((blocker) =>
            blocker.code.endsWith("-incomplete")), gate);
    }
});

test("decision snapshots are deterministic, identity-bound, bounded, and source-text-free", () => {
    const entry = finding({
        path: "src/stable.mjs",
        fill: "b",
        producer: "role-one",
        suffix: "stable",
    });
    const stableChain = chain("stable");
    const input = {
        auditId: AUDIT_ID,
        findings: [entry],
        traceSnapshot: trace([stableChain]),
        validationSnapshot: validation([entry], { stable: stableChain }),
        coverage: COMPLETE_COVERAGE,
    };
    const first = buildTrustedDecisionSnapshot(input);
    const retry = buildTrustedDecisionSnapshot(structuredClone(input));
    assert.equal(first.decisionId, retry.decisionId);
    assert.equal(first.inputFingerprint, retry.inputFingerprint);
    assert.doesNotMatch(JSON.stringify(first), /Same prose|narrative wording/);
    assert.throws(
        () => buildTrustedDecisionSnapshot({
            ...input,
            auditId: "22222222-2222-4222-8222-222222222222",
        }),
        /auditId/u,
    );
});

test("packet handoff uses the trusted decision snapshot for dual rendering", () => {
    const validatePacket = readFileSync(
        new URL("../packet/validate.mjs", import.meta.url),
        "utf8",
    );
    const scanPacket = readFileSync(
        new URL("../packet/scan.mjs", import.meta.url),
        "utf8",
    );
    assert.match(validatePacket, /validationFinal\.decisionSnapshot/u);
    assert.match(validatePacket, /renders\s+REPORT\.md and source-text-free FINDINGS\.json/u);
    assert.match(scanPacket, /severityCounts\.active/u);
    assert.match(scanPacket, /must not recompute them from prose/u);
});
