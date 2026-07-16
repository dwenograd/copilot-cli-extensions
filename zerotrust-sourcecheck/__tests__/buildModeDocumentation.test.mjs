import { readFileSync } from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";

import { runHandler } from "../handler.mjs";
import {
    BUILD_MODE_TAXONOMY_NOTE,
    FULL_BUILD_MODES,
    modeIsFullBuild,
} from "../modes.mjs";
import { buildInstructionPacket } from "../packet.mjs";
import { DEFAULT_BUILD_ROOT } from "../safeWrappers/defaults.mjs";
import { buildClonePath, buildQuarantinePath, buildReportPath } from "../urlParser.mjs";

const HERE = nodePath.dirname(fileURLToPath(import.meta.url));
const ROOT = nodePath.resolve(HERE, "..");
const URL = "https://github.com/octocat/Hello-World";
const PLACEHOLDER = "0".repeat(40);
const CLONE = buildClonePath(DEFAULT_BUILD_ROOT, "octocat", "Hello", PLACEHOLDER);
const REPORT = buildReportPath(DEFAULT_BUILD_ROOT, "octocat", "Hello", PLACEHOLDER);
const QUARANTINE = buildQuarantinePath(DEFAULT_BUILD_ROOT, "octocat", "Hello", PLACEHOLDER);

function source(name) {
    return readFileSync(nodePath.join(ROOT, name), "utf8");
}

function packet(mode, overrides = {}) {
    return buildInstructionPacket({
        mode,
        parsed: {
            owner: "octocat",
            repo: "Hello",
            ref: "main",
            refType: "branch",
            kind: "tree",
            canonicalUrl: "https://github.com/octocat/Hello/tree/main",
        },
        refOverride: null,
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "build-mode-doc-test",
        scrubNote: null,
        privateRepoAck: true,
        buildExecAck: mode.includes("build"),
        unsafeAck: mode.includes("full"),
        buildRoot: DEFAULT_BUILD_ROOT,
        expectedClonePath: CLONE,
        expectedReportPath: REPORT,
        expectedQuarantinePath: QUARANTINE,
        placeholderSha: true,
        councilManifest: null,
        councilJudgeModel: null,
        councilSubJudgeModel: null,
        maxPremiumCalls: null,
        ...overrides,
    });
}

function assertFinalizationPrecedesHostExecution(text) {
    const finalizerCall = text.indexOf(
        "const finalizeResult = zerotrust_finalize_report({",
    );
    const hostExecutionInstructions = text.indexOf(
        "Use `zerotrust_safe_install` for installs",
        finalizerCall,
    );
    assert.ok(finalizerCall >= 0, "packet must invoke the canonical finalizer");
    assert.ok(
        hostExecutionInstructions > finalizerCall,
        "wrapper-mediated host execution must follow canonical finalization",
    );
}

test("central build-mode taxonomy pins current safe/full behavior", () => {
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /Safe\/full mode names are retained for compatibility/i);
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /identical install\/build wrappers/i);
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /Install lifecycle scripts remain suppressed/i);
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /repo-controlled npm build scripts/i);
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /build\.rs/i);
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /MSBuild targets/i);
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /admission\/warning posture only/i);
    assert.match(BUILD_MODE_TAXONOMY_NOTE, /future distinction/i);
    assert.deepEqual([...FULL_BUILD_MODES], [
        "audit_and_full_build",
        "audit_and_full_build_council",
    ]);
    assert.equal(modeIsFullBuild("audit_and_safe_build"), false);
    assert.equal(modeIsFullBuild("audit_and_full_build"), true);
});

test("extension schema consumes the central mode enum and build taxonomy", () => {
    const text = source("extension.mjs");
    assert.match(text, /enum:\s*\[\.\.\.VALID_MODES\]/);
    assert.match(text, /BUILD_MODE_TAXONOMY_NOTE/);
    assert.match(text, /does not enable install lifecycle scripts or a less-restricted installer/);
    assert.match(text, /hazardous post-audit host execution may run repo-controlled npm build scripts/i);
    assert.match(text, /build\.rs/i);
    assert.match(text, /MSBuild targets/i);
});

test("handler acknowledgement errors describe actual build execution posture", () => {
    const missingBuildAck = runHandler(
        {
            url: URL,
            mode: "audit_and_safe_build",
            build_root: DEFAULT_BUILD_ROOT,
        },
        { sessionId: "build-doc-missing-build-ack" },
    );
    assert.equal(missingBuildAck.resultType, "failure");
    assert.match(missingBuildAck.textResultForLlm, /Install lifecycle scripts remain suppressed/);
    assert.match(missingBuildAck.textResultForLlm, /build\.rs/);

    const missingUnsafe = runHandler(
        {
            url: URL,
            mode: "audit_and_full_build",
            build_root: DEFAULT_BUILD_ROOT,
            i_understand_build_executes_code: true,
        },
        { sessionId: "build-doc-missing-unsafe" },
    );
    assert.equal(missingUnsafe.resultType, "failure");
    assert.match(missingUnsafe.textResultForLlm, /requires `unsafe: true`/);
    assert.match(missingUnsafe.textResultForLlm, /(?:same|identical) install\/build wrappers/);
    assert.match(missingUnsafe.textResultForLlm, /admission\/warning posture only/);
});

test("safe and full packets state the shared wrappers and build-time risk", () => {
    for (const mode of ["audit_and_safe_build", "audit_and_full_build"]) {
        const text = packet(mode);
        assert.match(text, /Safe\/full mode names are retained for compatibility/);
        assert.match(text, /Install lifecycle scripts remain suppressed/);
        assert.match(text, /npm build scripts/);
        assert.match(text, /build\.rs/);
        assert.match(text, /MSBuild targets/);
        assert.doesNotMatch(text, /lifecycle scripts (?:will|WILL) execute/i);
        assert.doesNotMatch(text, /allow lifecycle scripts/i);
    }
    assert.match(packet("audit_and_full_build"), /requires BOTH i_understand_build_executes_code: true AND unsafe: true|Both required acknowledgement flags are set/);
    assertFinalizationPrecedesHostExecution(packet("audit_and_safe_build"));
});

test("API-direct post-audit build wording does not promise a full installer", () => {
    const text = packet("audit_source");
    assert.match(text, /Install lifecycle scripts stay suppressed/);
    assert.match(text, /Safe\/full names are compatibility aliases for identical wrappers/);
    assert.match(text, /admission\/warning posture.*reserves a future distinction/);
    assert.doesNotMatch(text, /For full lifecycle scripts/);
});

test("README and agent notes pin the safe/full documentation contract", () => {
    const readme = source("README.md");
    const agents = source("AGENTS.md");
    for (const text of [readme, agents]) {
        assert.match(text, /(?:same|identical) (?:install\/build\s+)?wrappers/i);
        assert.match(text, /Install lifecycle scripts (?:remain|stay)\s+suppressed/i);
        assert.match(text, /build\.rs/);
        assert.match(text, /admission\/warning\s+posture/i);
        assert.match(text, /future distinction/i);
        assert.match(text, /less-restricted installer/i);
    }
    assert.doesNotMatch(readme, /full lifecycle scripts/i);
});

test("build-mode documentation surfaces contain no obsolete full-mode promises", () => {
    const combined = [
        "modes.mjs",
        "handler.mjs",
        "extension.mjs",
        "enforcement.mjs",
        "packet.mjs",
        "README.md",
        "AGENTS.md",
    ].map(source).join("\n");

    for (const obsolete of [
        /lifecycle scripts (?:will|WILL) execute/i,
        /allow(?:s|ed)? lifecycle scripts/i,
        /full lifecycle scripts/i,
        /lifecycle-script build/i,
        /outside of full-build modes/i,
        /re-run with mode='audit_and_full_build' if you intentionally want lifecycle scripts/i,
    ]) {
        assert.doesNotMatch(combined, obsolete);
    }
});
