import { test } from "node:test";
import assert from "node:assert/strict";

import {
    DEFAULT_META_JUDGE_MODEL,
    DEFAULT_SUB_JUDGE_MODEL,
    ROLES,
} from "../council/index.mjs";
import { VALID_MODES } from "../modes.mjs";
import { buildInstructionPacket } from "../packet.mjs";
import { renderAcquisitionStage } from "../packet/acquisition.mjs";
import { renderCurrentAssuranceStage } from "../packet/assurance.mjs";
import { renderFinalizeReportLifecycleStage } from "../packet/finalize.mjs";
import { buildLocalSourcePacket } from "../packet/local.mjs";
import { createUrlPacketContext, renderPrepareStage } from "../packet/prepare.mjs";
import { renderScanCouncilStage } from "../packet/scan.mjs";
import { renderTraceStage } from "../packet/trace.mjs";
import { renderValidateStage } from "../packet/validate.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/var/zerotrust-sourcecheck";
const LOCAL_PATH = process.platform === "win32" ? "C:\\projects\\sample": "/srv/sample";
const URL_MODES = VALID_MODES.filter((mode) => !mode.includes("local_source"));
const LOCAL_MODES = VALID_MODES.filter((mode) => mode.includes("local_source"));

function councilArgs(mode) {
    const enabled = mode.includes("council");
    return {
        councilManifest: enabled ? ROLES: null,
        councilJudgeModel: enabled ? DEFAULT_META_JUDGE_MODEL: null,
        councilSubJudgeModel: enabled ? DEFAULT_SUB_JUDGE_MODEL: null,
        maxPremiumCalls: enabled ? 128: null,
    };
}

function urlArgs(mode) {
    return {
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
        focusWrapped: "<<<FOCUS>>>\nUSER_INPUT_BEGIN\nfocus\nUSER_INPUT_END",
        injectionPreamble: "INJECTION PREAMBLE",
        injectionWarnings: ["warning-one"],
        subAgentInstruction: "SUBAGENT INSTRUCTION",
        nonce: "packet-assembly-test",
        scrubNote: "SCRUB NOTE",
        privateRepoAck: true,
        buildExecAck: mode.includes("build"),
        unsafeAck: mode.includes("full"),
        buildRoot: BUILD_ROOT,
        expectedClonePath: `${BUILD_ROOT}\\clone`,
        expectedReportPath: `${BUILD_ROOT}\\report`,
        expectedQuarantinePath: `${BUILD_ROOT}\\quarantine`,
        placeholderSha: true,
        auditId: "packet-assembly-audit",
        validationMinSeverity: enabledValidationFloor(mode),
        ...councilArgs(mode),
    };
}

function localArgs(mode) {
    return {
        mode,
        target: { kind: "local", localPath: LOCAL_PATH, slug: "sample" },
        focusWrapped: "<<<FOCUS>>>\nUSER_INPUT_BEGIN\nfocus\nUSER_INPUT_END",
        injectionPreamble: "INJECTION PREAMBLE",
        injectionWarnings: ["warning-one"],
        subAgentInstruction: "SUBAGENT INSTRUCTION",
        nonce: "packet-assembly-test",
        scrubNote: "SCRUB NOTE",
        buildRoot: BUILD_ROOT,
        expectedReportPath: `${BUILD_ROOT}\\local-report`,
        auditId: "packet-assembly-audit",
        validationMinSeverity: enabledValidationFloor(mode),
        ...councilArgs(mode),
    };
}

function enabledValidationFloor(mode) {
    return mode.includes("council") ? "medium": "high";
}

function assertForbiddenClaims(packet) {
    assert.doesNotMatch(packet, /lifecycle scripts (?:will|WILL) execute/i);
    assert.doesNotMatch(packet, /allow(?:s|ed)? lifecycle scripts/i);
    assert.doesNotMatch(packet, /full lifecycle scripts/i);
    assert.doesNotMatch(packet, /wrappers? (?:intercept|intercepts) raw built-in tool calls/i);
    assert.doesNotMatch(packet, /Verdict: clean\b/i);
}

function assertFinalizationPrecedesHostExecution(packet, mode) {
    const finalizerCall = packet.indexOf(
        "const finalizeResult = zerotrust_finalize_report({",
    );
    const hostExecutionInstructions = packet.indexOf(
        "Use `zerotrust_safe_install` for installs",
        finalizerCall,
    );
    assert.ok(finalizerCall >= 0, mode);
    assert.ok(hostExecutionInstructions > finalizerCall, mode);
}

test("URL packet assembly is the exact concatenation of pure stage renderers", () => {
    for (const mode of URL_MODES) {
        const args = urlArgs(mode);
        const context = createUrlPacketContext(args);
        const stages = [
            renderPrepareStage(context),
            renderAcquisitionStage(context),
            renderScanCouncilStage(context),
            renderCurrentAssuranceStage(context),
            renderFinalizeReportLifecycleStage(context),
        ];
        assert.ok(stages.every((stage) => typeof stage === "string"), mode);
        assert.equal(buildInstructionPacket(args), stages.join(""), mode);
    }
});

test("trace and validation stages render the current assurance workflow", () => {
    const rendered = renderTraceStage({
        auditId: "11111111-1111-4111-8111-111111111111",
    });
    assert.match(rendered, /zerotrust_prepare_evasive_graph/u);
    assert.match(rendered, /zerotrust_trace_evasive_graph/u);
    assert.match(rendered, /every activation\/trigger root plus every\s+alternate effect path/iu);
    const validation = renderValidateStage({
        auditId: "11111111-1111-4111-8111-111111111111",
        councilJudgeModel: DEFAULT_META_JUDGE_MODEL,
        councilSubJudgeModel: DEFAULT_SUB_JUDGE_MODEL,
    });
    assert.match(validation, /zerotrust_prepare_assurance_validation/u);
    assert.match(validation, /zerotrust_record_assurance_validation/u);
    assert.match(validation, /zerotrust_finalize_assurance_validation/u);
    assert.match(validation, /independent confirm\/refute assignments/iu);
});

test("local packet assembly delegates unchanged to the local renderer", () => {
    for (const mode of LOCAL_MODES) {
        const args = localArgs(mode);
        assert.equal(buildInstructionPacket(args), buildLocalSourcePacket({
            mode,
            auditId: args.auditId,
            localPath: args.target.localPath,
            focusWrapped: args.focusWrapped,
            injectionPreamble: args.injectionPreamble,
            injectionWarnings: args.injectionWarnings,
            subAgentInstruction: args.subAgentInstruction,
            nonce: args.nonce,
            scrubNote: args.scrubNote,
            buildRoot: args.buildRoot,
            expectedReportPath: args.expectedReportPath,
            councilManifest: args.councilManifest,
            councilJudgeModel: args.councilJudgeModel,
            councilSubJudgeModel: args.councilSubJudgeModel,
            maxPremiumCalls: args.maxPremiumCalls,
            validationMinSeverity: args.validationMinSeverity,
        }), mode);
    }
});

test("every mode retains its required security and lifecycle sections", () => {
    for (const mode of VALID_MODES) {
        const packet = buildInstructionPacket(mode.includes("local_source") ? localArgs(mode): urlArgs(mode));
        assert.match(packet, /INJECTION PREAMBLE/, mode);
        assert.match(packet, /USER_INPUT_BEGIN[\s\S]*USER_INPUT_END/, mode);
        assert.match(packet, /zerotrust_finalize_report/, mode);
        assert.match(packet, /zerotrust_close_audit/, mode);
        assertForbiddenClaims(packet);

        if (mode.includes("local_source")) {
            assert.match(packet, /LOCAL-SOURCE audit packet/, mode);
            assert.match(packet, /Containment is load-bearing/, mode);
            assert.match(packet, /Do not create the report\s+directory/i, mode);
            assert.match(packet, /Step E — Remediation decisions before finalization/, mode);
            assert.doesNotMatch(packet, /Section 4 — API-direct file enumeration/, mode);
            assert.doesNotMatch(packet, /Section 4 — Hardened clone/, mode);
            if (mode.includes("council")) {
                assert.match(packet, /Multi-role council discovery \(32 roles\)/, mode);
                assert.match(packet, /Continue into semantic coverage/, mode);
            } else {
                assert.match(packet, /Deterministic preparation without the discovery council/, mode);
            }
            continue;
        }

        assert.match(packet, /Section 1 — Threat model & ground rules/, mode);
        assert.match(packet, /Section 2 — Recon/, mode);
        if (mode === "metadata_only") {
            assert.match(packet, /metadata_only mode — short-circuit here/, mode);
            assert.match(packet, /reconnaissance only — NOT a security audit/, mode);
            assert.doesNotMatch(packet, /Section 4 — API-direct file enumeration/, mode);
            assert.doesNotMatch(
                packet,
                /Section 8 — Hazardous post-audit host execution/,
                mode,
            );
        } else if (mode.includes("build")) {
            assert.match(packet, /Section 4 — Hardened clone \(build mode\)/, mode);
            assert.match(packet, /Section 8 — Hazardous post-audit host execution/, mode);
            assert.match(packet, /zerotrust_safe_install/, mode);
            assert.match(packet, /build-time code execution surfaces/, mode);
            assert.match(packet, /zerotrust_cleanup_audit/, mode);
            assert.doesNotMatch(packet, /Section 4 — API-direct file enumeration/, mode);
            assertFinalizationPrecedesHostExecution(packet, mode);
        } else {
            assert.match(packet, /Section 4 — API-direct file enumeration/, mode);
            assert.match(packet, /requiredAcquisitionComplete === true/, mode);
            assert.match(packet, /Do NOT write files to disk for any reason/, mode);
            assert.doesNotMatch(packet, /Section 4 — Hardened clone/, mode);
            assert.doesNotMatch(
                packet,
                /Section 8 — Hazardous post-audit host execution/,
                mode,
            );
        }

        if (mode === "verify_release") {
            assert.match(packet, /Section 6 — Release verification \(this is the headline mode for this URL\)/, mode);
            assert.match(packet, /zerotrust_safe_list_release_assets/, mode);
            assert.match(packet, /requiredReleaseAssetAcquisitionComplete/, mode);
            assert.match(packet, /zerotrust_cleanup_quarantine/, mode);
        }

        if (mode.includes("council")) {
            assert.match(packet, /32-role council discovery input/, mode);
            assert.match(packet, /zerotrust_record_council_candidates/, mode);
            assert.match(packet, /There is no council-owned finalize or verdict path/, mode);
            assert.ok(
                packet.indexOf("zerotrust_record_council_candidates")
                    < packet.indexOf("zerotrust_prepare_semantic_coverage"),
                mode,
            );
            assert.ok(
                packet.indexOf("zerotrust_finalize_assurance_validation")
                    < packet.indexOf("Section 7 — Final report"),
                mode,
            );
            assert.doesNotMatch(packet, /zerotrust_record_council_outcome\(\{/, mode);
            assert.match(
                packet,
                /Investigation-only: report findings in your reply and (?:\*\*)?DO NOT write any files\s+for any reason(?:\*\*)?/,
                mode,
            );
        } else {
            assert.doesNotMatch(packet, /32-role council discovery input/, mode);
        }
    }
});
