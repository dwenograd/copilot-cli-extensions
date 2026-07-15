// packet.mjs
//
// Stable public assembly surface for zerotrust-sourcecheck instruction packets.
// Stage renderers live under packet/ and remain pure/testable; this module only
// selects local vs URL assembly and preserves the historical exports.

import {
    modeIsBuild,
    modeIsAudit,
    modeNeedsClone,
    modeUsesCouncil,
    modeIsFullBuild,
    modeIsSafeBuild,
    modeIsCouncilBuild,
    modeUsesApiDirect,
    modeUsesLocalSource,
} from "./modes.mjs";
import { renderAcquisitionStage, HARDENED_CLONE_FLAGS, HARDENED_CLONE_TAIL } from "./packet/acquisition.mjs";
import { renderFinalizeReportLifecycleStage } from "./packet/finalize.mjs";
import { buildLocalSourcePacket } from "./packet/local.mjs";
import { createUrlPacketContext, renderPrepareStage } from "./packet/prepare.mjs";
import { renderScanCouncilStage } from "./packet/scan.mjs";
import { renderRemediationBlock } from "./packet/shared.mjs";

export {
    mapOverallVerdict,
    scoreGitAttributesFilter,
    scoreInvisibleUnicode,
    validateFindingContract,
} from "./packet/shared.mjs";

export function buildInstructionPacket({
    mode,
    target,
    parsed,
    refOverride,
    focusWrapped,
    injectionPreamble,
    injectionWarnings,
    subAgentInstruction,
    nonce,
    scrubNote,
    privateRepoAck,
    buildExecAck,
    unsafeAck,
    buildRoot,
    expectedClonePath,
    expectedReportPath,
    expectedQuarantinePath,
    placeholderSha,
    auditId,
    analysisStageState,
    councilManifest,
    councilJudgeModel,
    councilSubJudgeModel,
    maxPremiumCalls,
    validationMinSeverity,
}) {
    if (target && target.kind === "local") {
        return buildLocalSourcePacket({
            mode,
            auditId,
            localPath: target.localPath,
            focusWrapped,
            injectionPreamble,
            injectionWarnings,
            subAgentInstruction,
            nonce,
            scrubNote,
            buildRoot,
            expectedReportPath,
            councilManifest,
            councilJudgeModel,
            councilSubJudgeModel,
            maxPremiumCalls,
            validationMinSeverity,
        });
    }

    const context = createUrlPacketContext({
        mode,
        target,
        parsed,
        refOverride,
        focusWrapped,
        injectionPreamble,
        injectionWarnings,
        subAgentInstruction,
        nonce,
        scrubNote,
        privateRepoAck,
        buildExecAck,
        unsafeAck,
        buildRoot,
        expectedClonePath,
        expectedReportPath,
        expectedQuarantinePath,
        placeholderSha,
        auditId,
        analysisStageState,
        councilManifest,
        councilJudgeModel,
        councilSubJudgeModel,
        maxPremiumCalls,
        validationMinSeverity,
    });

    return renderPrepareStage(context)
        + renderAcquisitionStage(context)
        + renderScanCouncilStage(context)
        + renderFinalizeReportLifecycleStage(context);
}

export const __internals = {
    HARDENED_CLONE_FLAGS,
    HARDENED_CLONE_TAIL,
    modeIsBuild,
    modeIsAudit,
    modeNeedsClone,
    modeUsesCouncil,
    modeIsFullBuild,
    modeIsSafeBuild,
    modeIsCouncilBuild,
    modeUsesApiDirect,
    modeUsesLocalSource,
    renderRemediationBlock,
    buildLocalSourcePacket,
};
