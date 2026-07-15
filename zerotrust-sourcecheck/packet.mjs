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

export function buildInstructionPacket(args) {
    const { target } = args;
    if (target && target.kind === "local") {
        return buildLocalSourcePacket({
            ...args,
            localPath: target.localPath,
        });
    }

    const context = createUrlPacketContext(args);
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
