// packet.mjs
//
// Stable public assembly surface for zerotrust-sourcecheck instruction packets.
// Stage renderers live under packet/ and remain pure/testable; this module only
// selects local vs URL assembly and exposes the current packet helpers.

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
import { renderCurrentAssuranceStage } from "./packet/assurance.mjs";
import { renderFinalizeReportLifecycleStage } from "./packet/finalize.mjs";
import { buildLocalSourcePacket } from "./packet/local.mjs";
import { createUrlPacketContext, renderPrepareStage } from "./packet/prepare.mjs";
import { renderScanCouncilStage } from "./packet/scan.mjs";

export {
    mapOverallVerdict,
    scoreGitAttributesFilter,
    scoreInvisibleUnicode,
    validateFindingContract,
} from "./packet/shared.mjs";
export {
    SEMANTIC_COVERAGE_WIRING_STATUS,
    renderSemanticCoverageScaffold,
} from "./packet/semanticCoverage.mjs";
export {
    RED_TEAM_WIRING_STATUS,
    renderRedTeamScaffold,
} from "./packet/redTeam.mjs";

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
        + renderCurrentAssuranceStage(context)
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
    buildLocalSourcePacket,
};
