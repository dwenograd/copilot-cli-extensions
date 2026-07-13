import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    assessVerifiedResultReadiness,
    artifactRefsFromProvenance,
    buildCandidateArchive,
    canonicalJson,
    decideNext,
} from "../domain/index.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";
import { createReplayStatsFixture } from "./v4-replay-stats-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function fixture(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.confirmation-${label}-`),
    );
    roots.push(root);
    return createReplayStatsFixture(root);
}

afterEach(async () => {
    await removeTrackedRoots(roots, {
        label: "confirmation test root",
    });
});

describe("v4 scientific confirmation", () => {
    it("freezes discovery before held-out work and cannot ready from discovery alone", () => {
        const item = fixture("freeze");
        const before = item.adapter.replay().aggregate;
        expect(assessVerifiedResultReadiness(before).ready).toBe(false);
        expect(before.terminal).toBeNull();

        const frozenEvent = item.freezeConfirmation();
        const frozen = item.adapter.replay().aggregate;
        expect(frozenEvent.payload.discoveryHead).toMatchObject({
            seq: before.lastSeq,
            eventHash: before.lastEventHash,
            scientificReplayClosureRoot:
                before.scientificReplay.closureRoot,
        });
        expect(frozen.scientificReplay.confirmationState).toMatchObject({
            status: "PENDING",
            ready: false,
            failed: false,
        });
        expect(decideNext(frozen)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "run_confirmation",
                harnessRole: "confirmation",
                confirmationFreezeHash: frozenEvent.payload.freezeHash,
                candidateEvidenceId: "replay-candidate-evidence",
            },
        });
        item.close();
    });

    it("requires independent confirmation and challenge, then waits for the decision gate", () => {
        const item = fixture("success");
        item.freezeConfirmation();
        const confirmation = item.appendScientificRole();
        expect(confirmation.command.kind).toBe("run_confirmation");
        expect(item.adapter.replay().aggregate.scientificReplay.confirmationState)
            .toMatchObject({ status: "PENDING", ready: false });

        const challenge = item.appendScientificRole();
        expect(challenge.command.kind).toBe("run_challenge");
        const aggregate = item.adapter.replay().aggregate;
        expect(aggregate.searchStrategy.revision).toBe(
            aggregate.confirmation.freeze.payload.discoveryHead
                .searchStrategyRevision,
        );
        expect(aggregate.scientificReplay.confirmationState).toMatchObject({
            status: "READY",
            ready: true,
            failed: false,
            members: [{
                status: "READY",
                roles: [
                    { role: "confirmation", status: "SUPPORTED" },
                    { role: "challenge", status: "SUPPORTED" },
                ],
            }],
        });
        expect(assessVerifiedResultReadiness(aggregate)).toMatchObject({
            ready: true,
            confirmationSupported: true,
            challengeSupported: true,
        });
        const candidateEvidence = Object.values(aggregate.evidence).find(
            (evidence) => evidence.purpose === "candidate",
        );
        const candidateObservation =
            aggregate.observations[candidateEvidence.observationId];
        const candidateCommandId = candidateObservation.commandId;
        const hypothesisTamper = structuredClone(aggregate);
        hypothesisTamper.commands[candidateCommandId].command.hypotheses = {
            identity: "sha256:crucible-hypotheses-v1:"
                + "9".repeat(64),
        };
        expect(assessVerifiedResultReadiness(hypothesisTamper)).toMatchObject({
            ready: false,
            scientificBindingsValid: false,
            missing: expect.arrayContaining([
                "trusted_command_hypothesis_control_stopping_bindings",
            ]),
        });

        const controlTamper = structuredClone(aggregate);
        controlTamper.evidence[candidateEvidence.evidenceId]
            .replication.control.artifactHash =
                `sha256:crucible-measurement-snapshot-v1:${"8".repeat(64)}`;
        expect(assessVerifiedResultReadiness(controlTamper)).toMatchObject({
            ready: false,
            scientificBindingsValid: false,
        });

        const stoppingTamper = structuredClone(aggregate);
        stoppingTamper.evidence[candidateEvidence.evidenceId]
            .replication.stopping.shouldContinue = true;
        expect(assessVerifiedResultReadiness(stoppingTamper)).toMatchObject({
            ready: false,
            scientificBindingsValid: false,
        });
        expect(canonicalJson(buildCandidateArchive(aggregate)))
            .not.toContain(confirmation.evidence.evidenceId);
        expect(canonicalJson(buildCandidateArchive(aggregate)))
            .not.toContain(challenge.evidence.evidenceId);
        expect(aggregate.terminal).toBeNull();
        expect(decideNext(aggregate)).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
        });
        for (const roleEvidence of [
            confirmation.evidence,
            challenge.evidence,
        ]) {
            const expectedIds = artifactRefsFromProvenance(
                roleEvidence.receipt.provenance,
            ).map((artifact) => artifact.artifactId).sort();
            const actualIds = item.repository.listArtifactRefsForEvent(
                item.investigationId,
                roleEvidence.committedSeq,
            ).map((artifact) => artifact.artifactId).sort();
            expect(actualIds).toEqual(expectedIds);
        }

        item.adapter.appendKernelDecision();
        expect(item.adapter.replay().aggregate.terminal).toMatchObject({
            decision: "VERIFIED_RESULT",
        });
        item.close();
    });

});
