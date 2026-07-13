import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    EVENT_TYPES,
    NON_RESULT_CODES,
    canonicalJson,
    createExternalEvent,
    decideNext,
} from "../domain/index.mjs";
import { openDomainRepositoryAdapter } from "../runtime/index.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";
import { createReplayStatsFixture } from "./v4-replay-stats-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function fixture(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.confirmation-failure-${label}-`),
    );
    roots.push(root);
    return createReplayStatsFixture(root);
}

afterEach(async () => {
    await removeTrackedRoots(roots, {
        label: "confirmation failure test root",
    });
});

describe("v4 scientific confirmation failures", () => {
    it("makes an overfit search pass/confirmation fail, challenge fail, or invalidation a non-result", () => {
        const confirmationFailure = fixture("confirm");
        confirmationFailure.freezeConfirmation();
        confirmationFailure.appendScientificRole({ candidateScore: -1 });
        const failedConfirmation =
            confirmationFailure.adapter.replay().aggregate;
        expect(failedConfirmation.scientificReplay.confirmationState)
            .toMatchObject({ status: "FAILED", failed: true });
        expect(decideNext(failedConfirmation)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.SCIENTIFIC_CONFIRMATION_FAILED,
        });
        confirmationFailure.close();

        const challengeFailure = fixture("challenge");
        challengeFailure.freezeConfirmation();
        challengeFailure.appendScientificRole();
        challengeFailure.appendScientificRole({ candidateScore: -1 });
        expect(decideNext(challengeFailure.adapter.replay().aggregate))
            .toMatchObject({
                kind: "NON_RESULT",
                code: NON_RESULT_CODES.SCIENTIFIC_CONFIRMATION_FAILED,
            });
        challengeFailure.close();

        const invalidated = fixture("invalidation");
        invalidated.freezeConfirmation();
        const confirmed = invalidated.appendScientificRole();
        invalidated.adapter.appendDomainEvent(createExternalEvent(
            invalidated.adapter.replay().aggregate,
            EVENT_TYPES.EVIDENCE_INVALIDATED,
            {
                evidenceId: confirmed.evidence.evidenceId,
                reason: "receipt integrity was revoked",
            },
        ));
        expect(decideNext(invalidated.adapter.replay().aggregate))
            .toMatchObject({
                kind: "NON_RESULT",
                code: NON_RESULT_CODES.SCIENTIFIC_CONFIRMATION_FAILED,
            });
        invalidated.close();
    });

    it("replays the frozen role state across a crash boundary", () => {
        const item = fixture("replay");
        const freezeEvent = item.freezeConfirmation();
        item.appendScientificRole();
        const before = item.adapter.replay().aggregate;
        const dbFile = item.dbFile;
        const investigationId = item.investigationId;
        item.close();

        const reopened = openDomainRepositoryAdapter({
            file: dbFile,
            investigationId,
        });
        try {
            expect(canonicalJson(reopened.adapter.replay().aggregate))
                .toBe(canonicalJson(before));
            expect(reopened.adapter.replay().aggregate.confirmation.freeze)
                .toMatchObject({
                    payload: {
                        freezeHash: freezeEvent.payload.freezeHash,
                    },
                });
        } finally {
            reopened.repository.close();
        }
    });
});
