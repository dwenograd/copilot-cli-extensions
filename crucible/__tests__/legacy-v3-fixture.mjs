import {
    canonicalClone,
    hashCanonical,
} from "../domain/index.mjs";

export const LEGACY_V3_DOMAIN_VERSION = 3;
export const LEGACY_V3_CONTRACT_HASH_ALGORITHM =
    "sha256:crucible-contract-v1";
export const LEGACY_V3_EVENT_HASH_ALGORITHM =
    "sha256:crucible-event-v1";

export function createLegacyV3OpenedEvent(currentContract) {
    const contract = canonicalClone(currentContract);
    delete contract.domainVersion;
    const event = {
        seq: 1,
        type: "investigation_opened",
        prevHash: null,
        payload: {
            domainVersion: LEGACY_V3_DOMAIN_VERSION,
            contract,
            contractHash: hashCanonical(
                contract,
                LEGACY_V3_CONTRACT_HASH_ALGORITHM,
            ),
        },
    };
    return {
        ...event,
        eventHash: hashCanonical(event, LEGACY_V3_EVENT_HASH_ALGORITHM),
    };
}

export function appendLegacyV3Investigation(
    repository,
    investigationId,
    currentContract,
) {
    const domainEvent = createLegacyV3OpenedEvent(currentContract);
    repository.ensureInvestigation({
        investigationId,
        metadata: { role: "crucible-domain" },
    });
    repository.appendEvents({
        investigationId,
        expectedHead: null,
        events: [{
            kind: `domain:${domainEvent.type}`,
            payload: { domainEvent },
        }],
    });
    return domainEvent;
}
