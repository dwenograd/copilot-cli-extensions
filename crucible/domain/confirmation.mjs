import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    deriveReplicationControlBinding,
    deriveReplicationSchedule,
    statisticalSubjectIndex,
} from "./replication.mjs";
import { claimSetAlphaAllocation } from "./statistics.mjs";

export const SCIENTIFIC_CONFIRMATION_VERSION =
    "crucible-scientific-confirmation-v1";
const SCIENTIFIC_CONFIRMATION_FREEZE_HASH_ALGORITHM =
    "sha256:crucible-scientific-confirmation-freeze-v1";
const SCIENTIFIC_CONFIRMATION_ROLE_MANIFEST_HASH_ALGORITHM =
    "sha256:crucible-scientific-confirmation-role-manifest-v1";
const SCIENTIFIC_CONFIRMATION_PROTOCOL_SEED_HASH_ALGORITHM =
    "sha256:crucible-scientific-confirmation-protocol-seed-v1";
const SCIENTIFIC_CONFIRMATION_PROTOCOL_MANIFEST_HASH_ALGORITHM =
    "sha256:crucible-scientific-confirmation-protocol-manifest-v1";
const SCIENTIFIC_CONFIRMATION_ALPHA_USE_HASH_ALGORITHM =
    "sha256:crucible-scientific-confirmation-alpha-use-v1";
const SCIENTIFIC_CONFIRMATION_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-scientific-confirmation-closure-v1";

export const SCIENTIFIC_CONFIRMATION_ROLES = Object.freeze([
    "confirmation",
    "challenge",
]);

const CONFIRMATION_SUBJECT_STRIDE = 3;

function ownEntry(record, key) {
    return record !== null
        && typeof record === "object"
        && typeof key === "string"
        && Object.hasOwn(record, key)
        ? record[key]
        : null;
}

function searchSubjectCapacity(contract) {
    return contract.enumerandManifest?.entries?.length
        ?? contract.candidatesPerRound * contract.maxRounds;
}

function roleManifest(contract, role) {
    const spec = contract.harnessSuite.roles[role];
    const core = {
        role,
        harnessId: spec.harnessId,
        harnessEntryHash: spec.harnessEntryHash,
        executableHash: spec.executableHash,
        parser: spec.parser,
        dependencies: spec.dependencies,
        configHash: spec.configHash,
        observableSchemaHash: spec.observableSchemaHash,
        caseManifest: spec.caseManifest,
        caseManifestHash: spec.caseManifestHash,
        deterministicSeed: spec.deterministicSeed,
        sandboxIdentity: spec.sandboxIdentity,
    };
    return immutableCanonical({
        ...core,
        roleManifestHash: hashCanonical(
            core,
            SCIENTIFIC_CONFIRMATION_ROLE_MANIFEST_HASH_ALGORITHM,
        ),
    });
}

function alphaReservations(contract, schedule) {
    return immutableCanonical(
        contract.acceptanceClaimSet.claims.map((claim) => ({
            claimId: claim.id,
            allocation: claimSetAlphaAllocation({
                statisticalPolicy: contract.statisticalPolicy,
                allocationClaims: contract.acceptanceClaimSet.claims,
                claimId: claim.id,
                subject: schedule.subject,
                observableRegistry: contract.observableRegistry,
            }),
        })),
    );
}

function frozenRoleProtocol({
    aggregate,
    discoveryHead,
    member,
    memberOrdinal,
    role,
}) {
    const roleOffset = SCIENTIFIC_CONFIRMATION_ROLES.indexOf(role);
    const subjectOrdinal = searchSubjectCapacity(aggregate.contract)
        + memberOrdinal * CONFIRMATION_SUBJECT_STRIDE
        + roleOffset;
    const manifest = roleManifest(aggregate.contract, role);
    const protocolSeed = hashCanonical({
        version: SCIENTIFIC_CONFIRMATION_VERSION,
        contractHash: aggregate.contractHash,
        discoveryHead,
        memberOrdinal,
        candidateId: member.candidateId,
        candidateEvidenceId: member.evidenceId,
        candidateEvidenceHash: member.commitEventHash,
        candidateArtifactHash: member.receipt.candidateArtifactHash,
        hypothesesIdentity: member.hypothesesIdentity ?? null,
        controlBindingHash:
            member.replication?.control?.controlBindingHash ?? null,
        role,
        roleManifestHash: manifest.roleManifestHash,
        configuredRoleSeed: manifest.deterministicSeed,
    }, SCIENTIFIC_CONFIRMATION_PROTOCOL_SEED_HASH_ALGORITHM);
    const subjectId = `scientific-${String(memberOrdinal).padStart(3, "0")}-${role}`;
    const schedule = deriveReplicationSchedule({
        contractHash: aggregate.contractHash,
        statisticalPolicy: aggregate.contract.statisticalPolicy,
        subject: {
            kind: "candidate",
            index: statisticalSubjectIndex("candidate", subjectOrdinal),
            id: subjectId,
            identity: hashCanonical({
                version: SCIENTIFIC_CONFIRMATION_VERSION,
                candidateArtifactHash: member.receipt.candidateArtifactHash,
                candidateEvidenceHash: member.commitEventHash,
                protocolSeed,
                role,
            }, "sha256:crucible-scientific-confirmation-subject-v1"),
        },
    });
    const control = deriveReplicationControlBinding({
        contractHash: aggregate.contractHash,
        statisticalPolicy: aggregate.contract.statisticalPolicy,
        schedule,
        enumerandManifest: aggregate.contract.enumerandManifest ?? null,
        manifestOptions: {
            topology: aggregate.contract.enumerandManifest?.topology
                ?? aggregate.contract.hypothesisTopology,
            observableRegistry: aggregate.contract.observableRegistry,
            hypothesisPolicy: aggregate.contract.hypothesisPolicy,
        },
        controlSnapshotHashes: [
            member.replication.control.artifactHash,
        ],
        requireObservedControl: true,
    });
    const challengePolicy = role === "challenge"
        ? immutableCanonical({
            version: 1,
            kind: "candidate_dependent_frozen_harness_generator",
            candidateDependent: true,
            generatorIdentityHash: hashCanonical({
                roleManifestHash: manifest.roleManifestHash,
                harnessEntryHash: manifest.harnessEntryHash,
                executableHash: manifest.executableHash,
                configHash: manifest.configHash,
                caseManifestHash: manifest.caseManifestHash,
            }, "sha256:crucible-challenge-generator-policy-v1"),
            seedPolicy: {
                algorithm:
                    SCIENTIFIC_CONFIRMATION_PROTOCOL_SEED_HASH_ALGORITHM,
                seed: protocolSeed,
            },
        })
        : null;
    const protocolCore = {
        version: SCIENTIFIC_CONFIRMATION_VERSION,
        role,
        memberOrdinal,
        candidateId: member.candidateId,
        candidateEvidenceId: member.evidenceId,
        candidateEvidenceHash: member.commitEventHash,
        candidateArtifactHash: member.receipt.candidateArtifactHash,
        hypotheses: member.annotations?.hypotheses ?? null,
        hypothesesIdentity: member.hypothesesIdentity ?? null,
        control,
        roleManifest: manifest,
        protocolSeed,
        replicationSchedule: schedule,
        alphaReservations: alphaReservations(aggregate.contract, schedule),
        challengePolicy,
    };
    return immutableCanonical({
        ...protocolCore,
        protocolManifestHash: hashCanonical(
            protocolCore,
            SCIENTIFIC_CONFIRMATION_PROTOCOL_MANIFEST_HASH_ALGORITHM,
        ),
    });
}

export function deriveScientificConfirmationFreeze({
    aggregate,
    cohort,
    cohortEvidence,
    basis,
}) {
    if (aggregate?.confirmation?.freeze !== null
        && aggregate?.confirmation?.freeze !== undefined) {
        throw new TypeError("Scientific confirmation may be frozen only once");
    }
    if (cohort?.resolved !== true
        || (cohort.status !== "UNIQUE_BEST"
            && cohort.status !== "TIE_COHORT")
        || !Array.isArray(cohortEvidence)
        || cohortEvidence.length === 0
        || cohortEvidence.length !== cohort.cohort.length) {
        throw new TypeError(
            "Scientific confirmation requires a resolved provisional cohort",
        );
    }
    if (cohortEvidence.length
        > aggregate.contract.statisticalPolicy.maxConfirmations) {
        throw new RangeError(
            "The provisional cohort exceeds the frozen confirmation capacity",
        );
    }
    const discoveryHead = immutableCanonical({
        seq: aggregate.lastSeq,
        eventHash: aggregate.lastEventHash,
        scientificReplayClosureRoot:
            aggregate.scientificReplay?.closureRoot ?? null,
        rawAuthorityRoot:
            aggregate.scientificReplay?.rawAuthorityRoot ?? null,
        candidateComparisonHash: cohort.comparisonHash,
        relationEvidenceHash: cohort.relationEvidenceHash,
        searchStrategyRevision: aggregate.searchStrategy.revision,
        searchStrategyHistoryHash: hashCanonical(
            aggregate.searchStrategy.history,
            "sha256:crucible-confirmation-discovery-strategy-v1",
        ),
    });
    const members = cohortEvidence.map((evidence, memberOrdinal) => {
        const observation = ownEntry(
            aggregate.observations,
            evidence.observationId,
        );
        const command = ownEntry(
            aggregate.commands,
            observation?.commandId,
        )?.command ?? null;
        if (evidence.invalidated === true
            || !isAlgorithmTaggedSha256(evidence.commitEventHash)
            || !isAlgorithmTaggedSha256(
                evidence.receipt?.candidateArtifactHash,
            )
            || command?.kind !== "search_candidate"
            || !Object.hasOwn(command, "hypotheses")
            || !canonicalEqual(
                command.hypotheses,
                evidence.annotations?.hypotheses ?? null,
            )
            || evidence.hypothesesIdentity
                !== (command.hypotheses?.identity ?? null)
            || !isAlgorithmTaggedSha256(
                evidence.replication?.control?.controlBindingHash,
            )) {
            throw new TypeError(
                "Scientific confirmation cannot freeze invalid candidate evidence",
            );
        }
        const member = {
            memberOrdinal,
            candidateId: evidence.candidateId,
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash,
            provenanceRoot: evidence.provenanceRoot,
            candidateArtifactHash:
                evidence.receipt.candidateArtifactHash,
            hypotheses: command.hypotheses,
            hypothesesIdentity: evidence.hypothesesIdentity,
            control: evidence.replication.control,
        };
        return {
            ...member,
            roles: Object.fromEntries(
                SCIENTIFIC_CONFIRMATION_ROLES.map((role) => [
                    role,
                    frozenRoleProtocol({
                        aggregate,
                        discoveryHead,
                        member: evidence,
                        memberOrdinal,
                        role,
                    }),
                ]),
            ),
            unspentGuardSubjectIndex: statisticalSubjectIndex(
                "candidate",
                searchSubjectCapacity(aggregate.contract)
                    + memberOrdinal * CONFIRMATION_SUBJECT_STRIDE
                    + 2,
            ),
        };
    });
    const core = {
        version: SCIENTIFIC_CONFIRMATION_VERSION,
        contractHash: aggregate.contractHash,
        statisticalPolicyIdentity:
            aggregate.contract.statisticalPolicyIdentity,
        discoveryHead,
        discoveryClosure: {
            basis,
            cohortStatus: cohort.status,
            candidateIds: members.map((member) => member.candidateId),
            evidenceIds: members.map((member) => member.evidenceId),
            evidenceHashes: members.map((member) => member.evidenceHash),
            cohortComparisonHash: cohort.comparisonHash,
            relationEvidenceHash: cohort.relationEvidenceHash,
        },
        members,
        noReuse: true,
        noPostConfirmationSearch: true,
    };
    return immutableCanonical({
        ...core,
        freezeHash: hashCanonical(
            core,
            SCIENTIFIC_CONFIRMATION_FREEZE_HASH_ALGORITHM,
        ),
    });
}

function scientificConfirmationEvidenceItems(
    aggregate,
    role = null,
    { includeInvalidated = true } = {},
) {
    return immutableCanonical(
        aggregate.evidenceOrder
            .map((evidenceId) => ownEntry(aggregate.evidence, evidenceId))
            .filter((evidence) =>
                evidence !== null
                && evidence.sourceKind === "harness"
                && SCIENTIFIC_CONFIRMATION_ROLES.includes(evidence.purpose)
                && (role === null || evidence.purpose === role)
                && (includeInvalidated || evidence.invalidated !== true)),
    );
}

function roleEvidenceState(aggregate, freeze, member, role) {
    const matches = scientificConfirmationEvidenceItems(aggregate, role)
        .filter((evidence) =>
            evidence.confirmationFreezeHash === freeze.freezeHash
            && evidence.candidateEvidenceId === member.evidenceId);
    if (matches.length === 0) {
        return {
            role,
            status: "PENDING",
            evidence: null,
        };
    }
    if (matches.length !== 1) {
        return {
            role,
            status: "INVALID",
            evidence: null,
        };
    }
    const evidence = matches[0];
    const observation = ownEntry(
        aggregate.observations,
        evidence.observationId,
    );
    const command = ownEntry(
        aggregate.commands,
        observation?.commandId,
    )?.command ?? null;
    const protocol = member.roles[role];
    const validBinding = evidence.invalidated !== true
        && evidence.candidateId === member.candidateId
        && evidence.candidateEvidenceHash === member.evidenceHash
        && evidence.receipt?.candidateArtifactHash
            === member.candidateArtifactHash
        && evidence.roleManifestHash
            === protocol.roleManifest.roleManifestHash
        && evidence.protocolManifestHash
            === protocol.protocolManifestHash
        && evidence.replication?.scheduleHash
            === protocol.replicationSchedule.scheduleHash
        && evidence.hypothesesIdentity === member.hypothesesIdentity
        && canonicalEqual(
            evidence.annotations?.hypotheses ?? null,
            member.hypotheses,
        )
        && canonicalEqual(
            evidence.replication?.control ?? null,
            protocol.control,
        )
        && command?.confirmationFreezeHash === freeze.freezeHash
        && command?.candidateEvidenceId === member.evidenceId
        && canonicalEqual(command?.hypotheses ?? null, member.hypotheses)
        && canonicalEqual(command?.protocolManifest, protocol);
    return {
        role,
        status: validBinding
            ? evidence.statisticalEvaluation?.requiredState ?? "INVALID"
            : "INVALID",
        evidence,
    };
}

function roleClosure(item) {
    if (item.evidence === null) {
        return {
            role: item.role,
            status: item.status,
            evidenceId: null,
            evidenceHash: null,
            provenanceRoot: null,
            rawAuthorityDigest: null,
            scheduleHash: null,
            evaluationHash: null,
            alphaUseHash: null,
            hypothesesIdentity: null,
            controlBindingHash: null,
        };
    }
    const claims =
        item.evidence.statisticalEvaluation?.statistics?.claims ?? [];
    return {
        role: item.role,
        status: item.status,
        evidenceId: item.evidence.evidenceId,
        evidenceHash: item.evidence.commitEventHash,
        provenanceRoot: item.evidence.provenanceRoot,
        rawAuthorityDigest: item.evidence.rawAuthorityDigest,
        scheduleHash: item.evidence.replication?.scheduleHash ?? null,
        evaluationHash:
            item.evidence.statisticalEvaluation?.evaluationHash ?? null,
        alphaUseHash: hashCanonical(
            claims.map((claim) => ({
                claimId: claim.id,
                state: claim.state,
                allocation: claim.allocation ?? null,
            })),
            SCIENTIFIC_CONFIRMATION_ALPHA_USE_HASH_ALGORITHM,
        ),
        hypothesesIdentity: item.evidence.hypothesesIdentity ?? null,
        controlBindingHash:
            item.evidence.replication?.control?.controlBindingHash ?? null,
    };
}

export function deriveScientificConfirmationState(aggregate) {
    const stored = aggregate?.confirmation?.freeze ?? null;
    if (stored === null) {
        return immutableCanonical({
            version: SCIENTIFIC_CONFIRMATION_VERSION,
            status: "NOT_FROZEN",
            ready: false,
            failed: false,
            freezeHash: null,
            members: [],
            closureHash: null,
        });
    }
    const freeze = stored.payload ?? stored;
    const candidateEvidenceAppendedAfterFreeze =
        aggregate.evidenceOrder.some((evidenceId) => {
            const evidence = ownEntry(aggregate.evidence, evidenceId);
            return evidence?.sourceKind === "harness"
                && evidence?.purpose === "candidate"
                && evidence.committedSeq > stored.seq;
        });
    const members = freeze.members.map((member) => {
        const discoveryEvidence = ownEntry(
            aggregate.evidence,
            member.evidenceId,
        );
        const roles = SCIENTIFIC_CONFIRMATION_ROLES.map((role) =>
            roleEvidenceState(aggregate, freeze, member, role));
        const discoveryBound = discoveryEvidence !== null
            && discoveryEvidence.invalidated !== true
            && discoveryEvidence.commitEventHash === member.evidenceHash
            && discoveryEvidence.receipt?.candidateArtifactHash
                === member.candidateArtifactHash
            && discoveryEvidence.hypothesesIdentity
                === member.hypothesesIdentity
            && canonicalEqual(
                discoveryEvidence.annotations?.hypotheses ?? null,
                member.hypotheses,
            )
            && canonicalEqual(
                discoveryEvidence.replication?.control ?? null,
                member.control,
            );
        const statuses = roles.map((item) => item.status);
        const status = !discoveryBound
            || statuses.some((state) =>
                state === "REFUTED"
                || state === "INVALID"
                || state === "UNRESOLVED")
            ? "FAILED"
            : statuses.every((state) => state === "SUPPORTED")
                ? "READY"
                : "PENDING";
        return {
            memberOrdinal: member.memberOrdinal,
            candidateId: member.candidateId,
            evidenceId: member.evidenceId,
            evidenceHash: member.evidenceHash,
            discoveryBound,
            status,
            roles: roles.map(roleClosure),
        };
    });
    const failed = candidateEvidenceAppendedAfterFreeze
        || members.some((member) => member.status === "FAILED");
    const ready = !failed
        && members.length > 0
        && members.every((member) => member.status === "READY");
    const status = failed ? "FAILED" : ready ? "READY" : "PENDING";
    const closureCore = {
        version: SCIENTIFIC_CONFIRMATION_VERSION,
        freezeHash: freeze.freezeHash,
        discoveryHead: freeze.discoveryHead,
        candidateEvidenceAppendedAfterFreeze,
        status,
        members,
    };
    return immutableCanonical({
        ...closureCore,
        ready,
        failed,
        closureHash: hashCanonical(
            closureCore,
            SCIENTIFIC_CONFIRMATION_CLOSURE_HASH_ALGORITHM,
        ),
    });
}

export function nextScientificConfirmationCommand(aggregate) {
    const freeze = aggregate?.confirmation?.freeze?.payload
        ?? aggregate?.confirmation?.freeze
        ?? null;
    if (freeze === null) return null;
    const state = deriveScientificConfirmationState(aggregate);
    if (state.failed || state.ready) return null;
    for (const role of SCIENTIFIC_CONFIRMATION_ROLES) {
        for (const member of freeze.members) {
            const memberState = state.members.find((item) =>
                item.evidenceId === member.evidenceId);
            const roleState = memberState?.roles.find((item) =>
                item.role === role);
            if (roleState?.status !== "PENDING") continue;
            const protocol = member.roles[role];
            return immutableCanonical({
                kind: role === "confirmation"
                    ? "run_confirmation"
                    : "run_challenge",
                harnessRole: role,
                harnessId: protocol.roleManifest.harnessId,
                parserVersion: protocol.roleManifest.parser.version,
                confirmationFreezeHash: freeze.freezeHash,
                memberOrdinal: member.memberOrdinal,
                candidateId: member.candidateId,
                candidateEvidenceId: member.evidenceId,
                candidateEvidenceHash: member.evidenceHash,
                candidateArtifactHash: member.candidateArtifactHash,
                roleManifestHash:
                    protocol.roleManifest.roleManifestHash,
                protocolManifest: protocol,
                protocolManifestHash: protocol.protocolManifestHash,
                hypotheses: protocol.hypotheses,
                replicationSchedule: protocol.replicationSchedule,
            });
        }
    }
    return null;
}
