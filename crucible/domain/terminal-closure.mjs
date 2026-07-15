import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import { buildCandidateArchive } from "./archive.mjs";
import { artifactRefsFromProvenance } from "./evidence.mjs";
import { deriveUnreachableCoverageClosure } from "./impossibility.mjs";
import {
    deriveScientificConclusion,
    scientificReplaySummary,
} from "./scientific-replay.mjs";
import {
    candidateCohortState,
    currentValidationEvidence,
    searchProgress,
} from "./state.mjs";
import { detectPlateau } from "./strategy.mjs";
import {
    verifiedImpossibilityExecutionFor,
} from "./private-verifier-execution.mjs";

export const TERMINAL_EVIDENCE_CLOSURE_VERSION =
    "crucible-terminal-evidence-closure-v2";
export const TERMINAL_EVIDENCE_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-terminal-evidence-closure-v2";

const TERMINAL_AUTHORITY_CLOSURE_VERSION =
    "crucible-terminal-authority-closure-v1";
const TERMINAL_AUTHORITY_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-terminal-authority-closure-v1";
const TERMINAL_AUTHORITY_SIGNATURE_HASH_ALGORITHM =
    "sha256:crucible-terminal-authority-signature-v1";
const TERMINAL_RUNTIME_IDENTITIES_HASH_ALGORITHM =
    "sha256:crucible-terminal-runtime-identities-v1";
const TERMINAL_RUNTIME_SECURITY_HASH_ALGORITHM =
    "sha256:crucible-terminal-runtime-security-v1";
const TERMINAL_RUNTIME_SANDBOX_HASH_ALGORITHM =
    "sha256:crucible-terminal-runtime-sandbox-v1";
const TERMINAL_HARNESS_ROLES_HASH_ALGORITHM =
    "sha256:crucible-terminal-harness-roles-v1";
const TERMINAL_ARTIFACT_CLOSURE_VERSION =
    "crucible-terminal-artifact-closure-v1";
const TERMINAL_ARTIFACT_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-terminal-artifact-closure-v1";
const TERMINAL_ARTIFACT_REFS_HASH_ALGORITHM =
    "sha256:crucible-terminal-artifact-refs-v1";
const TERMINAL_PROVENANCE_ROOTS_HASH_ALGORITHM =
    "sha256:crucible-terminal-provenance-roots-v1";
const TERMINAL_RECEIPT_ROOTS_HASH_ALGORITHM =
    "sha256:crucible-terminal-receipt-roots-v1";
const TERMINAL_FRONTIER_HASH_ALGORITHM =
    "sha256:crucible-terminal-frontier-v1";
const TERMINAL_ARCHIVE_HASH_ALGORITHM =
    "sha256:crucible-terminal-archive-v1";
const TERMINAL_BASIS_HASH_ALGORITHM =
    "sha256:crucible-terminal-basis-v1";
const TERMINAL_STRATEGY_HISTORY_HASH_ALGORITHM =
    "sha256:crucible-terminal-strategy-history-v1";
const TERMINAL_IMPOSSIBILITY_VERIFIER_VERSION =
    "crucible-terminal-impossibility-verifier-v2";
const TERMINAL_IMPOSSIBILITY_VERIFIER_HASH_ALGORITHM =
    "sha256:crucible-terminal-impossibility-verifier-v2";
const TERMINAL_IMPOSSIBILITY_REQUEST_HASH_ALGORITHM =
    "sha256:crucible-terminal-impossibility-request-v1";
const TERMINAL_IMPOSSIBILITY_OUTPUT_HASH_ALGORITHM =
    "sha256:crucible-terminal-impossibility-output-v1";
const TERMINAL_IMPOSSIBILITY_RECEIPT_HASH_ALGORITHM =
    "sha256:crucible-terminal-impossibility-receipt-v1";
const TERMINAL_IMPOSSIBILITY_PROPOSAL_HASH_ALGORITHM =
    "sha256:crucible-terminal-impossibility-proposal-v1";
const TERMINAL_UNREACHABLE_CONCLUSION_VERSION =
    "crucible-target-unreachable-conclusion-v2";
const TERMINAL_UNREACHABLE_CONCLUSION_HASH_ALGORITHM =
    "sha256:crucible-target-unreachable-conclusion-v2";

function evidenceReference(evidence) {
    if (evidence === null || evidence === undefined) {
        throw new TypeError("terminal closure requires persisted evidence");
    }
    return {
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        provenanceRoot: evidence.provenanceRoot,
    };
}

function projectArchiveEvidence(evidence) {
    return {
        candidateId: evidence.candidateId,
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        provenanceRoot: evidence.provenanceRoot,
        outcomeClass: evidence.outcomeClass,
        rankable: evidence.rankable,
        metrics: evidence.metrics,
        round: evidence.round,
        slotIndex: evidence.slotIndex,
    };
}

function terminalAuthorityClosure(aggregate) {
    const contract = aggregate?.contract;
    const authority = aggregate?.experimentAuthority;
    const manifest = authority?.manifest;
    const runtime = aggregate?.runtimeConfigAuthority;
    if (contract === null
        || contract === undefined
        || authority === null
        || authority === undefined
        || manifest === null
        || manifest === undefined
        || runtime === null
        || runtime === undefined
        || aggregate.experimentAuthorityIdentity !== authority.identity
        || aggregate.runtimeConfigFingerprint !== runtime.fingerprint) {
        throw new TypeError(
            "terminal closure requires canonical experiment and runtime authority",
        );
    }
    const core = {
        version: TERMINAL_AUTHORITY_CLOSURE_VERSION,
        domainVersion: aggregate.domainVersion,
        experiment: {
            authorityIdentity: authority.identity,
            manifestIdentity: authority.manifestIdentity,
            trustFingerprint: authority.trustFingerprint,
            signatureHash: hashCanonical({
                algorithm: authority.algorithm,
                signature: authority.signature,
            }, TERMINAL_AUTHORITY_SIGNATURE_HASH_ALGORITHM),
            investigationId: manifest.investigationId,
        },
        contract: {
            contractHash: aggregate.contractHash,
            signedContractHash: manifest.contractHash,
            harnessSuiteIdentity: contract.harnessSuiteIdentity,
            signedHarnessSuiteIdentity: manifest.harnessSuiteIdentity,
            statisticalPolicyIdentity: contract.statisticalPolicyIdentity,
            signedStatisticalPolicyIdentity:
                manifest.statisticalPolicyIdentity,
            hypothesisPolicyIdentity: contract.hypothesisPolicyIdentity,
            signedHypothesisPolicyIdentity:
                manifest.hypothesisPolicyIdentity,
            enumerandRoot: contract.enumerandManifest?.merkleRoot ?? null,
            signedEnumerandRoot: manifest.enumerandRoot,
            scientificTerminalPolicyVersion:
                contract.scientificTerminalPolicy.version,
        },
        harness: {
            suiteIdentity: contract.harnessSuiteIdentity,
            environmentIdentity:
                contract.harnessSuite.environmentIdentity ?? null,
            rolesRoot: hashCanonical(
                contract.harnessSuite.roles,
                TERMINAL_HARNESS_ROLES_HASH_ALGORITHM,
            ),
        },
        runtime: {
            fingerprint: runtime.fingerprint,
            identitiesHash: hashCanonical(
                runtime.identities,
                TERMINAL_RUNTIME_IDENTITIES_HASH_ALGORITHM,
            ),
            securityConfigHash: hashCanonical(
                runtime.securityConfig,
                TERMINAL_RUNTIME_SECURITY_HASH_ALGORITHM,
            ),
            sandboxHash: hashCanonical(
                runtime.sandbox,
                TERMINAL_RUNTIME_SANDBOX_HASH_ALGORITHM,
            ),
            workerAdditionalContextHash:
                runtime.workerAdditionalContextHash,
        },
    };
    return immutableCanonical({
        ...core,
        closureRoot: hashCanonical(
            core,
            TERMINAL_AUTHORITY_CLOSURE_HASH_ALGORITHM,
        ),
    });
}

function terminalArtifactClosure(aggregate) {
    const evidence = aggregate.evidenceOrder.map((evidenceId) => {
        const item = aggregate.evidence[evidenceId];
        const refs = item?.sourceKind === "harness"
            ? artifactRefsFromProvenance(item.receipt.provenance)
            : [];
        return {
            evidenceId,
            evidenceHash: item?.commitEventHash ?? null,
            sourceKind: item?.sourceKind ?? null,
            purpose: item?.purpose ?? null,
            invalidated: item?.invalidated === true,
            provenanceRoot: item?.provenanceRoot ?? null,
            rawAuthorityDigest: item?.rawAuthorityDigest ?? null,
            artifactRefs: refs,
        };
    });
    const artifactRefs = evidence.flatMap((item) =>
        item.artifactRefs.map((artifact) => ({
            evidenceId: item.evidenceId,
            purpose: item.purpose,
            artifactId: artifact.artifactId,
            objectId: artifact.objectId,
        })));
    const uniqueArtifacts = new Set(
        artifactRefs.map((artifact) =>
            `${artifact.artifactId}\0${artifact.objectId}`),
    );
    const purposeCounts = Object.fromEntries(
        [...new Set(evidence.map((item) => item.purpose).filter(Boolean))]
            .sort()
            .map((purpose) => [
                purpose,
                evidence.filter((item) => item.purpose === purpose).length,
            ]),
    );
    const provenanceRoots = evidence.map((item) => ({
        evidenceId: item.evidenceId,
        evidenceHash: item.evidenceHash,
        purpose: item.purpose,
        invalidated: item.invalidated,
        provenanceRoot: item.provenanceRoot,
        rawAuthorityDigest: item.rawAuthorityDigest,
    }));
    const core = {
        version: TERMINAL_ARTIFACT_CLOSURE_VERSION,
        evidenceCount: evidence.length,
        harnessEvidenceCount: evidence.filter((item) =>
            item.sourceKind === "harness").length,
        artifactReferenceCount: artifactRefs.length,
        uniqueArtifactCount: uniqueArtifacts.size,
        purposeCounts,
        artifactRefsRoot: hashCanonical(
            artifactRefs,
            TERMINAL_ARTIFACT_REFS_HASH_ALGORITHM,
        ),
        provenanceRootsRoot: hashCanonical(
            provenanceRoots,
            TERMINAL_PROVENANCE_ROOTS_HASH_ALGORITHM,
        ),
    };
    return immutableCanonical({
        ...core,
        closureRoot: hashCanonical(
            core,
            TERMINAL_ARTIFACT_CLOSURE_HASH_ALGORITHM,
        ),
    });
}

function terminalImpossibilityVerifierClosure(aggregate, evidence) {
    if (evidence === null || evidence === undefined) return null;
    const observation = aggregate.observations[evidence.observationId] ?? null;
    const command = observation === null
        ? null
        : aggregate.commands[observation.commandId]?.command ?? null;
    const measurement =
        evidence.receipt?.provenance?.measurements?.[0] ?? null;
    const certificateArtifact =
        evidence.receipt?.provenance?.impossibilityCertificateArtifact ?? null;
    if (command?.kind !== "verify_impossibility"
        || observation === null
        || measurement === null
        || certificateArtifact === null) {
        throw new TypeError(
            "terminal impossibility closure requires a complete verifier record",
        );
    }
    const execution = verifiedImpossibilityExecutionFor(
        aggregate,
        observation.observationId,
        observation.verifierExecution ?? null,
    );
    if (execution === null) {
        throw new TypeError(
            "terminal impossibility closure requires a code-verified execution reference",
        );
    }
    const facts = execution.facts;
    const core = {
        version: TERMINAL_IMPOSSIBILITY_VERIFIER_VERSION,
        commandId: observation.commandId,
        observationId: observation.observationId,
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        verifier: {
            harnessRole: command.harnessRole,
            harnessId: command.harnessId,
            parserVersion: command.parserVersion,
            roleIdentity: command.request?.verifier?.roleIdentity ?? null,
            executableHash:
                command.request?.verifier?.executableHash ?? null,
            applicationEntrypointHash:
                command.request?.verifier?.applicationEntrypointHash ?? null,
            parserSourceHash:
                command.request?.verifier?.parser?.sourceHash ?? null,
            independenceAttestation:
                command.request?.verifier?.independenceAttestation ?? null,
        },
        request: {
            requestHash: command.requestHash,
            coverageClosureRoot:
                command.request?.evidence?.coverageClosureRoot ?? null,
            objectManifestRoot:
                command.request?.objectManifest?.root ?? null,
            requestRoot: hashCanonical(
                command.request,
                TERMINAL_IMPOSSIBILITY_REQUEST_HASH_ALGORITHM,
            ),
        },
        proposal: {
            artifactHash: command.proposedCertificateArtifactHash,
            proposalRoot: hashCanonical(
                command.proposedCertificate,
                TERMINAL_IMPOSSIBILITY_PROPOSAL_HASH_ALGORITHM,
            ),
        },
        proof: {
            artifactHash: execution.proof.artifactHash,
            artifact: execution.proof.artifact,
            sizeBytes: execution.proof.sizeBytes,
            checkerIdentity:
                command.request?.verifier?.proofChecker?.identity ?? null,
        },
        output: {
            checkerStatus: facts.status,
            certificateVerdict: facts.verdict,
            complete: facts.complete === true,
            disagreementCount: facts.disagreementCount,
            checkerEvidenceRoot: facts.checkerEvidenceRoot,
            verifierFactsRoot: facts.factsRoot,
            enumerandObservationsRoot: hashCanonical(
                facts.enumerandObservations,
                "sha256:crucible-terminal-impossibility-enumerand-observations-v1",
            ),
            outputRoot: hashCanonical(
                facts,
                TERMINAL_IMPOSSIBILITY_OUTPUT_HASH_ALGORITHM,
            ),
        },
        receipt: {
            provenanceRoot: evidence.provenanceRoot,
            measurementRoot: measurement.measurementRoot,
            measurementReceiptHash:
                evidence.receipt.measurementReceiptHash ?? null,
            measurementReceiptArtifact:
                measurement.receiptArtifact,
            rawStdoutArtifact: measurement.rawStdoutArtifact,
            rawStderrArtifact: measurement.rawStderrArtifact,
            verificationSnapshotHash:
                evidence.receipt.verificationSnapshotHash ?? null,
            executionIdentity:
                execution.executionIdentity.identity,
            effectBinding: execution.effectBinding,
            receiptRoot: hashCanonical(
                evidence.receipt,
                TERMINAL_IMPOSSIBILITY_RECEIPT_HASH_ALGORITHM,
            ),
        },
        certificate: {
            artifact: execution.certificate.artifact,
            artifactHash: execution.certificate.artifactHash,
            sizeBytes: execution.certificate.sizeBytes,
            certificateRoot: hashCanonical(
                observation.data?.checkerResult?.certificate ?? null,
                "sha256:crucible-terminal-impossibility-certificate-v1",
            ),
        },
    };
    return immutableCanonical({
        ...core,
        closureRoot: hashCanonical(
            core,
            TERMINAL_IMPOSSIBILITY_VERIFIER_HASH_ALGORITHM,
        ),
    });
}

function unreachableConclusion(
    aggregate,
    coverage,
    verifier,
) {
    const core = {
        version: TERMINAL_UNREACHABLE_CONCLUSION_VERSION,
        authority: "replay_derived_statistical_kernel",
        decision: "TARGET_UNREACHABLE",
        contractHash: aggregate.contractHash,
        scientificReplayClosureRoot:
            aggregate.scientificReplay.closureRoot,
        coverage: {
            topology: aggregate.contract.hypothesisTopology,
            enumerandCount: coverage.manifest.count,
            enumerandManifestRoot: coverage.manifest.merkleRoot,
            coverageClosureRoot: coverage.closureRoot,
            enumerandEvidenceRoot: coverage.enumerandEvidenceRoot,
            rawBlockRoots: coverage.rawBlockRoots,
            roleReceiptsRoot: coverage.roleReceiptsRoot,
            alphaAllocationsRoot: coverage.alphaAllocationsRoot,
            alphaLedgerRoot: coverage.alphaLedgerRoot,
        },
        verifier: {
            closureRoot: verifier.closureRoot,
            checkerStatus: verifier.output.checkerStatus,
            certificateVerdict: verifier.output.certificateVerdict,
            requestHash: verifier.request.requestHash,
            checkerEvidenceRoot: verifier.output.checkerEvidenceRoot,
            verifierFactsRoot: verifier.output.verifierFactsRoot,
            enumerandObservationsRoot:
                verifier.output.enumerandObservationsRoot,
            independenceAttestation:
                verifier.verifier.independenceAttestation,
        },
        assumptions: [{
            code: "OPERATOR_ATTESTED_VERIFIER_INDEPENDENCE",
            note:
                "Verifier separation is operator-attested and bound to distinct executable/application identities; mathematical independence is not proven.",
        }],
        limitations: [{
            code: "FROZEN_ENUMERAND_SCOPE_ONLY",
            note:
                "TARGET_UNREACHABLE applies only to the immutable signed enumerand manifest, harness suite, contract, and verifier closure.",
        }],
    };
    return immutableCanonical({
        ...core,
        conclusionHash: hashCanonical(
            core,
            TERMINAL_UNREACHABLE_CONCLUSION_HASH_ALGORITHM,
        ),
    });
}

export function deriveTerminalEvidenceClosure(
    aggregate,
    {
        basis,
        decisiveKind,
        decisiveEvidence = null,
    },
) {
    const decisiveEvidenceItems = Array.isArray(decisiveEvidence)
        ? decisiveEvidence
        : decisiveEvidence === null
            ? []
            : [decisiveEvidence];
    const candidateCohort = candidateCohortState(aggregate);
    const validation = currentValidationEvidence(aggregate);
    const receiptRoots = aggregate.evidenceOrder.flatMap((evidenceId) => {
        const evidence = aggregate.evidence[evidenceId];
        if (evidence.receipt?.provenance?.measurements === undefined) {
            return [];
        }
        return evidence.receipt.provenance.measurements.map((measurement) => ({
            evidenceId,
            evidenceHash: evidence.commitEventHash,
            provenanceRoot: evidence.provenanceRoot,
            subjectId: measurement.subjectId,
            measurementRoot: measurement.measurementRoot,
            invalidated: evidence.invalidated,
            invalidatedSeq: evidence.invalidatedSeq,
        }));
    });
    const progress = searchProgress(aggregate);
    const plateau = detectPlateau(aggregate);
    const frontierProjection = {
        active: progress.candidates.map((evidence) =>
            projectArchiveEvidence(evidence)),
        attempted: progress.attemptedCandidates.map((evidence) => ({
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash,
            provenanceRoot: evidence.provenanceRoot,
            invalidated: evidence.invalidated,
            invalidatedSeq: evidence.invalidatedSeq,
            round: evidence.round,
            slotIndex: evidence.slotIndex,
        })),
        completedRounds: progress.completedRounds,
        nextRound: progress.nextRound,
        nextSlot: progress.nextSlot,
        roundsExhausted: progress.roundsExhausted,
        boundedComplete: progress.boundedComplete,
        boundedAttempted: progress.boundedAttempted,
    };
    const archive = buildCandidateArchive(aggregate);
    const archiveProjection = {
        accepted: archive.accepted.map(projectArchiveEvidence),
        nearMisses: archive.nearMisses.map(projectArchiveEvidence),
        rejected: archive.rejected.map(projectArchiveEvidence),
        invalidMetrics: archive.invalidMetrics.map(projectArchiveEvidence),
        mechanismGroups: archive.mechanismGroups,
        lessonGroups: archive.lessonGroups,
        duplicateIndex: archive.duplicateIndex,
        incumbent: archive.incumbent === null
            ? null
            : projectArchiveEvidence(archive.incumbent),
    };
    const unreachableCoverage = decisiveKind === "impossibility_certificate"
        ? deriveUnreachableCoverageClosure(aggregate)
        : null;
    const verifier = decisiveKind === "impossibility_certificate"
        ? terminalImpossibilityVerifierClosure(
            aggregate,
            decisiveEvidenceItems[0] ?? null,
        )
        : null;
    const coverageSummary = unreachableCoverage?.eligible === true
        ? {
            version: unreachableCoverage.closure.version,
            manifest: unreachableCoverage.closure.manifest,
            closureRoot: unreachableCoverage.closure.closureRoot,
            enumerandEvidenceRoot:
                unreachableCoverage.closure.enumerandEvidenceRoot,
            invalidationsRoot:
                unreachableCoverage.closure.invalidationsRoot,
            rawBlockRoots:
                unreachableCoverage.closure.rawBlockRoots,
            roleReceiptsRoot:
                unreachableCoverage.closure.roleReceiptsRoot,
            alphaAllocationsRoot:
                unreachableCoverage.closure.alphaAllocationsRoot,
            scientificReplayRoot:
                unreachableCoverage.closure.scientificReplayRoot,
            alphaLedgerRoot:
                unreachableCoverage.closure.alphaLedgerRoot,
        }
        : null;
    const candidateConclusions = decisiveKind === "candidate_cohort"
        ? decisiveEvidenceItems.map((evidence) =>
            deriveScientificConclusion(
                aggregate,
                evidence.evidenceId,
            ))
        : [];
    const scientificConclusion = decisiveKind === "candidate_cohort"
        && candidateConclusions.length === 1
        ? candidateConclusions[0]
        : decisiveKind === "impossibility_certificate"
            && coverageSummary !== null
            && verifier !== null
            ? unreachableConclusion(
                aggregate,
                coverageSummary,
                verifier,
            )
            : null;
    const core = {
        version: TERMINAL_EVIDENCE_CLOSURE_VERSION,
        authority: terminalAuthorityClosure(aggregate),
        artifacts: terminalArtifactClosure(aggregate),
        validation: evidenceReference(validation),
        decisive: {
            kind: decisiveKind,
            evidence: decisiveEvidenceItems.length === 1
                ? evidenceReference(decisiveEvidenceItems[0])
                : null,
            cohort: decisiveEvidenceItems.map(evidenceReference),
        },
        termination: {
            kind: basis.kind,
            basis,
            basisHash: hashCanonical(basis, TERMINAL_BASIS_HASH_ALGORITHM),
            strategyRevision: aggregate.searchStrategy.revision,
            strategyHistoryHash: hashCanonical(
                aggregate.searchStrategy.history,
                TERMINAL_STRATEGY_HISTORY_HASH_ALGORITHM,
            ),
            plateau,
        },
        receipts: {
            count: receiptRoots.length,
            evidenceCount: aggregate.evidenceOrder.length,
            root: hashCanonical(
                receiptRoots,
                TERMINAL_RECEIPT_ROOTS_HASH_ALGORITHM,
            ),
        },
        frontier: {
            activeCandidateCount: progress.candidates.length,
            attemptedCandidateCount: progress.attemptedCandidates.length,
            digest: hashCanonical(
                frontierProjection,
                TERMINAL_FRONTIER_HASH_ALGORITHM,
            ),
        },
        archive: {
            acceptedCount: archive.accepted.length,
            nearMissCount: archive.nearMisses.length,
            rejectedCount: archive.rejected.length,
            invalidMetricsCount: archive.invalidMetrics.length,
            digest: hashCanonical(
                archiveProjection,
                TERMINAL_ARCHIVE_HASH_ALGORITHM,
            ),
        },
        scientificReplay: scientificReplaySummary(
            aggregate.scientificReplay,
        ),
        scientificConfirmation:
            aggregate.scientificReplay?.confirmationState ?? null,
        unreachableCoverage: coverageSummary,
        unreachableVerifier: verifier,
        candidateCohort: decisiveKind === "candidate_cohort"
            ? candidateCohort
            : null,
        relationEvidence: decisiveKind === "candidate_cohort"
            ? {
                comparisonHash: candidateCohort?.comparisonHash ?? null,
                relationEvidenceHash:
                    candidateCohort?.relationEvidenceHash ?? null,
                status: candidateCohort?.status ?? null,
                decisiveRelations:
                    candidateCohort?.decisiveRelations ?? [],
            }
            : null,
        scientificConclusion,
        scientificConclusions: candidateConclusions,
    };
    return immutableCanonical({
        ...core,
        closureRoot: hashCanonical(
            core,
            TERMINAL_EVIDENCE_CLOSURE_HASH_ALGORITHM,
        ),
    });
}

export function terminalEvidenceClosureMatches(
    aggregate,
    terminal,
    decisiveEvidence,
) {
    try {
        const decisiveKind = terminal?.decision === "VERIFIED_RESULT"
            ? "candidate_cohort"
            : terminal?.decision === "TARGET_UNREACHABLE"
                ? "impossibility_certificate"
                : null;
        if (decisiveKind === null) return false;
        const expected = deriveTerminalEvidenceClosure(aggregate, {
            basis: terminal.basis,
            decisiveKind,
            decisiveEvidence,
        });
        return canonicalEqual(terminal.evidenceClosure, expected);
    } catch {
        return false;
    }
}
