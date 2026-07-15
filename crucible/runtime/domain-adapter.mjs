import {
    DOMAIN_VERSION,
    EVENT_TYPES,
    IMPOSSIBILITY_PROOF_ARTIFACT_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_HASH_ALGORITHM,
    OBSERVATION_STREAM_HASH_ALGORITHM,
    SNAPSHOT_EXECUTION_HASH_ALGORITHM,
    artifactRefsFromProvenance,
    assertExperimentAuthorityContractBinding,
    canonicalEqual,
    canonicalJson,
    contractHash,
    createInvestigationContract,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    createExternalEvent,
    createInvestigationOpenedEvent,
    createMeasurementProvenance,
    createSnapshotProvenance,
    deriveReplicationControlBinding,
    enumerandArtifactMeasurementHash,
    enumerandBindingHash,
    hashCanonical,
    immutableCanonical,
    normalizeRawMeasurementSeries,
    normalizeReplicationSchedule,
    replicationBlockPlan,
    normalizeRuntimeConfigAuthority,
    reduceEvent,
    replayEvents,
    materializeScientificReplayState,
    scientificReplaySummary,
    verifyEventChain,
} from "../domain/index.mjs";
import {
    readVerifiedExperimentAuthority,
} from "../api/experiment-authority.mjs";
import {
    ERROR_CODES as PERSISTENCE_ERROR_CODES,
    sha256Hex,
} from "../persistence/index.mjs";
import {
    HARNESS_SUITE_RECEIPT_VERSION,
    STREAM_HASH_ALGORITHM,
    hashReceipt,
    parseImpossibilityVerifierResult,
    sha256Bytes,
    trustedParserIdentity,
} from "../measurement/index.mjs";
import {
    issueVerifiedImpossibilityExecutionCapability,
} from "../domain/private-verifier-execution.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    RuntimeIntegrityError,
} from "./errors.mjs";
import {
    requireIdentifier,
    requirePlainObject,
    requireString,
    taggedHash,
} from "./utils.mjs";
import { PROMPT_CONTEXT_HASH_ALGORITHM } from "./prompt-context.mjs";

const DOMAIN_KIND_PREFIX = `domain:v${DOMAIN_VERSION}:`;
const OPERATIONAL_INVESTIGATION_SUFFIX = ".runtime-evidence";
const TERMINAL_METADATA = Object.freeze({
    [EVENT_TYPES.VERIFIED_RESULT]: "verified_result",
    [EVENT_TYPES.TARGET_UNREACHABLE]: "target_unreachable",
});
const SNAPSHOT_CLOSURE_HASH_RE =
    /^sha256:crucible-measurement-snapshot-closure-v1:[a-f0-9]{64}$/u;
const SNAPSHOT_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-measurement-snapshot-closure-v1";
const DOMAIN_FACT_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-runtime-domain-fact-v1";
const IMPOSSIBILITY_CERTIFICATE_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-certificate-artifact-v2";
const IMPOSSIBILITY_RECEIPT_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-receipt-artifact-v1";
const IMPOSSIBILITY_STDOUT_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-stdout-artifact-v1";
const IMPOSSIBILITY_STDERR_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-stderr-artifact-v1";
const IMPOSSIBILITY_REQUEST_FILENAME = "request.json";
const IMPOSSIBILITY_PROPOSAL_FILENAME = "proposed-certificate.json";
const IMPOSSIBILITY_PROOF_FILENAME = "proof-artifact.json";
const VERIFIED_IMPOSSIBILITY_EXECUTION_VERSION =
    "crucible-verified-impossibility-execution-v1";
const VERIFIED_IMPOSSIBILITY_EXECUTION_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-verified-impossibility-execution-identity-v1";
const VERIFIED_IMPOSSIBILITY_ENUMERAND_OBSERVATION_HASH_ALGORITHM =
    "sha256:crucible-verified-impossibility-enumerand-observation-v1";
const VERIFIED_IMPOSSIBILITY_CHECKER_RECEIPT_HASH_ALGORITHM =
    "sha256:crucible-verified-impossibility-checker-receipt-v1";
const VERIFIED_IMPOSSIBILITY_FACTS_HASH_ALGORITHM =
    "sha256:crucible-verified-impossibility-facts-v1";
const LOGICAL_EFFECT_KEY_HASH_ALGORITHM =
    "sha256:crucible-runtime-logical-effect-v1";
const MEASUREMENT_RECEIPT_KEYS = Object.freeze([
    "allowlistFileHash",
    "argvHash",
    "attemptId",
    "candidateSnapshotHash",
    "candidateSnapshotIdentitySummary",
    "candidateSnapshotMutationCheck",
    "candidateSnapshotPostClosureHash",
    "candidateSnapshotPreClosureHash",
    "completedAt",
    "dependencyHashes",
    "durationMs",
    "envHash",
    "executableHash",
    "exit",
    "harnessId",
    "harnessEntryHash",
    "launchFileBindings",
    "outputCapture",
    "parsed",
    "parserIdentity",
    "parserVersion",
    "runnerEpochId",
    "sandbox",
    "stagedCandidateSnapshotClosureHash",
    "stagedCandidateSnapshotHash",
    "stagedCandidateSnapshotIdentitySummary",
    "stagedDependencyHashes",
    "stagedExecutableHash",
    "startedAt",
    "stderrHash",
    "stdoutHash",
    "version",
]);
const HARNESS_SUITE_MEASUREMENT_RECEIPT_KEYS = Object.freeze([
    ...MEASUREMENT_RECEIPT_KEYS,
    "armId",
    "armIndex",
    "blockIndex",
    "deterministicSeed",
    "environmentIdentity",
    "phase",
    "replicateIndex",
    "role",
    "subjectId",
    "suiteIdentity",
]);

function isCasConflict(error) {
    return error?.code === PERSISTENCE_ERROR_CODES.CAS_CONFLICT;
}

function domainVersionOrNull(value) {
    return Number.isSafeInteger(value) && value > 0 ? value : null;
}

export function inspectInvestigationDomainCompatibility({
    repository,
    investigationId,
} = {}) {
    if (repository === null
        || typeof repository !== "object"
        || typeof repository.getInvestigation !== "function"
        || typeof repository.listEvents !== "function"
        || typeof repository.getHead !== "function") {
        throw new RuntimeConfigError(
            "inspectInvestigationDomainCompatibility requires an EventRepository",
        );
    }
    const id = requireIdentifier(investigationId, "investigationId");
    const investigation = repository.getInvestigation(id);
    if (investigation === null) {
        return Object.freeze({
            investigationId: id,
            present: false,
            compatibility: "absent",
            compatible: true,
            domainVersion: null,
            contractDomainVersion: null,
            eventCount: 0,
            headSeq: 0,
            readOnly: true,
            archiveable: false,
        });
    }

    const head = repository.getHead(id);
    const first = repository.listEvents(id, { fromSeq: 1, toSeq: 1 })[0] ?? null;
    const metadataDomainVersion = domainVersionOrNull(
        investigation.metadata?.domainVersion,
    );
    if (first === null) {
        const compatible = metadataDomainVersion === DOMAIN_VERSION;
        return Object.freeze({
            investigationId: id,
            present: true,
            compatibility: compatible ? "current_empty" : "incompatible",
            compatible,
            domainVersion: metadataDomainVersion,
            contractDomainVersion: null,
            eventCount: 0,
            headSeq: 0,
            readOnly: true,
            archiveable: false,
        });
    }

    const domainEvent = first.payload?.domainEvent ?? null;
    const eventDomainVersion = domainVersionOrNull(
        domainEvent?.payload?.domainVersion,
    );
    const contractDomainVersion = domainVersionOrNull(
        domainEvent?.payload?.contract?.domainVersion,
    );
    const currentKind =
        `${DOMAIN_KIND_PREFIX}${EVENT_TYPES.INVESTIGATION_OPENED}`;
    const compatible = first.seq === 1 && first.kind === currentKind;
    return Object.freeze({
        investigationId: id,
        present: true,
        compatibility: compatible ? "current" : "incompatible",
        compatible,
        domainVersion: eventDomainVersion ?? metadataDomainVersion,
        contractDomainVersion,
        eventCount: head.seq,
        headSeq: head.seq,
        readOnly: true,
        archiveable: false,
    });
}

export function assertInvestigationDomainCompatible(
    repository,
    investigationId,
) {
    const compatibility = inspectInvestigationDomainCompatibility({
        repository,
        investigationId,
    });
    if (!compatibility.compatible) {
        throw new RuntimeIntegrityError(
            "Persisted investigation does not match the active Crucible domain",
            {
                investigationId: compatibility.investigationId,
                expectedDomainVersion: DOMAIN_VERSION,
                actualDomainVersion: compatibility.domainVersion,
                contractDomainVersion: compatibility.contractDomainVersion,
                eventCount: compatibility.eventCount,
            },
        );
    }
    return compatibility;
}

function expectedTerminalKind(domainEvent) {
    return TERMINAL_METADATA[domainEvent.type] ?? null;
}

function domainFactIdentity(domainEvent) {
    return hashCanonical({
        type: domainEvent.type,
        payload: domainEvent.payload,
    }, DOMAIN_FACT_IDENTITY_HASH_ALGORITHM);
}

function integrityFailure(message, details = null, cause = null) {
    throw new RuntimeIntegrityError(
        message,
        details,
        cause === null ? undefined : { cause },
    );
}

function compareStable(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value, expected) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && canonicalEqual(Object.keys(value).sort(), [...expected].sort());
}

function dependencyIdentity(items) {
    if (!Array.isArray(items)) return null;
    return items.map((item) => ({
        role: item?.role ?? null,
        sha256: item?.sha256 ?? null,
    })).sort((left, right) =>
        compareStable(
            `${left.role ?? ""}\0${left.sha256 ?? ""}`,
            `${right.role ?? ""}\0${right.sha256 ?? ""}`,
        ));
}

function normalizedDependencies(items) {
    if (!Array.isArray(items)) return null;
    return items.map((item) => ({
        path: item?.path ?? null,
        role: item?.role ?? null,
        sha256: item?.sha256 ?? null,
    })).sort((left, right) =>
        compareStable(
            `${left.path ?? ""}\0${left.role ?? ""}\0${left.sha256 ?? ""}`,
            `${right.path ?? ""}\0${right.role ?? ""}\0${right.sha256 ?? ""}`,
        ));
}

function receiptHasCompleteOutput(receipt) {
    const capture = receipt?.outputCapture;
    if (capture === null
        || typeof capture !== "object"
        || capture.overflowed !== false
        || capture.truncated !== false) {
        return false;
    }
    return ["stdout", "stderr"].every((stream) => {
        const value = capture[stream];
        return value !== null
            && typeof value === "object"
            && Number.isSafeInteger(value.capBytes)
            && value.capBytes > 0
            && Number.isSafeInteger(value.totalObservedBytes)
            && value.totalObservedBytes >= 0
            && value.retainedBytes === value.totalObservedBytes
            && value.retainedBytes <= value.capBytes
            && value.overflowed === false
            && value.truncated === false;
    });
}

function receiptBindsExecutedBytes(receipt, snapshotHash) {
    const identity = receipt?.candidateSnapshotIdentitySummary;
    const stagedIdentity = receipt?.stagedCandidateSnapshotIdentitySummary;
    const mutation = receipt?.candidateSnapshotMutationCheck;
    return receipt?.version === HARNESS_SUITE_RECEIPT_VERSION
        && receipt.candidateSnapshotHash === snapshotHash
        && receipt.stagedCandidateSnapshotHash === snapshotHash
        && SNAPSHOT_CLOSURE_HASH_RE.test(
            receipt.stagedCandidateSnapshotClosureHash ?? "",
        )
        && stagedIdentity !== null
        && typeof stagedIdentity === "object"
        && Array.isArray(receipt.launchFileBindings)
        && receipt.launchFileBindings.some((file) =>
            file?.role === "candidate"
            && typeof file?.sha256 === "string")
        && SNAPSHOT_CLOSURE_HASH_RE.test(receipt.candidateSnapshotPreClosureHash ?? "")
        && receipt.candidateSnapshotPreClosureHash === receipt.candidateSnapshotPostClosureHash
        && identity !== null
        && typeof identity === "object"
        && identity.pre !== undefined
        && identity.post !== undefined
        && canonicalEqual(identity.pre, identity.post)
        && mutation?.status === "passed"
        && mutation.closureStable === true
        && mutation.identityStable === true
        && mutation.openHandleRehashStable === true
        && mutation.reparseStable === true
        && (receiptHasCompleteOutput(receipt) || receipt.parsed === null)
        && receipt.executableHash === receipt.stagedExecutableHash
        && canonicalEqual(
            dependencyIdentity(receipt.dependencyHashes),
            dependencyIdentity(receipt.stagedDependencyHashes),
        );
}

function snapshotExecutionHash(receipt) {
    return hashCanonical({
        stagedCandidateSnapshotHash: receipt.stagedCandidateSnapshotHash,
        stagedCandidateSnapshotClosureHash:
            receipt.stagedCandidateSnapshotClosureHash,
        stagedCandidateSnapshotIdentitySummary:
            receipt.stagedCandidateSnapshotIdentitySummary,
        candidateSnapshotPreClosureHash: receipt.candidateSnapshotPreClosureHash,
        candidateSnapshotPostClosureHash: receipt.candidateSnapshotPostClosureHash,
        candidateSnapshotIdentitySummary: receipt.candidateSnapshotIdentitySummary,
        candidateSnapshotMutationCheck: receipt.candidateSnapshotMutationCheck,
    }, SNAPSHOT_EXECUTION_HASH_ALGORITHM);
}

function snapshotClosureHash(snapshotId, manifest) {
    const directories = new Set();
    for (const entry of manifest.entries) {
        const segments = entry.path.split("/");
        for (let depth = 1; depth < segments.length; depth += 1) {
            directories.add(segments.slice(0, depth).join("/"));
        }
    }
    const expectedObjectClosure = [...new Set([
        snapshotId,
        ...manifest.entries.map((entry) => entry.object),
    ])].sort(compareStable);
    return hashCanonical({
        version: 1,
        snapshotId,
        expectedObjectClosure,
        directories: [...directories].sort(compareStable),
        files: manifest.entries.map((entry) => ({
            path: entry.path,
            size: entry.size,
            object: entry.object,
        })).sort((left, right) => compareStable(left.path, right.path)),
    }, SNAPSHOT_CLOSURE_HASH_ALGORITHM);
}

function sandboxPolicyFromReceipt(receipt) {
    return receipt.sandbox === null
        ? { kind: "none", sandboxId: null, environmentHash: null }
        : {
            kind: "sandbox",
            sandboxId: receipt.sandbox?.sandboxId,
            environmentHash: receipt.sandbox?.environmentHash,
        };
}

function expectedAssignment(command) {
    const assignment = {
        operator: command.operator,
        round: command.round,
        slotIndex: command.slotIndex,
        candidateId: command.candidateId,
        model: command.model,
        seed: command.seed,
        parentEvidenceIds: command.parentEvidenceIds,
        promptContextRefs: command.promptContextRefs,
    };
    if (command.boundedCandidateId !== undefined && command.boundedCandidateId !== null) {
        assignment.boundedCandidateId = command.boundedCandidateId;
    }
    return assignment;
}

function artifactReader(repository, artifactStore, investigationId) {
    if (artifactStore === null
        || typeof artifactStore !== "object"
        || typeof artifactStore.verifyObject !== "function"
        || typeof artifactStore.readObject !== "function"
        || typeof artifactStore.loadManifest !== "function") {
        throw new RuntimeConfigError("artifactStore must expose the read-only ArtifactStore API");
    }
    const records = new Map();
    const bytes = new Map();

    const verify = (artifact, label) => {
        const key = artifact.artifactId;
        const existing = records.get(key);
        if (existing !== undefined) {
            if (existing.objectId !== artifact.objectId) {
                integrityFailure("One terminal closure maps an artifact id to multiple objects", {
                    artifactId: key,
                    label,
                });
            }
            return existing;
        }
        const metadata = repository.getArtifact(artifact.artifactId);
        const expectedHash = artifact.objectId.slice("sha256:".length);
        if (metadata === null || metadata.investigationId !== investigationId) {
            integrityFailure("Terminal closure references missing artifact metadata", {
                artifactId: artifact.artifactId,
                label,
            });
        }
        if (!Number.isSafeInteger(metadata.sizeBytes) || metadata.sizeBytes < 0) {
            integrityFailure("Terminal closure artifact has incomplete size metadata", {
                artifactId: artifact.artifactId,
                label,
            });
        }

        if (metadata.storage !== "external") {
            integrityFailure("Terminal closure artifact storage kind is invalid", {
                artifactId: artifact.artifactId,
                label,
            });
        }
        if (metadata.durable !== true
            || metadata.hashAlgo !== "sha256"
            || metadata.hashValue !== expectedHash) {
            integrityFailure("Terminal closure external artifact metadata is inconsistent", {
                artifactId: artifact.artifactId,
                label,
            });
        }
        let probe;
        try {
            probe = artifactStore.verifyObject(artifact.objectId);
        } catch (error) {
            integrityFailure("Terminal closure external artifact could not be verified", {
                artifactId: artifact.artifactId,
                label,
            }, error);
        }
        if (probe.ok !== true || probe.size !== metadata.sizeBytes) {
            integrityFailure("Terminal closure external artifact is missing, corrupt, or size-mismatched", {
                artifactId: artifact.artifactId,
                label,
                reason: probe.reason ?? "size-mismatch",
            });
        }

        const record = { ...artifact, metadata };
        records.set(key, record);
        return record;
    };

    const read = (artifact, label) => {
        const record = verify(artifact, label);
        const cached = bytes.get(artifact.artifactId);
        if (cached !== undefined) return { record, bytes: cached };
        let content;
        try {
            content = artifactStore.readObject(artifact.objectId, { verify: true });
        } catch (error) {
            integrityFailure("Terminal closure artifact bytes could not be read", {
                artifactId: artifact.artifactId,
                label,
            }, error);
        }
        const buffer = Buffer.from(content);
        if (buffer.length !== record.metadata.sizeBytes) {
            integrityFailure("Terminal closure artifact bytes changed size while being read", {
                artifactId: artifact.artifactId,
                label,
            });
        }
        bytes.set(artifact.artifactId, buffer);
        return { record, bytes: buffer };
    };

    const readJson = (artifact, label) => {
        const stored = read(artifact, label);
        let value;
        try {
            value = JSON.parse(stored.bytes.toString("utf8"));
        } catch (error) {
            integrityFailure("Terminal closure JSON artifact is malformed", {
                artifactId: artifact.artifactId,
                label,
            }, error);
        }
        return { ...stored, value };
    };

    return {
        verify,
        read,
        readJson,
        count: () => records.size,
    };
}

function requiredArtifactRefs(domainEvent) {
    if ((domainEvent?.type !== EVENT_TYPES.COMMAND_OBSERVED
            && domainEvent?.type !== EVENT_TYPES.EVIDENCE_COMMITTED)
        || domainEvent.payload?.sourceKind !== "harness") {
        return [];
    }
    return artifactRefsFromProvenance(domainEvent.payload.receipt.provenance);
}

function assertArtifactBindings(repository, investigationId, seq, expectedRefs) {
    const actual = repository.listArtifactRefsForEvent(investigationId, seq);
    const expectedIds = expectedRefs.map((item) => item.artifactId).sort();
    const actualIds = actual.map((item) => item.artifactId).sort();
    if (!canonicalEqual(actualIds, expectedIds)) {
        throw new RuntimeIntegrityError(
            "Domain event artifact references do not match its provenance closure",
            { investigationId, seq, expectedIds, actualIds },
        );
    }
    for (const expected of expectedRefs) {
        const artifact = repository.getArtifact(expected.artifactId);
        const expectedHash = expected.objectId.slice("sha256:".length);
        if (artifact === null || artifact.investigationId !== investigationId) {
            throw new RuntimeIntegrityError(
                "Domain event provenance references missing or mismatched durable artifact metadata",
                {
                    investigationId,
                    seq,
                    artifactId: expected.artifactId,
                    objectId: expected.objectId,
                },
            );
        }
        if (artifact.storage !== "external"
            || artifact.durable !== true
            || artifact.hashAlgo !== "sha256"
            || artifact.hashValue !== expectedHash) {
            throw new RuntimeIntegrityError(
                "Domain event provenance references missing or mismatched durable external artifact metadata",
                {
                    investigationId,
                    seq,
                    artifactId: expected.artifactId,
                    objectId: expected.objectId,
                    storage: artifact.storage,
                },
            );
        }
    }
}

function assertRepositoryDomainRow(row) {
    if (row === null || typeof row !== "object") {
        throw new RuntimeIntegrityError("Repository event row is not an object");
    }
    const expectedKind = `${DOMAIN_KIND_PREFIX}${row.payload?.domainEvent?.type ?? ""}`;
    if (row.kind !== expectedKind) {
        throw new RuntimeIntegrityError("Repository event kind does not match its domain event", {
            seq: row.seq,
            kind: row.kind,
            expectedKind,
        });
    }
    const payloadKeys = Object.keys(row.payload ?? {}).sort();
    if (!canonicalEqual(payloadKeys, ["domainEvent"])) {
        throw new RuntimeIntegrityError(
            "Canonical domain repository payload must contain only domainEvent",
            { seq: row.seq, payloadKeys },
        );
    }
    if (row.attemptId !== null || row.evidenceKind !== null) {
        throw new RuntimeIntegrityError(
            "Canonical domain repository events cannot carry operational evidence keys",
            {
                seq: row.seq,
                attemptId: row.attemptId,
                evidenceKind: row.evidenceKind,
            },
        );
    }
    const domainEvent = row.payload.domainEvent;
    if (row.seq !== domainEvent?.seq) {
        throw new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.DOMAIN_SEQUENCE_MISMATCH,
            "Persistence sequence does not equal domain sequence",
            { persistenceSeq: row.seq, domainSeq: domainEvent?.seq ?? null },
        );
    }
    const terminalKind = expectedTerminalKind(domainEvent);
    if (row.isTerminal !== (terminalKind !== null) || row.terminalKind !== terminalKind) {
        throw new RuntimeIntegrityError(
            "Repository terminal metadata does not match the canonical domain event",
            {
                seq: row.seq,
                domainType: domainEvent?.type ?? null,
                isTerminal: row.isTerminal,
                terminalKind: row.terminalKind,
                expectedTerminalKind: terminalKind,
            },
        );
    }
    return domainEvent;
}

function verifySnapshotArtifactClosure(snapshot, label, reader, artifactStore) {
    const manifestRead = reader.read(snapshot.manifestArtifact, `${label} manifest`);
    if (manifestRead.record.metadata.storage !== "external") {
        integrityFailure("Snapshot manifests in terminal evidence must be external CAS objects", {
            artifactId: snapshot.manifestArtifact.artifactId,
            label,
        });
    }
    let status;
    try {
        status = artifactStore.verifySnapshot(snapshot.manifestArtifact.objectId);
    } catch (error) {
        integrityFailure("Snapshot closure verification failed", { label }, error);
    }
    if (status.ok !== true) {
        integrityFailure("Snapshot manifest or object closure is missing or corrupt", {
            label,
            reason: status.reason ?? null,
            missingCount: status.missing?.length ?? 0,
            corruptCount: status.corrupt?.length ?? 0,
        });
    }
    let manifest;
    try {
        manifest = artifactStore.loadManifest(snapshot.manifestArtifact.objectId);
    } catch (error) {
        integrityFailure("Snapshot manifest is invalid", { label }, error);
    }
    const expectedObjectIds = [...new Set(manifest.entries.map((entry) => entry.object))]
        .sort(compareStable);
    const suppliedObjectIds = snapshot.objectArtifacts
        .map((artifact) => artifact.objectId)
        .sort(compareStable);
    if (!canonicalEqual(expectedObjectIds, suppliedObjectIds)) {
        integrityFailure("Snapshot provenance does not enumerate its complete manifest closure", {
            label,
        });
    }
    const expectedSizes = new Map(
        manifest.entries.map((entry) => [entry.object, entry.size]),
    );
    const objectArtifacts = new Map();
    for (const artifact of snapshot.objectArtifacts) {
        const record = reader.verify(artifact, `${label} object`);
        if (record.metadata.sizeBytes !== expectedSizes.get(artifact.objectId)) {
            integrityFailure("Snapshot object size disagrees with its canonical manifest", {
                artifactId: artifact.artifactId,
                label,
            });
        }
        objectArtifacts.set(artifact.objectId, artifact);
    }
    const rebuilt = createSnapshotProvenance({
        snapshotHash: snapshot.snapshotHash,
        manifestArtifact: snapshot.manifestArtifact,
        objectArtifacts: snapshot.objectArtifacts,
    });
    if (!canonicalEqual(rebuilt, snapshot)) {
        integrityFailure("Snapshot provenance root is inconsistent", { label });
    }
    return { manifest, objectArtifacts };
}

function verifyMeasurementArtifactClosure(
    measurement,
    label,
    reader,
    artifactStore,
) {
    const receiptRead = reader.readJson(measurement.receiptArtifact, `${label} receipt`);
    const receipt = receiptRead.value;
    const expectedReceiptKeys =
        receipt?.version === HARNESS_SUITE_RECEIPT_VERSION
            ? HARNESS_SUITE_MEASUREMENT_RECEIPT_KEYS
            : MEASUREMENT_RECEIPT_KEYS;
    if (!exactKeys(receipt, expectedReceiptKeys)) {
        integrityFailure("Measurement receipt artifact does not contain the complete receipt schema", {
            artifactId: measurement.receiptArtifact.artifactId,
            label,
        });
    }
    if (hashReceipt(receipt) !== measurement.receiptHash
        || typeof receipt.harnessId !== "string"
        || receipt.harnessId.length === 0
        || receipt.role !== measurement.role
        || receipt.phase !== measurement.phase
        || receipt.parserVersion !== measurement.parserVersion
        || receipt.parserIdentity?.version !== receipt.parserVersion
        || receipt.allowlistFileHash !== measurement.allowlistFileHash
        || receipt.harnessEntryHash !== measurement.harnessEntryHash
        || receipt.executableHash !== measurement.executableHash
        || receipt.stagedExecutableHash !== measurement.stagedExecutableHash
        || !canonicalEqual(
            normalizedDependencies(receipt.dependencyHashes),
            measurement.dependencyHashes,
        )
        || !canonicalEqual(
            normalizedDependencies(receipt.stagedDependencyHashes),
            measurement.stagedDependencyHashes,
        )
        || receipt.argvHash !== measurement.argvHash
        || receipt.envHash !== measurement.envHash
        || !canonicalEqual(sandboxPolicyFromReceipt(receipt), measurement.sandboxPolicy)
        || receipt.stdoutHash !== measurement.rawStdoutHash
        || receipt.stderrHash !== measurement.rawStderrHash
        || snapshotExecutionHash(receipt) !== measurement.snapshotExecutionHash
        || !receiptBindsExecutedBytes(receipt, measurement.snapshot.snapshotHash)) {
        integrityFailure("Measurement receipt artifact disagrees with persisted provenance", {
            artifactId: measurement.receiptArtifact.artifactId,
            label,
        });
    }

    const snapshot = verifySnapshotArtifactClosure(
        measurement.snapshot,
        `${label} snapshot`,
        reader,
        artifactStore,
    );
    const expectedSnapshotClosureHash = snapshotClosureHash(
        measurement.snapshot.manifestArtifact.objectId,
        snapshot.manifest,
    );
    if (receipt.candidateSnapshotPreClosureHash !== expectedSnapshotClosureHash
        || receipt.candidateSnapshotPostClosureHash !== expectedSnapshotClosureHash) {
        integrityFailure("Measurement receipt snapshot closure digest is inconsistent", {
            artifactId: measurement.receiptArtifact.artifactId,
            label,
        });
    }
    const stdout = reader.read(measurement.rawStdoutArtifact, `${label} raw stdout`);
    const stderr = reader.read(measurement.rawStderrArtifact, `${label} raw stderr`);
    if (sha256Bytes(stdout.bytes, STREAM_HASH_ALGORITHM) !== measurement.rawStdoutHash
        || sha256Bytes(stderr.bytes, STREAM_HASH_ALGORITHM) !== measurement.rawStderrHash
        || receipt.outputCapture.stdout.retainedBytes !== stdout.bytes.length
        || receipt.outputCapture.stderr.retainedBytes !== stderr.bytes.length) {
        integrityFailure("Raw output artifact bytes disagree with the full measurement receipt", {
            label,
        });
    }

    const rebuilt = createMeasurementProvenance({
        subjectId: measurement.subjectId,
        role: receipt.role,
        phase: receipt.phase,
        receiptArtifact: measurement.receiptArtifact,
        receiptHash: hashReceipt(receipt),
        rawStdoutArtifact: measurement.rawStdoutArtifact,
        rawStdoutHash: receipt.stdoutHash,
        rawStderrArtifact: measurement.rawStderrArtifact,
        rawStderrHash: receipt.stderrHash,
        parserVersion: receipt.parserVersion,
        allowlistFileHash: receipt.allowlistFileHash,
        harnessEntryHash: receipt.harnessEntryHash,
        executableHash: receipt.executableHash,
        stagedExecutableHash: receipt.stagedExecutableHash,
        dependencyHashes: receipt.dependencyHashes,
        stagedDependencyHashes: receipt.stagedDependencyHashes,
        argvHash: receipt.argvHash,
        envHash: receipt.envHash,
        sandboxPolicy: sandboxPolicyFromReceipt(receipt),
        snapshot: measurement.snapshot,
        snapshotExecutionHash: snapshotExecutionHash(receipt),
    });
    if (!canonicalEqual(rebuilt, measurement)) {
        integrityFailure("Measurement provenance root is inconsistent", { label });
    }
    return {
        measurement,
        receipt,
        receiptBytes: receiptRead.bytes,
        stdoutBytes: stdout.bytes,
        stderrBytes: stderr.bytes,
        snapshot,
    };
}

export function candidateProposalAnnotationsMatch(
    proposal,
    observation,
) {
    return canonicalEqual(
        proposal?.annotations ?? null,
        observation?.annotations ?? null,
    );
}

function verifyProposalSnapshot(proposal, measurementResult, reader, label) {
    if (proposal === null
        || typeof proposal !== "object"
        || Array.isArray(proposal)
        || !Array.isArray(proposal.files)
        || proposal.files.length === 0) {
        integrityFailure("Candidate proposal artifact does not contain a complete proposal", {
            label,
        });
    }

    const proposed = proposal.files.map((file) => {
        if (file === null
            || typeof file !== "object"
            || typeof file.path !== "string"
            || typeof file.content !== "string") {
            integrityFailure("Candidate proposal artifact contains an invalid file", { label });
        }
        const content = Buffer.from(file.content, "utf8");
        return {
            path: file.path,
            size: content.length,
            object: `sha256:${sha256Hex(content)}`,
            content,
        };
    }).sort((left, right) => compareStable(left.path, right.path));
    if (new Set(proposed.map((file) => file.path)).size !== proposed.length
        || !canonicalEqual(
            proposed.map(({ content: _content, ...file }) => file),
            measurementResult.snapshot.manifest.entries,
        )) {
        integrityFailure("Candidate proposal files do not match the measured snapshot manifest", {
            label,
        });
    }
    for (const file of proposed) {
        const artifact = measurementResult.snapshot.objectArtifacts.get(file.object);
        if (artifact === undefined) {
            integrityFailure("Candidate proposal references a snapshot object outside the closure", {
                label,
                path: file.path,
            });
        }
        const stored = reader.read(artifact, `${label} proposed file`);
        if (!stored.bytes.equals(file.content)) {
            integrityFailure("Candidate proposal file bytes disagree with the measured snapshot", {
                label,
                path: file.path,
            });
        }
    }
}

function verifyCandidateArtifacts(
    aggregate,
    evidence,
    observation,
    provenance,
    measurements,
    reader,
) {
    if (provenance.proposalArtifact === null
        || provenance.replicationScheduleArtifact === null
        || provenance.replicationCompositeArtifact === null) {
        integrityFailure("Candidate evidence has an incomplete proposal/measurement closure", {
            evidenceId: evidence.evidenceId,
        });
    }
    const command = aggregate.commands[observation.commandId]?.command ?? null;
    if (command?.kind !== "search_candidate") {
        integrityFailure("Candidate evidence does not reference its reserved search command", {
            evidenceId: evidence.evidenceId,
        });
    }
    const schedule = normalizeReplicationSchedule(command.replicationSchedule);
    if (!Object.hasOwn(command, "hypotheses")
        || !canonicalEqual(
            command.hypotheses,
            observation.annotations?.hypotheses ?? null,
        )
        || evidence.hypothesesIdentity
            !== (command.hypotheses?.identity ?? null)) {
        integrityFailure("Candidate hypotheses are not bound to the frozen command", {
            evidenceId: evidence.evidenceId,
        });
    }
    const rawSeries = normalizeRawMeasurementSeries(
        observation.data?.series?.[0],
        {
            schedule,
            role: "search",
            phase: "search",
            caseId: null,
        },
    ).series;
    const searchMeasurements = measurements.filter(
        (item) => item.measurement.role === "search",
    );
    if (searchMeasurements.length !== measurements.length
        || searchMeasurements.length % schedule.arms.length !== 0) {
        integrityFailure("Candidate evidence does not contain complete replicate blocks", {
            evidenceId: evidence.evidenceId,
        });
    }
    const blockCount = searchMeasurements.length / schedule.arms.length;
    if (blockCount !== rawSeries.completeBlocks.length
        || blockCount !== evidence.replication?.blockCount
        || searchMeasurements.length !== evidence.replication?.attemptCount) {
        integrityFailure("Candidate replication counts disagree with its provenance", {
            evidenceId: evidence.evidenceId,
        });
    }
    const persistedSchedule = reader.readJson(
        provenance.replicationScheduleArtifact,
        `candidate ${evidence.evidenceId} measurement schedule`,
    ).value;
    if (!canonicalEqual(persistedSchedule, schedule)) {
        integrityFailure("Candidate measurement schedule artifact changed", {
            evidenceId: evidence.evidenceId,
        });
    }
    const bySubject = new Map(
        searchMeasurements.map((measurement) => [
            measurement.measurement.subjectId,
            measurement,
        ]),
    );
    const candidateMeasurements = [];
    const controlMeasurements = [];
    const expectedAttempts = [];
    for (let blockIndex = 0; blockIndex < blockCount; blockIndex += 1) {
        const blockPlan = replicationBlockPlan(schedule, blockIndex);
        for (const arm of [...blockPlan.arms].sort((left, right) =>
            left.armIndex - right.armIndex)) {
            const measured = bySubject.get(arm.subjectId);
            if (measured === undefined
                || measured.receipt.role !== "search"
                || measured.receipt.phase !== "search"
                || measured.receipt.replicateIndex !== arm.replicateIndex
                || measured.receipt.blockIndex !== arm.blockIndex
                || measured.receipt.armIndex !== arm.armIndex
                || measured.receipt.armId !== arm.armId
                || measured.receipt.deterministicSeed !== arm.deterministicSeed
                || measured.receipt.subjectId !== arm.subjectId
                || measured.receipt.environmentIdentity
                    !== aggregate.contract.harnessSuite.environmentIdentity
                || measured.receipt.suiteIdentity
                    !== aggregate.contract.harnessSuiteIdentity) {
                integrityFailure(
                    "Candidate measurement receipt does not match its scheduled block arm",
                    {
                        evidenceId: evidence.evidenceId,
                        blockIndex,
                        armIndex: arm.armIndex,
                    },
                );
            }
            expectedAttempts.push({ arm, measured });
            if (arm.armId === "candidate") candidateMeasurements.push(measured);
            if (arm.armId === "control") controlMeasurements.push(measured);
        }
    }
    if (candidateMeasurements.length !== blockCount
        || controlMeasurements.length !== blockCount
        || candidateMeasurements.some((measured) =>
            measured.measurement.snapshot.snapshotHash
                !== observation.receipt.candidateArtifactHash)
        || new Set(controlMeasurements.map((measured) =>
            measured.measurement.snapshot.snapshotHash)).size !== 1) {
        integrityFailure("Candidate/control snapshot identity drifted across replicate blocks", {
            evidenceId: evidence.evidenceId,
        });
    }
    const controlBinding = deriveReplicationControlBinding({
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
        controlSnapshotHashes: controlMeasurements.map((measured) =>
            measured.measurement.snapshot.snapshotHash),
        requireObservedControl: true,
    });
    if (!canonicalEqual(controlBinding, evidence.replication?.control ?? null)) {
        integrityFailure("Candidate control binding disagrees with the signed contract", {
            evidenceId: evidence.evidenceId,
        });
    }

    const composite = reader.readJson(
        provenance.replicationCompositeArtifact,
        `candidate ${evidence.evidenceId} replication composite`,
    ).value;
    if (!exactKeys(composite, [
        "authority",
        "candidateId",
        "commandId",
        "schedule",
        "scheduleArtifact",
        "series",
        "stopping",
        "version",
    ])
        || composite.version !== 2
        || composite.authority !== "raw_complete_blocks"
        || composite.commandId !== observation.commandId
        || composite.candidateId !== command.candidateId
        || !canonicalEqual(composite.schedule, schedule)
        || !canonicalEqual(
            composite.scheduleArtifact,
            provenance.replicationScheduleArtifact,
        )
        || !canonicalEqual(composite.series, rawSeries)
        || !canonicalEqual(
            composite.stopping,
            evidence.replication?.stopping ?? null,
        )) {
        integrityFailure("Candidate replication composite is inconsistent", {
            evidenceId: evidence.evidenceId,
        });
    }
    const rawAttempts = rawSeries.completeBlocks.flatMap(
        (block) => block.observations,
    );
    for (const [index, expected] of expectedAttempts.entries()) {
        const raw = rawAttempts[index];
        const { arm, measured } = expected;
        if (raw?.attemptId !== measured.receipt.attemptId
            || raw.blockIndex !== arm.blockIndex
            || raw.replicateIndex !== arm.replicateIndex
            || raw.armIndex !== arm.armIndex
            || raw.armId !== arm.armId
            || raw.logicalSubjectId !== arm.logicalSubjectId
            || raw.subjectId !== arm.subjectId
            || raw.deterministicSeed !== arm.deterministicSeed
            || raw.receiptHash !== measured.measurement.receiptHash
            || raw.measurementRoot !== measured.measurement.measurementRoot
            || !canonicalEqual(raw.parsed, measured.receipt.parsed)
            || (raw.invalid === null) !== (measured.receipt.parsed !== null)) {
            integrityFailure("Replication composite does not reference every raw receipt", {
                evidenceId: evidence.evidenceId,
                index,
            });
        }
    }
    const proposalArtifact = reader.readJson(
        provenance.proposalArtifact,
        `candidate ${evidence.evidenceId} proposal`,
    );
    const value = proposalArtifact.value;
    const finiteEnumerand = command.enumerand?.topology === "finite_enumerable";
    const boundedEnumerand =
        command.enumerand?.topology === "bounded_parameterized";
    const enumerandOptions = {
        observableRegistry: aggregate.contract.observableRegistry,
        hypothesisPolicy: aggregate.contract.hypothesisPolicy,
    };
    const expectedKeys = finiteEnumerand
        ? [
            "assignment",
            "enumerand",
            "promptContext",
            "promptContextHash",
            "proposal",
        ]
        : boundedEnumerand
            ? [
                "assignment",
                "generationRequest",
                "promptContext",
                "promptContextHash",
                "proposal",
            ]
            : ["assignment", "promptContext", "promptContextHash", "proposal"];
    if (!exactKeys(value, expectedKeys)
        || value.promptContextHash !== provenance.promptContextHash
        || hashCanonical(value.promptContext, PROMPT_CONTEXT_HASH_ALGORITHM)
            !== provenance.promptContextHash
        || !canonicalEqual(value.assignment, value.promptContext?.assignment)
        || !canonicalEqual(value.assignment, expectedAssignment(command))
        || value.proposal?.candidateId !== command.candidateId
        || !candidateProposalAnnotationsMatch(
            value.proposal,
            observation,
        )) {
        integrityFailure("Candidate proposal/context artifact is inconsistent with persisted evidence", {
            evidenceId: evidence.evidenceId,
        });
    }
    if (finiteEnumerand) {
        const measuredSnapshot =
            candidateMeasurements[0].measurement.snapshot.manifestArtifact.objectId;
        if (!canonicalEqual(value.enumerand, command.enumerand)
            || !Array.isArray(value.proposal.files)
            || value.proposal.files.length !== 0
            || value.proposal.identity?.source !== "frozen_enumerand_manifest"
            || value.proposal.identity?.enumerandBindingHash
                !== enumerandBindingHash(command.enumerand, enumerandOptions)
            || measuredSnapshot !== command.enumerand.artifactSnapshotHash
            || observation.receipt.candidateArtifactHash
                !== enumerandArtifactMeasurementHash(
                    command.enumerand.artifactSnapshotHash,
                )) {
            integrityFailure(
                "Finite enumerand proposal does not match its frozen snapshot binding",
                { evidenceId: evidence.evidenceId },
            );
        }
    } else {
        if (boundedEnumerand
            && (!canonicalEqual(
                value.generationRequest?.enumerandBinding,
                command.enumerand,
            )
                || value.generationRequest?.enumerandBindingHash
                !== enumerandBindingHash(command.enumerand, enumerandOptions)
                || value.proposal.identity?.source
                    !== "trusted_parameterized_generator"
                || value.proposal.identity?.enumerandBindingHash
                    !== enumerandBindingHash(
                        command.enumerand,
                        enumerandOptions,
                    ))) {
            integrityFailure(
                "Parameterized proposal does not match its frozen enumerand binding",
                { evidenceId: evidence.evidenceId },
            );
        }
        verifyProposalSnapshot(
            value.proposal,
            candidateMeasurements[0],
            reader,
            `candidate ${evidence.evidenceId}`,
        );
    }

    if (provenance.measurementReuseArtifact !== null) {
        integrityFailure(
            "Replicated candidate evidence cannot reuse another candidate's measurement",
            { evidenceId: evidence.evidenceId },
        );
    }
}

function verifyScientificRoleArtifacts(
    aggregate,
    evidence,
    observation,
    provenance,
    measurements,
    reader,
) {
    const role = evidence.purpose;
    const command = aggregate.commands[observation.commandId]?.command ?? null;
    const expectedKind = role === "confirmation"
        ? "run_confirmation"
        : "run_challenge";
    const freeze = aggregate.confirmation?.freeze?.payload ?? null;
    const member = freeze?.members?.find((item) =>
        item.evidenceId === command?.candidateEvidenceId) ?? null;
    const protocol = member?.roles?.[role] ?? null;
    if (command?.kind !== expectedKind
        || command.harnessRole !== role
        || protocol === null
        || !canonicalEqual(command.protocolManifest, protocol)
        || command.protocolManifestHash !== protocol.protocolManifestHash
        || provenance.proposalArtifact !== null
        || provenance.replicationScheduleArtifact === null
        || provenance.replicationCompositeArtifact === null) {
        integrityFailure(
            "Scientific role evidence has an incomplete or mismatched frozen protocol closure",
            { evidenceId: evidence.evidenceId, role },
        );
    }
    const schedule = normalizeReplicationSchedule(command.replicationSchedule);
    if (!Object.hasOwn(command, "hypotheses")
        || !canonicalEqual(
            command.hypotheses,
            observation.annotations?.hypotheses ?? null,
        )
        || evidence.hypothesesIdentity
            !== (command.hypotheses?.identity ?? null)
        || !canonicalEqual(command.hypotheses, protocol.hypotheses)) {
        integrityFailure(
            "Scientific role hypotheses are not bound to the frozen protocol",
            { evidenceId: evidence.evidenceId, role },
        );
    }
    const rawSeries = normalizeRawMeasurementSeries(
        observation.data?.series?.[0],
        {
            schedule,
            role,
            phase: role,
            caseId: null,
        },
    ).series;
    if (measurements.length % schedule.arms.length !== 0
        || measurements.some((item) =>
            item.measurement.role !== role
            || item.measurement.phase !== role)) {
        integrityFailure(
            "Scientific role evidence does not contain complete role-tagged replicate blocks",
            { evidenceId: evidence.evidenceId, role },
        );
    }
    const blockCount = measurements.length / schedule.arms.length;
    if (blockCount !== rawSeries.completeBlocks.length
        || blockCount !== evidence.replication?.blockCount
        || measurements.length !== evidence.replication?.attemptCount) {
        integrityFailure(
            "Scientific role replication counts disagree with its provenance",
            { evidenceId: evidence.evidenceId, role },
        );
    }
    const persistedSchedule = reader.readJson(
        provenance.replicationScheduleArtifact,
        `${role} ${evidence.evidenceId} measurement schedule`,
    ).value;
    if (!canonicalEqual(persistedSchedule, schedule)) {
        integrityFailure("Scientific role measurement schedule artifact changed", {
            evidenceId: evidence.evidenceId,
            role,
        });
    }
    const bySubject = new Map(
        measurements.map((item) => [item.measurement.subjectId, item]),
    );
    const expectedAttempts = [];
    const candidateMeasurements = [];
    const controlMeasurements = [];
    for (let blockIndex = 0; blockIndex < blockCount; blockIndex += 1) {
        for (const arm of [...replicationBlockPlan(
            schedule,
            blockIndex,
        ).arms].sort((left, right) => left.armIndex - right.armIndex)) {
            const measured = bySubject.get(arm.subjectId);
            if (measured === undefined
                || measured.receipt.role !== role
                || measured.receipt.phase !== role
                || measured.receipt.replicateIndex !== arm.replicateIndex
                || measured.receipt.blockIndex !== arm.blockIndex
                || measured.receipt.armIndex !== arm.armIndex
                || measured.receipt.armId !== arm.armId
                || measured.receipt.deterministicSeed
                    !== arm.deterministicSeed
                || measured.receipt.subjectId !== arm.subjectId
                || measured.receipt.environmentIdentity
                    !== aggregate.contract.harnessSuite.environmentIdentity
                || measured.receipt.suiteIdentity
                    !== aggregate.contract.harnessSuiteIdentity) {
                integrityFailure(
                    "Scientific role receipt does not match its scheduled block arm",
                    {
                        evidenceId: evidence.evidenceId,
                        role,
                        blockIndex,
                        armIndex: arm.armIndex,
                    },
                );
            }
            expectedAttempts.push({ arm, measured });
            if (arm.armId === "candidate") {
                candidateMeasurements.push(measured);
            } else if (arm.armId === "control") {
                controlMeasurements.push(measured);
            }
        }
    }
    if (candidateMeasurements.length !== blockCount
        || controlMeasurements.length !== blockCount
        || candidateMeasurements.some((measured) =>
            measured.measurement.snapshot.snapshotHash
                !== member.candidateArtifactHash)
        || new Set(controlMeasurements.map((measured) =>
            measured.measurement.snapshot.snapshotHash)).size !== 1) {
        integrityFailure(
            "Scientific role candidate/control snapshot identity drifted",
            { evidenceId: evidence.evidenceId, role },
        );
    }
    const controlBinding = deriveReplicationControlBinding({
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
        controlSnapshotHashes: controlMeasurements.map((measured) =>
            measured.measurement.snapshot.snapshotHash),
        requireObservedControl: true,
    });
    if (!canonicalEqual(controlBinding, evidence.replication?.control ?? null)
        || !canonicalEqual(controlBinding, protocol.control ?? null)) {
        integrityFailure(
            "Scientific role control binding disagrees with the frozen protocol",
            { evidenceId: evidence.evidenceId, role },
        );
    }
    const composite = reader.readJson(
        provenance.replicationCompositeArtifact,
        `${role} ${evidence.evidenceId} replication composite`,
    ).value;
    if (!exactKeys(composite, [
        "authority",
        "candidateEvidenceId",
        "candidateId",
        "commandId",
        "confirmationFreezeHash",
        "protocolManifest",
        "protocolManifestHash",
        "role",
        "schedule",
        "scheduleArtifact",
        "series",
        "stopping",
        "version",
    ])
        || composite.version !== 2
        || composite.authority !== "raw_complete_blocks"
        || composite.commandId !== observation.commandId
        || composite.candidateId !== command.candidateId
        || composite.candidateEvidenceId !== command.candidateEvidenceId
        || composite.confirmationFreezeHash
            !== command.confirmationFreezeHash
        || composite.role !== role
        || composite.protocolManifestHash
            !== command.protocolManifestHash
        || !canonicalEqual(
            composite.protocolManifest,
            command.protocolManifest,
        )
        || !canonicalEqual(composite.schedule, schedule)
        || !canonicalEqual(
            composite.scheduleArtifact,
            provenance.replicationScheduleArtifact,
        )
        || !canonicalEqual(composite.series, rawSeries)
        || !canonicalEqual(
            composite.stopping,
            evidence.replication?.stopping ?? null,
        )) {
        integrityFailure(
            "Scientific role replication/protocol composite is inconsistent",
            { evidenceId: evidence.evidenceId, role },
        );
    }
    const rawAttempts = rawSeries.completeBlocks.flatMap(
        (block) => block.observations,
    );
    for (const [index, expected] of expectedAttempts.entries()) {
        const raw = rawAttempts[index];
        const { arm, measured } = expected;
        if (raw?.attemptId !== measured.receipt.attemptId
            || raw.blockIndex !== arm.blockIndex
            || raw.replicateIndex !== arm.replicateIndex
            || raw.armIndex !== arm.armIndex
            || raw.armId !== arm.armId
            || raw.logicalSubjectId !== arm.logicalSubjectId
            || raw.subjectId !== arm.subjectId
            || raw.deterministicSeed !== arm.deterministicSeed
            || raw.receiptHash !== measured.measurement.receiptHash
            || raw.measurementRoot !== measured.measurement.measurementRoot
            || !canonicalEqual(raw.parsed, measured.receipt.parsed)
            || (raw.invalid === null)
                !== (measured.receipt.parsed !== null)) {
            integrityFailure(
                "Scientific role composite does not reference every raw receipt",
                { evidenceId: evidence.evidenceId, role, index },
            );
        }
    }
}

function verifyValidationArtifacts(
    aggregate,
    evidence,
    observation,
    provenance,
    measurements,
    reader,
) {
    const command = aggregate.commands[observation.commandId]?.command ?? null;
    if (command?.kind !== "run_validation"
        || provenance.validationCompositeArtifact === null
        || measurements.length !== command.validationSeries.length) {
        integrityFailure("Validation evidence has an incomplete composite closure", {
            evidenceId: evidence.evidenceId,
        });
    }
    const validationControlBindings = command.validationSeries.map((series) =>
        deriveReplicationControlBinding({
            contractHash: aggregate.contractHash,
            statisticalPolicy: aggregate.contract.statisticalPolicy,
            schedule: series.replicationSchedule,
            enumerandManifest: aggregate.contract.enumerandManifest ?? null,
            manifestOptions: {
                topology: aggregate.contract.enumerandManifest?.topology
                    ?? aggregate.contract.hypothesisTopology,
                observableRegistry: aggregate.contract.observableRegistry,
                hypothesisPolicy: aggregate.contract.hypothesisPolicy,
            },
        }));
    if (!canonicalEqual(
        validationControlBindings,
        evidence.validationControlBindings ?? [],
    )) {
        integrityFailure(
            "Validation schedules do not bind the signed statistical control",
            { evidenceId: evidence.evidenceId },
        );
    }
    const bySubject = new Map(
        measurements.map((item) => [item.measurement.subjectId, item]),
    );
    const normalizedSeries = [];
    for (const reservedSeries of command.validationSeries) {
        const raw = observation.data?.series?.find((series) =>
            series.role === reservedSeries.role
            && series.caseId === reservedSeries.caseId);
        const normalized = normalizeRawMeasurementSeries(raw, {
            schedule: reservedSeries.replicationSchedule,
            role: reservedSeries.role,
            phase: "calibration",
            caseId: reservedSeries.caseId,
        }).series;
        if (normalized.completeBlocks.length !== 1
            || normalized.completeBlocks[0].blockIndex !== command.attemptIndex
            || normalized.completeBlocks[0].observations.length !== 1) {
            integrityFailure("Validation composite has an invalid complete block", {
                evidenceId: evidence.evidenceId,
                role: reservedSeries.role,
                caseId: reservedSeries.caseId,
            });
        }
        const rawObservation = normalized.completeBlocks[0].observations[0];
        const measured = bySubject.get(rawObservation.subjectId);
        if (measured === undefined
            || measured.receipt.role !== reservedSeries.role
            || measured.receipt.phase !== "calibration"
            || measured.receipt.blockIndex !== command.attemptIndex
            || measured.receipt.subjectId !== rawObservation.subjectId
            || measured.measurement.snapshot.manifestArtifact.objectId
                !== reservedSeries.artifactHash
            || rawObservation.attemptId !== measured.receipt.attemptId
            || rawObservation.receiptHash !== measured.measurement.receiptHash
            || rawObservation.measurementRoot
                !== measured.measurement.measurementRoot
            || !canonicalEqual(rawObservation.parsed, measured.receipt.parsed)
            || (rawObservation.invalid === null)
                !== (measured.receipt.parsed !== null)) {
            integrityFailure(
                "Validation raw observation disagrees with its role-tagged receipt",
                {
                    evidenceId: evidence.evidenceId,
                    role: reservedSeries.role,
                    caseId: reservedSeries.caseId,
                },
            );
        }
        normalizedSeries.push(normalized);
    }
    normalizedSeries.sort((left, right) =>
        `${left.role}\0${left.caseId}`.localeCompare(
            `${right.role}\0${right.caseId}`,
        ));
    const composite = reader.readJson(
        provenance.validationCompositeArtifact,
        `validation ${evidence.evidenceId} composite`,
    ).value;
    if (!exactKeys(composite, [
        "attemptIndex",
        "authority",
        "commandId",
        "series",
        "version",
    ])
        || composite.version !== 2
        || composite.authority !== "raw_complete_blocks"
        || composite.commandId !== observation.commandId
        || composite.attemptIndex !== command.attemptIndex
        || observation.data?.attemptIndex !== command.attemptIndex
        || !canonicalEqual(composite.series, normalizedSeries)
        || !canonicalEqual(observation.data?.series, normalizedSeries)) {
        integrityFailure("Validation composite artifact disagrees with its full receipts", {
            evidenceId: evidence.evidenceId,
        });
    }
}

function taggedHashMatchesObjectId(tagged, objectId) {
    return typeof tagged === "string"
        && typeof objectId === "string"
        && tagged.split(":").at(-1)
            === objectId.slice("sha256:".length);
}

function generatedImpossibilityDocuments(command) {
    const documents = new Map([
        ["coverage-closure.json", command.request.evidence.coverageClosure],
        ["enumerand-manifest.json", command.request.enumerands.manifest],
        ["scientific-replay.json", command.request.statistics.scientificReplay],
        [IMPOSSIBILITY_PROOF_FILENAME, command.proofArtifact],
    ]);
    if (command.request.reevaluation.calibration !== null) {
        documents.set(
            "reevaluation/calibration.json",
            command.request.reevaluation.calibration,
        );
    }
    for (const input of command.request.reevaluation.enumerands) {
        documents.set(
            `reevaluation/enumerands/${String(input.ordinal)
                .padStart(6, "0")}.json`,
            input,
        );
    }
    return documents;
}

function verifyImpossibilityRequestSnapshot(
    command,
    measured,
    reader,
    evidenceId,
) {
    const manifest = command.request.objectManifest;
    const expectedManifestRoot = hashCanonical(
        {
            version: manifest.version,
            pack: manifest.pack,
            entries: manifest.entries,
        },
        IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_HASH_ALGORITHM,
    );
    const snapshotEntries = new Map(
        measured.snapshot.manifest.entries.map((entry) => [
            entry.path,
            entry,
        ]),
    );
    const objectArtifacts = measured.snapshot.objectArtifacts;
    const readEntry = (path, label) => {
        const entry = snapshotEntries.get(path) ?? null;
        const artifact = entry === null
            ? null
            : objectArtifacts.get(entry.object) ?? null;
        return artifact === null
            ? null
            : {
                entry,
                artifact,
                bytes: reader.read(artifact, label).bytes,
            };
    };
    const requestRead = readEntry(
        IMPOSSIBILITY_REQUEST_FILENAME,
        `impossibility ${evidenceId} verification request`,
    );
    const proposalRead = readEntry(
        IMPOSSIBILITY_PROPOSAL_FILENAME,
        `impossibility ${evidenceId} proposed certificate`,
    );
    const packRead = readEntry(
        manifest.pack?.path ?? "",
        `impossibility ${evidenceId} verifier object pack`,
    );
    if (manifest.root !== expectedManifestRoot
        || manifest.pack?.format
            !== "crucible-base64-object-pack-v1"
        || requestRead === null
        || proposalRead === null
        || packRead === null
        || requestRead.bytes.toString("utf8")
            !== canonicalJson(command.request)
        || proposalRead.bytes.toString("utf8")
            !== canonicalJson(command.proposedCertificate)) {
        return false;
    }
    let objectPack;
    try {
        objectPack = JSON.parse(packRead.bytes.toString("utf8"));
    } catch {
        return false;
    }
    if (!exactKeys(objectPack, ["entries", "version"])
        || canonicalJson(objectPack) !== packRead.bytes.toString("utf8")
        || objectPack?.version !== manifest.pack.format
        || !Array.isArray(objectPack.entries)
        || objectPack.entries.some((entry) =>
            !exactKeys(entry, [
                "artifactIds",
                "byteHash",
                "contentBase64",
                "objectId",
                "path",
                "semanticHashes",
            ]))
        || objectPack.entries.some((entry, index) =>
            index > 0
            && objectPack.entries[index - 1].path
                .localeCompare(entry.path) >= 0)) {
        return false;
    }
    const packedByPath = new Map(
        objectPack.entries.map((entry) => [entry.path, entry]),
    );
    if (packedByPath.size !== objectPack.entries.length) return false;
    const generated = generatedImpossibilityDocuments(command);
    const expectedPaths = new Set([
        IMPOSSIBILITY_REQUEST_FILENAME,
        IMPOSSIBILITY_PROPOSAL_FILENAME,
        manifest.pack.path,
    ]);
    for (const object of manifest.entries) {
        const generatedValue = generated.get(object.path);
        if (!exactKeys(object, [
            "artifactIds",
            "byteHash",
            "kind",
            "objectId",
            "path",
            "semanticHashes",
        ])
            || !Array.isArray(object.artifactIds)
            || !taggedHashMatchesObjectId(
                object.byteHash,
                object.objectId,
            )
            || !Array.isArray(object.semanticHashes)
            || object.semanticHashes.some((hash) =>
                !taggedHashMatchesObjectId(hash, object.objectId))
            || ((object.kind === "generated")
                !== (generatedValue !== undefined))) {
            return false;
        }
        if (generatedValue !== undefined) {
            expectedPaths.add(object.path);
            const read = readEntry(
                object.path,
                `impossibility ${evidenceId} object ${object.path}`,
            );
            if (read === null
                || read.entry.object !== object.objectId
                || read.bytes.toString("utf8")
                    !== canonicalJson(generatedValue)) {
                return false;
            }
        } else {
            const packed = packedByPath.get(object.path);
            if (packed === undefined
                || packed.objectId !== object.objectId
                || packed.byteHash !== object.byteHash
                || !canonicalEqual(
                    packed.artifactIds,
                    object.artifactIds,
                )
                || !canonicalEqual(
                    packed.semanticHashes,
                    object.semanticHashes,
                )
                || typeof packed.contentBase64 !== "string") {
                return false;
            }
            let bytes;
            try {
                bytes = Buffer.from(packed.contentBase64, "base64");
            } catch {
                return false;
            }
            if (bytes.toString("base64") !== packed.contentBase64
                || `sha256:${sha256Hex(bytes)}` !== object.objectId) {
                return false;
            }
        }
    }
    const complete = [...generated.keys()].every((path) =>
        expectedPaths.has(path))
        && packedByPath.size === manifest.entries.filter((entry) =>
            entry.kind === "cas_object").length
        && measured.snapshot.manifest.entries.length === expectedPaths.size
        && measured.snapshot.manifest.entries.every((entry) =>
            expectedPaths.has(entry.path));
    if (!complete) return false;
    const proofRead = readEntry(
        IMPOSSIBILITY_PROOF_FILENAME,
        `impossibility ${evidenceId} proof artifact`,
    );
    if (proofRead === null) return false;
    return {
        request: requestRead,
        proposal: proposalRead,
        proof: proofRead,
        objectPack: packRead,
    };
}

function normalizedDependencyIdentity(dependencies) {
    return [...dependencies].map((dependency) => ({
        role: dependency.role,
        sha256: dependency.sha256,
    })).sort((left, right) =>
        `${left.role}\0${left.sha256}`.localeCompare(
            `${right.role}\0${right.sha256}`,
        ));
}

function parseAttemptMetadata(attempt, label) {
    if (attempt === null) {
        integrityFailure(`${label} attempt is missing`);
    }
    let metadata;
    try {
        metadata = JSON.parse(attempt.command);
    } catch (error) {
        integrityFailure(`${label} attempt command is not canonical JSON`, {
            attemptId: attempt.attemptId,
        }, error);
    }
    if (canonicalJson(metadata) !== attempt.command) {
        integrityFailure(`${label} attempt command is not canonical`, {
            attemptId: attempt.attemptId,
        });
    }
    return metadata;
}

function attemptAuthorityProjection(attempt) {
    return {
        attemptId: attempt.attemptId,
        leaseId: attempt.leaseId,
        fencingToken: attempt.fencingToken,
        owner: attempt.owner,
        supervisorGeneration: attempt.supervisorGeneration,
        runnerIncarnation: attempt.runnerIncarnation,
    };
}

function logicalEffectKey(investigationId, effect) {
    return hashCanonical({
        investigationId,
        domainCommandId: effect.commandId ?? null,
        phase: effect.kind ?? null,
        round: effect.round ?? null,
        slotIndex: effect.slotIndex ?? null,
        candidateId: effect.candidateId ?? effect.caseId ?? null,
        snapshotId: effect.snapshot ?? null,
        scheduleHash: effect.scheduleHash ?? null,
        blockIndex: effect.blockIndex ?? null,
        replicateIndex: effect.replicateIndex ?? null,
        armIndex: effect.armIndex ?? null,
        armId: effect.armId ?? null,
        deterministicSeed: effect.deterministicSeed ?? null,
        subjectId: effect.subjectId ?? null,
    }, LOGICAL_EFFECT_KEY_HASH_ALGORITHM);
}

function sameAttemptAuthority(left, right) {
    return left.leaseId === right.leaseId
        && left.fencingToken === right.fencingToken
        && left.owner === right.owner
        && left.supervisorGeneration === right.supervisorGeneration
        && left.runnerIncarnation === right.runnerIncarnation;
}

function exactOperationalEvent(events, predicate, label, details = {}) {
    const matches = events.filter(predicate);
    if (matches.length !== 1) {
        integrityFailure(
            `${label} must have exactly one committed operational record`,
            { ...details, count: matches.length },
        );
    }
    return matches[0];
}

function executionArtifactProjection(artifact) {
    return {
        artifactId: artifact.artifactId,
        objectId: artifact.objectId,
    };
}

function verifierExecutionIdentity({
    command,
    role,
    receipt,
    measurement,
    effectAttempt,
    mainAttempt,
    requestArtifact,
    proofArtifact,
}) {
    const core = {
        harnessRole: "impossibility_verifier",
        harnessId: command.harnessId,
        harnessEntryHash: receipt.harnessEntryHash,
        allowlistFileHash: receipt.allowlistFileHash,
        executableHash: receipt.executableHash,
        stagedExecutableHash: receipt.stagedExecutableHash,
        applicationEntrypointHash: role.applicationEntrypointHash,
        dependencyHashes: receipt.dependencyHashes,
        stagedDependencyHashes: receipt.stagedDependencyHashes,
        launchFileBindings: receipt.launchFileBindings,
        parserIdentity: receipt.parserIdentity,
        argvHash: receipt.argvHash,
        envHash: receipt.envHash,
        sandbox: receipt.sandbox,
        measurementReceiptHash: measurement.receiptHash,
        measurementReceiptArtifact:
            executionArtifactProjection(measurement.receiptArtifact),
        rawStdoutArtifact:
            executionArtifactProjection(measurement.rawStdoutArtifact),
        rawStderrArtifact:
            executionArtifactProjection(measurement.rawStderrArtifact),
        requestArtifact: executionArtifactProjection(requestArtifact),
        proofArtifact: executionArtifactProjection(proofArtifact),
        effectAttempt: attemptAuthorityProjection(effectAttempt),
        observationAttempt: attemptAuthorityProjection(mainAttempt),
    };
    return {
        ...core,
        identity: hashCanonical(
            core,
            VERIFIED_IMPOSSIBILITY_EXECUTION_IDENTITY_HASH_ALGORITHM,
        ),
    };
}

function deriveVerifierFacts({
    parsed,
    command,
    measured,
    requestClosure,
    executionIdentity,
}) {
    const enumerandObservations = parsed.mode === "enumerand_reexecution"
        ? parsed.enumerandResults.map((result) => {
            const path = `reevaluation/enumerands/${
                String(result.ordinal).padStart(6, "0")
            }.json`;
            const inputEntry = measured.snapshot.manifest.entries.find(
                (entry) => entry.path === path,
            ) ?? null;
            const inputArtifact = inputEntry === null
                ? null
                : measured.snapshot.objectArtifacts.get(inputEntry.object)
                    ?? null;
            if (inputArtifact === null) {
                integrityFailure(
                    "Verifier enumerand result has no persisted input artifact",
                    { ordinal: result.ordinal, path },
                );
            }
            const observation = {
                ordinal: result.ordinal,
                enumerandHash: result.enumerandHash,
                inputRoot: result.inputRoot,
                receiptBindingsRoot: result.receiptBindingsRoot,
                claimStates: result.claimStates,
                inputArtifact: executionArtifactProjection(inputArtifact),
            };
            const observationHash = hashCanonical(
                observation,
                VERIFIED_IMPOSSIBILITY_ENUMERAND_OBSERVATION_HASH_ALGORITHM,
            );
            const receiptCore = {
                executionIdentity: executionIdentity.identity,
                measurementReceiptHash:
                    measured.measurement.receiptHash,
                rawStdoutHash: measured.measurement.rawStdoutHash,
                requestHash: command.requestHash,
                requestArtifact:
                    executionArtifactProjection(requestClosure.request.artifact),
                observationHash,
                inputArtifact: observation.inputArtifact,
            };
            return {
                ...observation,
                observationHash,
                checkerReceipt: {
                    ...receiptCore,
                    receiptHash: hashCanonical(
                        receiptCore,
                        VERIFIED_IMPOSSIBILITY_CHECKER_RECEIPT_HASH_ALGORITHM,
                    ),
                },
            };
        })
        : [];
    const proofCheckerReceipt = parsed.mode === "certificate_validation"
        ? (() => {
            const receiptCore = {
                executionIdentity: executionIdentity.identity,
                measurementReceiptHash:
                    measured.measurement.receiptHash,
                rawStdoutHash: measured.measurement.rawStdoutHash,
                requestHash: command.requestHash,
                requestArtifact:
                    executionArtifactProjection(requestClosure.request.artifact),
                proofArtifact:
                    executionArtifactProjection(requestClosure.proof.artifact),
                proofArtifactHash: command.proofArtifactHash,
                proofCheckerIdentity:
                    command.request.verifier.proofChecker.identity,
                certificateFormat:
                    command.request.verifier.verificationPolicy
                        .certificateFormat,
                status: parsed.status,
            };
            return {
                ...receiptCore,
                receiptHash: hashCanonical(
                    receiptCore,
                    VERIFIED_IMPOSSIBILITY_CHECKER_RECEIPT_HASH_ALGORITHM,
                ),
            };
        })()
        : null;
    const core = {
        status: parsed.status,
        verdict: parsed.certificate.verdict,
        mode: parsed.mode,
        complete: parsed.complete,
        disagreementCount: parsed.disagreementCount,
        requestHash: command.requestHash,
        proposedCertificateArtifactHash:
            command.proposedCertificateArtifactHash,
        proofArtifactHash: command.proofArtifactHash,
        coverageClosureRoot: parsed.coverageClosureRoot,
        enumerandManifestRoot: parsed.enumerandManifestRoot,
        enumerandCount: parsed.enumerandCount,
        checkedEnumerandCount: parsed.checkedEnumerandCount,
        enumerandObservations,
        evidenceRoots: parsed.evidenceRoots,
        statisticalPolicyIdentity: parsed.statisticalPolicyIdentity,
        alphaLedgerRoot: parsed.alphaLedgerRoot,
        checkerEvidenceRoot: parsed.checkerEvidenceRoot,
        proofCheckerReceipt,
    };
    return {
        ...core,
        factsRoot: hashCanonical(
            core,
            VERIFIED_IMPOSSIBILITY_FACTS_HASH_ALGORITHM,
        ),
    };
}

function deriveVerifiedImpossibilityExecutionCapability({
    aggregate,
    payload,
    repository,
    artifactStore,
    investigationId,
    operationalEvidence,
    expectedObservationAttemptId = null,
    expectedLease = null,
}) {
    if (artifactStore === null) {
        integrityFailure(
            "Impossibility execution verification requires the repository-bound ArtifactStore",
            { commandId: payload?.commandId ?? null },
        );
    }
    const commandRecord = aggregate.commands[payload?.commandId] ?? null;
    const command = commandRecord?.command ?? null;
    const provenance = payload?.receipt?.provenance ?? null;
    const measurement = provenance?.measurements?.[0] ?? null;
    const role =
        aggregate.contract?.harnessSuite?.roles?.impossibility_verifier ?? null;
    if (command?.kind !== "verify_impossibility"
        || payload?.purpose !== "impossibility"
        || provenance === null
        || provenance.measurements.length !== 1
        || measurement === null
        || role === null) {
        integrityFailure(
            "Impossibility observation is not bound to one frozen verifier command",
            { commandId: payload?.commandId ?? null },
        );
    }

    verifyOperationalMeasurementClosure(
        payload,
        provenance,
        operationalEvidence,
    );
    const reader = artifactReader(
        repository,
        artifactStore,
        investigationId,
    );
    const measured = verifyMeasurementArtifactClosure(
        measurement,
        `impossibility ${payload.observationId} measurement`,
        reader,
        artifactStore,
    );
    const requestClosure = verifyImpossibilityRequestSnapshot(
        command,
        measured,
        reader,
        payload.observationId,
    );
    if (requestClosure === false) {
        integrityFailure(
            "Impossibility verifier request/proof bytes do not match the reserved command",
            { commandId: payload.commandId },
        );
    }
    const certificateArtifact =
        provenance.impossibilityCertificateArtifact;
    const certificateRead = reader.readJson(
        certificateArtifact,
        `impossibility ${payload.observationId} certificate`,
    );
    let parsed;
    try {
        parsed = parseImpossibilityVerifierResult(
            measured.stdoutBytes.toString("utf8"),
            {
                request: command.request,
                requestHash: command.requestHash,
                expectedBinding: command.measurementBinding,
            },
        );
    } catch (error) {
        integrityFailure(
            "Persisted raw verifier stdout does not parse under the frozen verifier parser",
            {
                commandId: payload.commandId,
                parserVersion: command.parserVersion,
            },
            error,
        );
    }
    const expectedParserIdentity = trustedParserIdentity(
        command.parserVersion,
    );
    const frozenDependencies = normalizedDependencyIdentity(
        role.dependencies,
    );
    const receiptDependencies = normalizedDependencyIdentity(
        measured.receipt.dependencyHashes,
    );
    const stagedDependencies = normalizedDependencyIdentity(
        measured.receipt.stagedDependencyHashes,
    );
    const launchHashes = new Set(
        measured.receipt.launchFileBindings.map((file) =>
            `${file.role}\0${file.sha256}`),
    );
    if (measured.receipt.version !== HARNESS_SUITE_RECEIPT_VERSION
        || measured.receipt.harnessId !== role.harnessId
        || measured.receipt.role !== "impossibility_verifier"
        || measured.receipt.phase !== "impossibility_verification"
        || measured.receipt.parserVersion !== role.parser.version
        || !canonicalEqual(
            measured.receipt.parserIdentity,
            role.parser,
        )
        || !canonicalEqual(role.parser, expectedParserIdentity)
        || measured.receipt.harnessEntryHash !== role.harnessEntryHash
        || measured.receipt.executableHash !== role.executableHash
        || measured.receipt.stagedExecutableHash !== role.executableHash
        || !canonicalEqual(receiptDependencies, frozenDependencies)
        || !canonicalEqual(stagedDependencies, frozenDependencies)
        || !launchHashes.has(
            `executable\0${measured.receipt.stagedExecutableHash}`,
        )
        || stagedDependencies.some((dependency) =>
            !launchHashes.has(`${dependency.role}\0${dependency.sha256}`))
        || measured.receipt.sandbox?.policyDigest
            !== role.sandboxIdentity.policyDigest
        || measured.receipt.sandbox?.capabilityLaunchUsed !== true
        || typeof measured.receipt.sandbox?.capabilityId !== "string"
        || measured.receipt.sandbox.capabilityId.length === 0
        || measured.receipt.sandbox?.policyIdentity?.securityContext
            ?.appContainer !== true
        || measured.receipt.sandbox?.policyIdentity?.securityContext
            ?.lowIntegrity !== true
        || !Array.isArray(
            measured.receipt.sandbox?.policyIdentity?.securityContext
                ?.capabilities,
        )
        || measured.receipt.sandbox.policyIdentity.securityContext
            .capabilities.length !== 0
        || measured.receipt.runnerEpochId !== payload.receipt.runnerEpochId
        || commandRecord.capabilityEpochId
            !== measured.receipt.runnerEpochId
        || !canonicalEqual(measured.receipt.parsed, parsed)
        || !canonicalEqual(payload.data?.checkerResult, parsed)
        || !canonicalEqual(certificateRead.value, parsed.certificate)) {
        integrityFailure(
            "Persisted impossibility execution does not match the frozen verifier role and MeasurementReceiptV6 closure",
            { commandId: payload.commandId },
        );
    }

    const measurementEvent = exactOperationalEvent(
        operationalEvidence,
        (event) =>
            event.kind === "runtime:measurement"
            && event.payload?.commandId === payload.commandId
            && event.payload?.purpose === "impossibility"
            && event.payload?.receiptArtifactId
                === measured.measurement.receiptArtifact.artifactId,
        "Impossibility measurement",
        { commandId: payload.commandId },
    );
    const certificateEvent = exactOperationalEvent(
        operationalEvidence,
        (event) =>
            event.kind === "runtime:impossibility_certificate"
            && event.payload?.commandId === payload.commandId
            && event.payload?.measurementReceiptArtifactId
                === measured.measurement.receiptArtifact.artifactId,
        "Impossibility certificate",
        { commandId: payload.commandId },
    );
    const boundObservationAttemptId =
        expectedObservationAttemptId
        ?? payload.verifierExecution?.effectBinding
            ?.observationAttempt?.attemptId
        ?? null;
    const requestEvent = exactOperationalEvent(
        operationalEvidence,
        (event) =>
            event.kind === "runtime:impossibility_request"
            && event.payload?.commandId === payload.commandId
            && (boundObservationAttemptId === null
                || event.attemptId === boundObservationAttemptId),
        "Impossibility request",
        { commandId: payload.commandId },
    );
    const effectAttempt = repository.getCommandAttempt(
        measurementEvent.attemptId,
    );
    const mainAttempt = repository.getCommandAttempt(requestEvent.attemptId);
    const recoveredEffectAuthority =
        effectAttempt.state === "committed"
        && mainAttempt.fencingToken > effectAttempt.fencingToken
        && mainAttempt.owner === effectAttempt.owner
        && mainAttempt.supervisorGeneration
            === effectAttempt.supervisorGeneration
        && mainAttempt.runnerIncarnation === effectAttempt.runnerIncarnation;
    const effectMetadata = parseAttemptMetadata(
        effectAttempt,
        "Impossibility effect",
    );
    const mainMetadata = parseAttemptMetadata(
        mainAttempt,
        "Impossibility domain command",
    );
    const effectSourceBound =
        effectAttempt.attemptId === measured.receipt.attemptId
        || effectMetadata.recoveredFromAttemptId
            === measured.receipt.attemptId;
    const expectedLogicalEffectKey = logicalEffectKey(
        investigationId,
        effectMetadata.effect ?? {},
    );
    if (effectAttempt.state !== "committed"
        || !["dispatched", "observed", "committed"].includes(
            mainAttempt.state,
        )
        || effectMetadata.scope !== "external-effect"
        || effectMetadata.logicalEffectKey !== expectedLogicalEffectKey
        || effectMetadata.logicalEffectKey
            !== measurementEvent.payload.logicalEffectKey
        || effectMetadata.logicalEffectKey
            !== certificateEvent.payload.logicalEffectKey
        || effectMetadata.effect?.kind !== "impossibility-verification"
        || effectMetadata.effect?.commandId !== payload.commandId
        || effectMetadata.effect?.requestHash !== command.requestHash
        || !effectSourceBound
        || payload.receipt.attemptId !== effectAttempt.attemptId
        || effectMetadata.effect?.snapshot
            !== measurementEvent.payload.snapshotId
        || mainMetadata.scope !== "domain-command"
        || mainMetadata.commandId !== payload.commandId
        || !canonicalEqual(mainMetadata.command, command)
        || (!sameAttemptAuthority(effectAttempt, mainAttempt)
            && !recoveredEffectAuthority)
        || (expectedObservationAttemptId !== null
            && mainAttempt.attemptId !== expectedObservationAttemptId)
        || (expectedLease !== null
            && (mainAttempt.leaseId !== expectedLease.leaseId
                || mainAttempt.fencingToken !== expectedLease.fencingToken
                || mainAttempt.owner !== expectedLease.owner
                || mainAttempt.supervisorGeneration
                    !== (expectedLease.supervisorGeneration ?? null)
                || mainAttempt.runnerIncarnation
                    !== (expectedLease.runnerIncarnation ?? null)))
        || requestEvent.payload.requestHash !== command.requestHash
        || requestEvent.payload.snapshotId
            !== measurementEvent.payload.snapshotId
        || requestEvent.payload.snapshotProvenance?.manifestArtifact?.objectId
            !== measured.measurement.snapshot.manifestArtifact.objectId
        || certificateEvent.payload.measurementReceiptArtifactId
            !== measured.measurement.receiptArtifact.artifactId
        || certificateEvent.payload.rawStdoutArtifactId
            !== measured.measurement.rawStdoutArtifact.artifactId
        || certificateEvent.payload.rawStderrArtifactId
            !== measured.measurement.rawStderrArtifact.artifactId
        || certificateEvent.payload.certificateArtifactId
            !== certificateArtifact.artifactId) {
        integrityFailure(
            "Impossibility process effect is not bound to its runner attempt, lease, generation, and operational records",
            {
                commandId: payload.commandId,
                recoveredEffectAuthority,
                expectedLogicalEffectKey,
                effectLogicalEffectKey: effectMetadata.logicalEffectKey,
                measurementLogicalEffectKey:
                    measurementEvent.payload.logicalEffectKey,
                certificateLogicalEffectKey:
                    certificateEvent.payload.logicalEffectKey,
                requestSnapshotId: requestEvent.payload.snapshotId,
                measurementSnapshotId:
                    measurementEvent.payload.snapshotId,
                requestManifestObjectId:
                    requestEvent.payload.snapshotProvenance
                        ?.manifestArtifact?.objectId ?? null,
                measurementManifestObjectId:
                    measured.measurement.snapshot.manifestArtifact.objectId,
                effectAttempt: {
                    attemptId: effectAttempt?.attemptId ?? null,
                    state: effectAttempt?.state ?? null,
                    leaseId: effectAttempt?.leaseId ?? null,
                    fencingToken: effectAttempt?.fencingToken ?? null,
                    owner: effectAttempt?.owner ?? null,
                    supervisorGeneration:
                        effectAttempt?.supervisorGeneration ?? null,
                    runnerIncarnation:
                        effectAttempt?.runnerIncarnation ?? null,
                },
                mainAttempt: {
                    attemptId: mainAttempt?.attemptId ?? null,
                    state: mainAttempt?.state ?? null,
                    leaseId: mainAttempt?.leaseId ?? null,
                    fencingToken: mainAttempt?.fencingToken ?? null,
                    owner: mainAttempt?.owner ?? null,
                    supervisorGeneration:
                        mainAttempt?.supervisorGeneration ?? null,
                    runnerIncarnation:
                        mainAttempt?.runnerIncarnation ?? null,
                },
            },
        );
    }

    const executionIdentity = verifierExecutionIdentity({
        command,
        role,
        receipt: measured.receipt,
        measurement: measured.measurement,
        effectAttempt,
        mainAttempt,
        requestArtifact: requestClosure.request.artifact,
        proofArtifact: requestClosure.proof.artifact,
    });
    const facts = deriveVerifierFacts({
        parsed,
        command,
        measured,
        requestClosure,
        executionIdentity,
    });
    const reference = immutableCanonical({
        version: VERIFIED_IMPOSSIBILITY_EXECUTION_VERSION,
        commandId: payload.commandId,
        observationId: payload.observationId,
        request: {
            requestHash: command.requestHash,
            artifact:
                executionArtifactProjection(requestClosure.request.artifact),
            snapshotManifestArtifact: executionArtifactProjection(
                measured.measurement.snapshot.manifestArtifact,
            ),
        },
        proof: {
            artifactHash: command.proofArtifactHash,
            artifact:
                executionArtifactProjection(requestClosure.proof.artifact),
            sizeBytes: requestClosure.proof.bytes.length,
        },
        certificate: {
            artifact: executionArtifactProjection(certificateArtifact),
            artifactHash: taggedHash(
                IMPOSSIBILITY_CERTIFICATE_ARTIFACT_HASH_ALGORITHM,
                certificateRead.bytes,
            ),
            sizeBytes: certificateRead.bytes.length,
        },
        measurement: {
            subjectId: measured.measurement.subjectId,
            measurementRoot: measured.measurement.measurementRoot,
            receiptHash: measured.measurement.receiptHash,
            receiptArtifact:
                executionArtifactProjection(measured.measurement.receiptArtifact),
            rawStdoutHash: measured.measurement.rawStdoutHash,
            rawStdoutArtifact:
                executionArtifactProjection(measured.measurement.rawStdoutArtifact),
            rawStderrHash: measured.measurement.rawStderrHash,
            rawStderrArtifact:
                executionArtifactProjection(measured.measurement.rawStderrArtifact),
            snapshotHash: measured.measurement.snapshot.snapshotHash,
            snapshotClosureRoot:
                measured.measurement.snapshot.closureRoot,
        },
        executionIdentity,
        effectBinding: {
            logicalEffectKey: effectMetadata.logicalEffectKey,
            effectAttempt: attemptAuthorityProjection(effectAttempt),
            observationAttempt: attemptAuthorityProjection(mainAttempt),
            requestEvent: {
                seq: requestEvent.seq,
                eventHash: requestEvent.eventHash,
            },
            measurementEvent: {
                seq: measurementEvent.seq,
                eventHash: measurementEvent.eventHash,
            },
            certificateEvent: {
                seq: certificateEvent.seq,
                eventHash: certificateEvent.eventHash,
            },
            runnerEpochId: measured.receipt.runnerEpochId,
        },
        facts,
    });
    if (Object.hasOwn(payload, "verifierExecution")
        && !canonicalEqual(payload.verifierExecution, reference)) {
        integrityFailure(
            "Persisted verifier execution reference does not rederive from repository-bound artifacts",
            { commandId: payload.commandId },
        );
    }
    return issueVerifiedImpossibilityExecutionCapability({
        commandId: payload.commandId,
        observationId: payload.observationId,
        reference,
    });
}

function verifyImpossibilityArtifacts(
    aggregate,
    evidence,
    observation,
    provenance,
    measurements,
    reader,
) {
    if (provenance.impossibilityCertificateArtifact === null || measurements.length !== 1) {
        integrityFailure("Impossibility evidence has an incomplete certificate closure", {
            evidenceId: evidence.evidenceId,
        });
    }
    const command = aggregate.commands[observation.commandId]?.command ?? null;
    const measured = measurements[0];
    const certificateRead = reader.readJson(
        provenance.impossibilityCertificateArtifact,
        `impossibility ${evidence.evidenceId} certificate`,
    );
    const certificate = certificateRead.value;
    const expectedCertificate = observation.data?.checkerResult?.certificate;
    const sandboxSecurityContext =
        measured.receipt.sandbox?.policyIdentity?.securityContext;
    if (command?.kind !== "verify_impossibility"
        || !verifyImpossibilityRequestSnapshot(
            command,
            measured,
            reader,
            evidence.evidenceId,
        )
        || hashCanonical(
            command.proofArtifact,
            IMPOSSIBILITY_PROOF_ARTIFACT_HASH_ALGORITHM,
        ) !== command.proofArtifactHash
        || command.proofArtifactHash
            === command.proposedCertificateArtifactHash
        || !canonicalEqual(certificate, expectedCertificate)
        || !canonicalEqual(measured.receipt.parsed, observation.data.checkerResult)
        || observation.data.proposedCertificateArtifactHash
            !== command.proposedCertificateArtifactHash
        || measured.receipt.sandbox?.policyDigest
            !== aggregate.contract.harnessSuite.roles
                .impossibility_verifier.sandboxIdentity.policyDigest
        || sandboxSecurityContext?.appContainer !== true
        || sandboxSecurityContext?.lowIntegrity !== true
        || !Array.isArray(sandboxSecurityContext.capabilities)
        || sandboxSecurityContext.capabilities.length !== 0
        || observation.receipt.measurementReceiptHash !== measured.measurement.receiptHash
        || observation.receipt.verificationSnapshotHash
            !== measured.measurement.snapshot.snapshotHash
        || observation.receipt.verificationRequestHash !== command.requestHash
        || observation.receipt.measurementReceiptArtifactHash !== taggedHash(
            IMPOSSIBILITY_RECEIPT_ARTIFACT_HASH_ALGORITHM,
            measured.receiptBytes,
        )
        || observation.receipt.rawStdoutArtifactHash !== taggedHash(
            IMPOSSIBILITY_STDOUT_ARTIFACT_HASH_ALGORITHM,
            measured.stdoutBytes,
        )
        || observation.receipt.rawStderrArtifactHash !== taggedHash(
            IMPOSSIBILITY_STDERR_ARTIFACT_HASH_ALGORITHM,
            measured.stderrBytes,
        )
        || observation.receipt.certificateArtifactHash !== taggedHash(
            IMPOSSIBILITY_CERTIFICATE_ARTIFACT_HASH_ALGORITHM,
            certificateRead.bytes,
        )) {
        integrityFailure("Impossibility certificate artifact disagrees with persisted verifier evidence", {
            evidenceId: evidence.evidenceId,
        });
    }
}

function verifyEvidenceArtifactClosure(
    aggregate,
    evidence,
    reader,
    artifactStore,
) {
    if (evidence.sourceKind !== "harness") return 0;
    const observation = aggregate.observations[evidence.observationId] ?? null;
    const provenance = evidence.receipt?.provenance ?? null;
    if (observation === null || provenance === null) {
        integrityFailure("Harness evidence is missing its persisted observation provenance", {
            evidenceId: evidence.evidenceId,
        });
    }
    const measurements = provenance.measurements.map((measurement, index) =>
        verifyMeasurementArtifactClosure(
            measurement,
            `${evidence.evidenceId} measurement ${index}`,
            reader,
            artifactStore,
        ));
    if (measurements.some((item) =>
        item.receipt.runnerEpochId !== observation.receipt?.runnerEpochId)
        || (evidence.purpose === "impossibility"
            && measurements[0]?.receipt.attemptId !== observation.receipt?.attemptId)) {
        integrityFailure("Full measurement receipts are not bound to the observation attempt", {
            evidenceId: evidence.evidenceId,
        });
    }

    const stdoutHashes = measurements.map((item) => ({
        id: item.measurement.subjectId,
        hash: item.measurement.rawStdoutHash,
    }));
    const stderrHashes = measurements.map((item) => ({
        id: item.measurement.subjectId,
        hash: item.measurement.rawStderrHash,
    }));
    const compositeStreams = evidence.purpose === "validation"
        || evidence.purpose === "candidate"
        || evidence.purpose === "confirmation"
        || evidence.purpose === "challenge";
    const expectedStdout = compositeStreams
        ? hashCanonical(stdoutHashes, OBSERVATION_STREAM_HASH_ALGORITHM)
        : measurements[0]?.measurement.rawStdoutHash ?? null;
    const expectedStderr = compositeStreams
        ? hashCanonical(stderrHashes, OBSERVATION_STREAM_HASH_ALGORITHM)
        : measurements[0]?.measurement.rawStderrHash ?? null;
    if (observation.receipt?.rawStdoutHash !== expectedStdout
        || observation.receipt?.rawStderrHash !== expectedStderr) {
        integrityFailure("Observation stream roots disagree with raw output artifacts", {
            evidenceId: evidence.evidenceId,
        });
    }

    if (evidence.purpose === "candidate") {
        verifyCandidateArtifacts(
            aggregate,
            evidence,
            observation,
            provenance,
            measurements,
            reader,
        );
    } else if (evidence.purpose === "confirmation"
        || evidence.purpose === "challenge") {
        verifyScientificRoleArtifacts(
            aggregate,
            evidence,
            observation,
            provenance,
            measurements,
            reader,
        );
    } else if (evidence.purpose === "validation") {
        verifyValidationArtifacts(
            aggregate,
            evidence,
            observation,
            provenance,
            measurements,
            reader,
        );
    } else if (evidence.purpose === "impossibility") {
        verifyImpossibilityArtifacts(
            aggregate,
            evidence,
            observation,
            provenance,
            measurements,
            reader,
        );
    } else {
        integrityFailure("Harness evidence has an unknown purpose", {
            evidenceId: evidence.evidenceId,
            purpose: evidence.purpose,
        });
    }
    return measurements.length;
}

function verifyOperationalMeasurementClosure(
    observation,
    provenance,
    operationalEvidence,
    { requirePresence = true } = {},
) {
    const committed = operationalEvidence.filter((event) =>
        event.kind === "runtime:measurement"
        && event.payload?.commandId === observation.commandId
        && event.payload?.purpose === observation.purpose);
    if (!requirePresence && committed.length === 0) return;
    const bySubject = new Map();
    for (const event of committed) {
        const subjectId = event.payload?.measurementSubjectId;
        if (typeof subjectId !== "string" || bySubject.has(subjectId)) {
            integrityFailure(
                "Operational measurement history has a duplicate or invalid subject",
                { commandId: observation.commandId, subjectId: subjectId ?? null },
            );
        }
        bySubject.set(subjectId, event.payload);
    }
    if (bySubject.size !== provenance.measurements.length
        || provenance.measurements.some((measurement) =>
            !canonicalEqual(
                bySubject.get(measurement.subjectId)?.measurementProvenance
                    ?? null,
                measurement,
            ))) {
        integrityFailure(
            "Evidence omitted or changed committed operational measurement blocks",
            {
                commandId: observation.commandId,
                purpose: observation.purpose,
                committedCount: bySubject.size,
                evidenceCount: provenance.measurements.length,
            },
        );
    }
}

export class DomainRepositoryAdapter {
    #repository;
    #artifactStore;
    #investigationId;
    #operationalInvestigationId;
    #beforeCasAttempt;

    constructor({
        repository,
        artifactStore = null,
        investigationId,
        ensure = true,
        beforeCasAttempt = null,
    } = {}) {
        if (repository === null
            || typeof repository !== "object"
            || typeof repository.appendEvents !== "function"
            || typeof repository.appendEventsWithAttemptTransition !== "function"
            || typeof repository.assertAttemptAuthority !== "function"
            || typeof repository.ingestEvidenceBatchFenced !== "function"
            || typeof repository.ingestEvidenceBatchWithAttemptTransition !== "function"
            || typeof repository.verifyInvestigation !== "function"
            || typeof repository.listArtifactRefsForEvent !== "function"
            || typeof repository.getArtifact !== "function") {
            throw new RuntimeConfigError("repository must be an EventRepository");
        }
        if (beforeCasAttempt !== null && typeof beforeCasAttempt !== "function") {
            throw new RuntimeConfigError("beforeCasAttempt must be a function or null");
        }
        if (artifactStore !== null
            && (typeof artifactStore !== "object"
                || typeof artifactStore.verifyObject !== "function"
                || typeof artifactStore.readObject !== "function"
                || typeof artifactStore.loadManifest !== "function")) {
            throw new RuntimeConfigError(
                "artifactStore must expose the read-only ArtifactStore API or be null",
            );
        }
        this.#repository = repository;
        this.#artifactStore = artifactStore;
        this.#beforeCasAttempt = beforeCasAttempt;
        this.#investigationId = requireIdentifier(investigationId, "investigationId");
        this.#operationalInvestigationId =
            `${this.#investigationId}${OPERATIONAL_INVESTIGATION_SUFFIX}`;
        if (ensure) {
            const compatibility = assertInvestigationDomainCompatible(
                this.#repository,
                this.#investigationId,
            );
            const operational = this.#repository.getInvestigation(
                this.#operationalInvestigationId,
            );
            if (operational !== null
                && operational.metadata?.domainVersion !== DOMAIN_VERSION) {
                throw new RuntimeIntegrityError(
                    "Persisted operational evidence does not match the active Crucible domain",
                    {
                        investigationId: this.#investigationId,
                        operationalInvestigationId: this.#operationalInvestigationId,
                        expectedDomainVersion: DOMAIN_VERSION,
                        actualDomainVersion:
                            domainVersionOrNull(operational.metadata?.domainVersion),
                    },
                );
            }
            this.#repository.ensureInvestigation({
                investigationId: this.#investigationId,
                metadata: {
                    role: "crucible-domain",
                    domainVersion: DOMAIN_VERSION,
                },
            });
            this.#repository.ensureInvestigation({
                investigationId: this.#operationalInvestigationId,
                metadata: {
                    role: "crucible-runtime-evidence",
                    domainInvestigationId: this.#investigationId,
                    domainVersion: DOMAIN_VERSION,
                },
            });
        }
    }

    domainFactIdentity(domainEvent) {
        return domainFactIdentity(domainEvent);
    }

    replay({ artifactStore = this.#artifactStore } = {}) {
        assertInvestigationDomainCompatible(
            this.#repository,
            this.#investigationId,
        );
        const repositoryReport = this.#repository.verifyInvestigation(this.#investigationId);
        if (!repositoryReport.ok) {
            throw new RuntimeIntegrityError(
                "Repository structural integrity verification failed",
                { violations: repositoryReport.violations },
            );
        }
        const rows = this.#repository.listEvents(this.#investigationId);
        const domainEvents = rows.map((row) => {
            const domainEvent = assertRepositoryDomainRow(row);
            assertArtifactBindings(
                this.#repository,
                this.#investigationId,
                row.seq,
                requiredArtifactRefs(domainEvent),
            );
            return domainEvent;
        });
        const stoppingIndex = domainEvents.findIndex((event) =>
            event.type === EVENT_TYPES.NON_RESULT_RECORDED);
        if (stoppingIndex !== -1 && stoppingIndex !== domainEvents.length - 1) {
            throw new RuntimeIntegrityError(
                "Non-result domain events must be the final persisted event",
                {
                    stoppingSeq: domainEvents[stoppingIndex].seq,
                    eventCount: domainEvents.length,
                },
            );
        }
        try {
            verifyEventChain(domainEvents);
            const operationalEvidence = domainEvents.some((event) =>
                event.type === EVENT_TYPES.COMMAND_OBSERVED
                && event.payload?.purpose === "impossibility")
                ? this.listOperationalEvidence()
                : [];
            const aggregate = replayEvents(domainEvents, {
                verifierExecutionResolver: ({ aggregate: current, event }) =>
                    event.type === EVENT_TYPES.COMMAND_OBSERVED
                    && event.payload?.purpose === "impossibility"
                        ? deriveVerifiedImpossibilityExecutionCapability({
                            aggregate: current,
                            payload: event.payload,
                            repository: this.#repository,
                            artifactStore,
                            investigationId: this.#investigationId,
                            operationalEvidence,
                        })
                        : null,
            });
            return {
                aggregate,
                scientificReplay: aggregate.scientificReplay,
                domainEvents,
                repositoryEvents: rows,
                repositoryReport,
            };
        } catch (error) {
            throw new RuntimeIntegrityError(
                "Domain hash-chain or reducer replay failed",
                {
                    code: error?.code ?? null,
                    message: error?.message ?? String(error),
                },
                { cause: error },
            );
        }
    }

    replayScientific() {
        const replay = this.replay();
        return {
            ...replay,
            scientificReplay: materializeScientificReplayState(
                replay.aggregate,
            ),
        };
    }

    verifyTerminalArtifactClosure({ artifactStore } = {}) {
        const replay = this.replay({ artifactStore });
        const { aggregate } = replay;
        if (aggregate.terminal === null) {
            return {
                ...replay,
                artifactClosureReport: {
                    ok: true,
                    terminal: false,
                    checkedArtifacts: 0,
                    checkedEvidence: 0,
                    checkedMeasurements: 0,
                },
            };
        }
        if (aggregate.terminal.evidenceClosure === null
            || typeof aggregate.terminal.evidenceClosure !== "object") {
            throw new RuntimeIntegrityError(
                "Persisted terminal decision has no evidence closure",
                { investigationId: this.#investigationId },
            );
        }

        const reader = artifactReader(
            this.#repository,
            artifactStore,
            this.#investigationId,
        );
        let checkedEvidence = 0;
        let checkedMeasurements = 0;
        const operationalEvidence = this.listOperationalEvidence();
        for (const evidenceId of aggregate.evidenceOrder) {
            const evidence = aggregate.evidence[evidenceId] ?? null;
            if (evidence === null) {
                throw new RuntimeIntegrityError(
                    "Terminal evidence order references missing evidence",
                    { investigationId: this.#investigationId, evidenceId },
                );
            }
            if (evidence.sourceKind === "harness") {
                const observation =
                    aggregate.observations[evidence.observationId] ?? null;
                if (observation === null) {
                    throw new RuntimeIntegrityError(
                        "Terminal harness evidence is missing its observation",
                        { investigationId: this.#investigationId, evidenceId },
                    );
                }
                verifyOperationalMeasurementClosure(
                    observation,
                    evidence.receipt.provenance,
                    operationalEvidence,
                );
                checkedEvidence += 1;
                checkedMeasurements += verifyEvidenceArtifactClosure(
                    aggregate,
                    evidence,
                    reader,
                    artifactStore,
                );
            }
        }
        if (checkedEvidence === 0 || checkedMeasurements === 0) {
            throw new RuntimeIntegrityError(
                "Persisted terminal decision has no verifiable harness artifact closure",
                { investigationId: this.#investigationId },
            );
        }
        const receiptSummary = aggregate.terminal.evidenceClosure.receipts;
        if (receiptSummary?.evidenceCount !== aggregate.evidenceOrder.length
            || receiptSummary?.count !== checkedMeasurements) {
            throw new RuntimeIntegrityError(
                "Persisted terminal receipt closure counts are inconsistent",
                { investigationId: this.#investigationId },
            );
        }
        const expectedScientificReplay = scientificReplaySummary(
            aggregate.scientificReplay,
        );
        if (!canonicalEqual(
            aggregate.terminal.evidenceClosure.scientificReplay,
            expectedScientificReplay,
        )) {
            throw new RuntimeIntegrityError(
                "Persisted terminal scientific replay closure is inconsistent",
                { investigationId: this.#investigationId },
            );
        }

        return {
            ...replay,
            artifactClosureReport: {
                ok: true,
                terminal: true,
                checkedArtifacts: reader.count(),
                checkedEvidence,
                checkedMeasurements,
                scientificReplayClosureRoot:
                    expectedScientificReplay.closureRoot,
            },
        };
    }

    openInvestigation(
        contract,
        verifiedExperimentAuthority,
        runtimeConfigAuthority,
    ) {
        const current = this.replay();
        if (current.domainEvents.length !== 0) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                "Investigation already has domain events",
                { investigationId: this.#investigationId },
            );
        }
        let authority;
        let normalizedContract;
        try {
            const verified = readVerifiedExperimentAuthority(
                verifiedExperimentAuthority,
            );
            normalizedContract = createInvestigationContract(contract);
            authority = assertExperimentAuthorityContractBinding(
                verified.authority,
                normalizedContract,
                this.#investigationId,
            );
            if (verified.trustedPublicKeyFingerprint
                    !== authority.trustFingerprint
                || !canonicalEqual(verified.signedPayload, authority.manifest)
                || verified.signedPayloadIdentity
                    !== authority.manifestIdentity
                || verified.signature !== authority.signature
                || verified.contractHash !== contractHash(normalizedContract)
                || verified.investigationId !== this.#investigationId
                || !canonicalEqual(
                    verified.signedPayload.experimentPayload.contract,
                    normalizedContract,
                )) {
                throw new Error(
                    "verified experiment authority capability bindings do not match the requested opening",
                );
            }
        } catch (error) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                `V4 investigation opening requires an exact verified Ed25519 authority capability: ${
                    error?.message ?? String(error)
                }`,
                {
                    investigationId: this.#investigationId,
                    cause: error?.code ?? null,
                },
                { cause: error },
            );
        }
        let runtimeAuthority;
        try {
            runtimeAuthority = normalizeRuntimeConfigAuthority(
                runtimeConfigAuthority,
            );
            if (runtimeAuthority.securityConfig?.runner?.investigationId
                !== this.#investigationId) {
                throw new Error(
                    "runtime config authority belongs to a different investigation",
                );
            }
        } catch (error) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                `V4 investigation opening requires immutable runtime config authority: ${
                    error?.message ?? String(error)
                }`,
                {
                    investigationId: this.#investigationId,
                    cause: error?.code ?? null,
                },
                { cause: error },
            );
        }
        return this.#appendDomainEvent(createInvestigationOpenedEvent(
            normalizedContract,
            authority,
            runtimeAuthority,
        ), {
            aggregate: current.aggregate,
        });
    }

    appendDomainEvent(domainEvent, options = {}) {
        if (domainEvent?.type === EVENT_TYPES.INVESTIGATION_OPENED) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                "Investigation opening events may only be appended through openInvestigation with a verified authority capability",
                { investigationId: this.#investigationId },
            );
        }
        return this.#appendDomainEvent(domainEvent, options);
    }

    #appendDomainEvent(domainEvent, options = {}) {
        const replayed = options.aggregate === undefined
            ? this.replay()
            : { aggregate: options.aggregate };
        const aggregate = replayed.aggregate;
        if ((aggregate.pause !== null
                && domainEvent?.type !== EVENT_TYPES.INVESTIGATION_RESUMED)
            || aggregate.nonResults.length > 0) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                "Paused investigations accept only resume; non-result investigations reject all subsequent domain events",
                {
                    status: aggregate.status,
                    type: domainEvent?.type ?? null,
                },
            );
        }
        let nextAggregate;
        try {
            nextAggregate = reduceEvent(aggregate, domainEvent);
        } catch (error) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                `Domain event was rejected before persistence: ${error.message}`,
                { code: error?.code ?? null, type: domainEvent?.type ?? null },
                { cause: error },
            );
        }
        const artifactRefs = requiredArtifactRefs(domainEvent);
        if (domainEvent.type === EVENT_TYPES.EVIDENCE_COMMITTED) {
            const observation = aggregate.observations[domainEvent.payload.observationId] ?? null;
            if (observation === null || !Number.isSafeInteger(observation.observedSeq)) {
                throw new RuntimeIntegrityError(
                    "Evidence commitment is missing its persisted source observation",
                    { observationId: domainEvent.payload.observationId },
                );
            }
            verifyOperationalMeasurementClosure(
                observation,
                observation.receipt.provenance,
                this.listOperationalEvidence(),
                { requirePresence: false },
            );
            assertArtifactBindings(
                this.#repository,
                this.#investigationId,
                observation.observedSeq,
                artifactRefs,
            );
        }
        const head = this.#repository.getHead(this.#investigationId);
        if (head.seq + 1 !== domainEvent.seq) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_SEQUENCE_MISMATCH,
                "Repository head cannot preserve persistence seq == domain seq",
                {
                    repositoryNextSeq: head.seq + 1,
                    domainSeq: domainEvent.seq,
                },
            );
        }
        const terminalKind = expectedTerminalKind(domainEvent);
        const appendInput = {
            investigationId: this.#investigationId,
            expectedHead: head.eventHash,
            events: [{
                kind: `${DOMAIN_KIND_PREFIX}${domainEvent.type}`,
                payload: { domainEvent },
                artifactIds: artifactRefs.map((item) => item.artifactId),
                ...(terminalKind === null ? {} : { terminal: { kind: terminalKind } }),
            }],
        };
        const attemptTransition = options.attemptTransition ?? null;
        const result = attemptTransition === null
            ? this.#repository.appendEvents(appendInput)
            : this.#repository.appendEventsWithAttemptTransition({
                ...appendInput,
                ...attemptTransition,
            });
        const row = result.events[0];
        if (row.seq !== domainEvent.seq) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_SEQUENCE_MISMATCH,
                "Persistence assigned a sequence different from the domain event",
                { persistenceSeq: row.seq, domainSeq: domainEvent.seq },
            );
        }
        assertArtifactBindings(
            this.#repository,
            this.#investigationId,
            row.seq,
            artifactRefs,
        );
        return { aggregate: nextAggregate, domainEvent, repositoryEvent: row };
    }

    appendFromFactory(factory, {
        maxCasRetries = 8,
        attemptTransition = null,
        expectedDomainFactHash = null,
    } = {}) {
        if (typeof factory !== "function") {
            throw new RuntimeConfigError("appendFromFactory requires a function");
        }
        let boundDomainFactHash = expectedDomainFactHash;
        for (let attempt = 0; attempt <= maxCasRetries; attempt += 1) {
            this.#beforeCasAttempt?.(Object.freeze({
                attempt,
                maxCasRetries,
                fenced: attemptTransition !== null,
            }));
            if (attemptTransition !== null) {
                this.#repository.assertAttemptAuthority({
                    authorityInvestigationId:
                        attemptTransition.authorityInvestigationId
                        ?? this.#investigationId,
                    attemptId: attemptTransition.attemptId,
                    attemptCommand: attemptTransition.attemptCommand,
                    leaseId: attemptTransition.leaseId,
                    fencingToken: attemptTransition.fencingToken,
                    owner: attemptTransition.owner,
                    supervisorGeneration:
                        attemptTransition.supervisorGeneration ?? null,
                    runnerIncarnation:
                        attemptTransition.runnerIncarnation ?? null,
                    expectedState: attemptTransition.fromState,
                });
            }
            const { aggregate } = this.replay();
            const domainEvent = factory(aggregate);
            if (domainEvent === null) {
                if (attemptTransition !== null && boundDomainFactHash !== null) {
                    throw new RuntimeIntegrityError(
                        "CAS replay removed the logical domain fact bound to the attempt",
                        { expectedDomainFactHash: boundDomainFactHash },
                    );
                }
                return { aggregate, domainEvent: null, repositoryEvent: null };
            }
            if (attemptTransition !== null || boundDomainFactHash !== null) {
                const actualDomainFactHash = domainFactIdentity(domainEvent);
                if (boundDomainFactHash === null) {
                    boundDomainFactHash = actualDomainFactHash;
                } else if (actualDomainFactHash !== boundDomainFactHash) {
                    throw new RuntimeIntegrityError(
                        "CAS replay changed the logical domain fact bound to the attempt",
                        {
                            expectedDomainFactHash: boundDomainFactHash,
                            actualDomainFactHash,
                            type: domainEvent.type,
                        },
                    );
                }
            }
            try {
                return this.appendDomainEvent(domainEvent, {
                    aggregate,
                    attemptTransition,
                });
            } catch (error) {
                if (!isCasConflict(error) || attempt === maxCasRetries) {
                    throw error;
                }
            }
        }
        throw new RuntimeIntegrityError("CAS retry loop exited unexpectedly");
    }

    appendKernelDecision() {
        return this.appendFromFactory((aggregate) => constructKernelDecisionEvent(aggregate));
    }

    appendStorageBudgetNonResult(telemetry) {
        const signaled = this.appendFromFactory((aggregate) => {
            if (aggregate.terminal !== null
                || aggregate.pause !== null
                || aggregate.nonResults.length > 0
                || (aggregate.storageBudgetExhaustion !== null
                    && aggregate.storageBudgetExhaustion !== undefined)) {
                return null;
            }
            return createExternalEvent(
                aggregate,
                EVENT_TYPES.STORAGE_BUDGET_EXHAUSTED,
                telemetry,
            );
        });
        if (signaled.domainEvent === null) {
            const replayed = this.replay();
            return {
                aggregate: replayed.aggregate,
                domainEvent: null,
                repositoryEvent: null,
                signal: null,
            };
        }
        const decision = this.appendKernelDecision();
        return {
            ...decision,
            signal: signaled,
        };
    }

    appendKernelDecisionFenced({
        attemptId,
        command,
        lease,
        expectedDomainFactHash = null,
    } = {}) {
        return this.appendFromFactory(
            (aggregate) => constructKernelDecisionEvent(aggregate),
            {
                attemptTransition: this.#attemptTransition({
                    attemptId,
                    command,
                    lease,
                    fromState: "observed",
                    toState: "committed",
                }),
                expectedDomainFactHash,
            },
        );
    }

    resumeInvestigation() {
        return this.appendFromFactory((aggregate) => {
            if (aggregate.pause === null) return null;
            return constructInvestigationResumedEvent(aggregate);
        });
    }

    resumeInvestigationFenced({
        attemptId,
        command,
        lease,
        expectedDomainFactHash = null,
    } = {}) {
        return this.appendFromFactory((aggregate) => {
            if (aggregate.pause === null) return null;
            return constructInvestigationResumedEvent(aggregate);
        }, {
            attemptTransition: this.#attemptTransition({
                attemptId,
                command,
                lease,
                fromState: "observed",
                toState: "committed",
            }),
            expectedDomainFactHash,
        });
    }

    appendExternal(type, payload) {
        return this.appendFromFactory((aggregate) => createExternalEvent(aggregate, type, payload));
    }

    appendExternalFenced(type, payload, {
        attemptId,
        command,
        lease,
        fromState,
        toState,
        expectedDomainFactHash = null,
    } = {}) {
        return this.appendFromFactory(
            (aggregate) => createExternalEvent(aggregate, type, payload),
            {
                attemptTransition: this.#attemptTransition({
                    attemptId,
                    command,
                    lease,
                    fromState,
                    toState,
                }),
                expectedDomainFactHash,
            },
        );
    }

    appendHarnessObservationFenced(payload, {
        attemptId,
        command,
        lease,
    } = {}) {
        return this.appendFromFactory(
            (aggregate) => {
                const verifierExecutionCapability =
                    payload?.purpose === "impossibility"
                        ? deriveVerifiedImpossibilityExecutionCapability({
                            aggregate,
                            payload,
                            repository: this.#repository,
                            artifactStore: this.#artifactStore,
                            investigationId: this.#investigationId,
                            operationalEvidence:
                                this.listOperationalEvidence(),
                            expectedObservationAttemptId: attemptId,
                            expectedLease: lease,
                        })
                        : null;
                return constructHarnessObservedEvent(
                    aggregate,
                    payload,
                    verifierExecutionCapability === null
                        ? {}
                        : { verifierExecutionCapability },
                );
            },
            {
                attemptTransition: this.#attemptTransition({
                    attemptId,
                    command,
                    lease,
                    fromState: "dispatched",
                    toState: "observed",
                }),
            },
        );
    }

    appendEvidenceCommitFenced(input, {
        attemptId,
        command,
        lease,
    } = {}) {
        return this.appendFromFactory(
            (aggregate) => constructEvidenceCommittedEvent(aggregate, input),
            {
                attemptTransition: this.#attemptTransition({
                    attemptId,
                    command,
                    lease,
                    fromState: "observed",
                    toState: "committed",
                }),
            },
        );
    }

    #attemptTransition({
        attemptId,
        command,
        lease,
        fromState,
        toState,
    }) {
        requireString(attemptId, "attemptId", { max: 256 });
        requirePlainObject(command, "command");
        requirePlainObject(lease, "lease");
        requireString(fromState, "fromState", { max: 32 });
        requireString(toState, "toState", { max: 32 });
        return {
            authorityInvestigationId: this.#investigationId,
            attemptId,
            attemptCommand: canonicalJson(command),
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration ?? null,
            runnerIncarnation: lease.runnerIncarnation ?? null,
            fromState,
            toState,
        };
    }

    requestStop({ requestId, reason, pauseRequested = true } = {}) {
        requireString(requestId, "requestId", { max: 128 });
        requireString(reason, "reason", { max: 4096, allowLineBreaks: true });
        const operationalNonResult = this.latestOperationalNonResult();
        if (operationalNonResult !== null) {
            const { aggregate } = this.replay();
            return { aggregate, domainEvent: null, repositoryEvent: null };
        }
        return this.appendFromFactory((aggregate) => {
            if (aggregate.terminal !== null
                || aggregate.pause !== null
                || aggregate.nonResults.length > 0) {
                return null;
            }
            return createExternalEvent(aggregate, EVENT_TYPES.STOP_REQUESTED, {
                requestId,
                reason,
                pauseRequested,
            });
        });
    }

    requestStopFenced({
        requestId,
        reason,
        pauseRequested = true,
        attemptId,
        command,
        lease,
        expectedDomainFactHash = null,
    } = {}) {
        requireString(requestId, "requestId", { max: 128 });
        requireString(reason, "reason", { max: 4096, allowLineBreaks: true });
        const operationalNonResult = this.latestOperationalNonResult();
        if (operationalNonResult !== null) {
            const { aggregate } = this.replay();
            return { aggregate, domainEvent: null, repositoryEvent: null };
        }
        return this.appendFromFactory((aggregate) => {
            if (aggregate.terminal !== null
                || aggregate.pause !== null
                || aggregate.nonResults.length > 0) {
                return null;
            }
            return createExternalEvent(aggregate, EVENT_TYPES.STOP_REQUESTED, {
                requestId,
                reason,
                pauseRequested,
            });
        }, {
            attemptTransition: this.#attemptTransition({
                attemptId,
                command,
                lease,
                fromState: "observed",
                toState: "committed",
            }),
            expectedDomainFactHash,
        });
    }

    acquireRunnerLease({
        leaseId,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
    } = {}) {
        requireString(leaseId, "leaseId", { max: 256 });
        requireString(owner, "owner", { max: 256 });
        const lease = this.#repository.acquireLease({
            investigationId: this.#investigationId,
            leaseId,
            owner,
            supervisorGeneration,
            runnerIncarnation,
        });
        const recovery = this.recoverStaleAttempts(lease);
        return { lease, recovery };
    }

    recoverStaleAttempts(lease) {
        requirePlainObject(lease, "lease");
        const attempts = this.#repository.listCommandAttempts(this.#investigationId);
        const abandoned = [];
        const uncertain = [];
        let uncertainDispatched = 0;
        for (const attempt of attempts) {
            if (attempt.state === "committed"
                || attempt.state === "abandoned"
                || attempt.fencingToken >= lease.fencingToken) {
                continue;
            }
            if (attempt.state === "dispatched" || attempt.state === "observed") {
                uncertainDispatched += 1;
                uncertain.push(Object.freeze({
                    ...attempt,
                    previousState: attempt.state,
                }));
            }
            abandoned.push(this.#repository.abandonStaleCommand({
                investigationId: this.#investigationId,
                attemptId: attempt.attemptId,
                leaseId: lease.leaseId,
                fencingToken: lease.fencingToken,
                owner: lease.owner,
                supervisorGeneration: lease.supervisorGeneration ?? null,
                runnerIncarnation: lease.runnerIncarnation ?? null,
            }));
        }
        return Object.freeze({
            abandoned: Object.freeze(abandoned),
            abandonedCount: abandoned.length,
            uncertainDispatched,
            uncertain: Object.freeze(uncertain),
        });
    }

    reserveAttempt({ attemptId, command, lease }) {
        requireString(attemptId, "attemptId", { max: 256 });
        requirePlainObject(command, "command");
        requirePlainObject(lease, "lease");
        this.recoverStaleAttempts(lease);
        return this.#repository.reserveCommand({
            investigationId: this.#investigationId,
            attemptId,
            command: canonicalJson(command),
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration ?? null,
            runnerIncarnation: lease.runnerIncarnation ?? null,
        });
    }

    dispatchAttempt(attemptId, lease) {
        return this.#repository.dispatchCommand({
            investigationId: this.#investigationId,
            attemptId,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration ?? null,
            runnerIncarnation: lease.runnerIncarnation ?? null,
        });
    }

    observeAttempt(attemptId, lease) {
        return this.#repository.observeCommand({
            investigationId: this.#investigationId,
            attemptId,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration ?? null,
            runnerIncarnation: lease.runnerIncarnation ?? null,
        });
    }

    commitAttempt(attemptId, lease) {
        return this.#repository.commitCommand({
            investigationId: this.#investigationId,
            attemptId,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration ?? null,
            runnerIncarnation: lease.runnerIncarnation ?? null,
        });
    }

    listAttempts() {
        return this.#repository.listCommandAttempts(this.#investigationId);
    }

    ingestOperationalEvidence({
        attemptId,
        evidenceKind,
        kind = "runtime:evidence",
        payload,
    } = {}) {
        return this.#repository.ingestEvidence({
            investigationId: this.#operationalInvestigationId,
            attemptId,
            evidenceKind,
            kind,
            payload,
        });
    }

    ingestOperationalEvidenceBatchFenced(evidence, {
        attemptId,
        command,
        lease,
        fromState,
        toState = null,
    } = {}) {
        if (!Array.isArray(evidence) || evidence.length === 0) {
            throw new RuntimeConfigError(
                "ingestOperationalEvidenceBatchFenced requires a non-empty evidence array",
            );
        }
        const transition = this.#attemptTransition({
            attemptId,
            command,
            lease,
            fromState,
            toState: toState ?? fromState,
        });
        const normalized = evidence.map((item, index) => {
            requirePlainObject(item, `evidence[${index}]`);
            if (item.attemptId !== undefined && item.attemptId !== attemptId) {
                throw new RuntimeConfigError(
                    "operational evidence attemptId must match its fenced attempt",
                    {
                        expectedAttemptId: attemptId,
                        actualAttemptId: item.attemptId,
                        index,
                    },
                );
            }
            return {
                evidenceKind: item.evidenceKind,
                kind: item.kind ?? "runtime:evidence",
                payload: item.payload,
                ...(item.createdAt === undefined ? {} : { createdAt: item.createdAt }),
            };
        });
        const input = {
            investigationId: this.#operationalInvestigationId,
            authorityInvestigationId: this.#investigationId,
            attemptId: transition.attemptId,
            attemptCommand: transition.attemptCommand,
            leaseId: transition.leaseId,
            fencingToken: transition.fencingToken,
            owner: transition.owner,
            supervisorGeneration: transition.supervisorGeneration,
            runnerIncarnation: transition.runnerIncarnation,
            evidence: normalized,
        };
        if (toState === null) {
            return this.#repository.ingestEvidenceBatchFenced({
                ...input,
                expectedState: fromState,
            });
        }
        return this.#repository.ingestEvidenceBatchWithAttemptTransition({
            ...input,
            fromState,
            toState,
        });
    }

    ingestOperationalEvidenceFenced(evidence, authority) {
        return this.ingestOperationalEvidenceBatchFenced([evidence], authority);
    }

    recordOperationalNonResult({ attemptId, code, reason, details = null } = {}) {
        requireString(code, "code", { max: 128 });
        requireString(reason, "reason", { max: 4096, allowLineBreaks: true });
        return this.ingestOperationalEvidence({
            attemptId,
            evidenceKind: `non-result:${code}`,
            kind: "runtime:non_result",
            payload: { code, reason, details },
        });
    }

    recordOperationalRecovery({
        attemptId,
        previousSeq,
        policy,
        reason,
        details = null,
    } = {}) {
        requireString(attemptId, "attemptId", { max: 256 });
        requireString(policy, "policy", { max: 128 });
        requireString(reason, "reason", { max: 4096, allowLineBreaks: true });
        if (!Number.isSafeInteger(previousSeq) || previousSeq < 1) {
            throw new RuntimeConfigError("previousSeq must be a positive safe integer");
        }
        const current = this.latestOperationalNonResult();
        if (current === null || current.seq !== previousSeq) {
            throw new RuntimeIntegrityError(
                "Operational recovery must reference the current non-result",
                { previousSeq, currentSeq: current?.seq ?? null },
            );
        }
        return this.ingestOperationalEvidence({
            attemptId,
            evidenceKind: `non-result-recovery:${policy}`,
            kind: "runtime:non_result_recovery",
            payload: { previousSeq, policy, reason, details },
        });
    }

    verifyOperationalEvidence() {
        return this.#repository.verifyInvestigation(this.#operationalInvestigationId);
    }

    listOperationalEvidence() {
        const report = this.verifyOperationalEvidence();
        if (!report.ok) {
            throw new RuntimeIntegrityError(
                "Operational evidence repository integrity verification failed",
                { violations: report.violations },
            );
        }
        return this.#repository.listEvents(this.#operationalInvestigationId);
    }

    latestOperationalNonResult() {
        const events = this.listOperationalEvidence();
        for (let index = events.length - 1; index >= 0; index -= 1) {
            if (events[index].kind === "runtime:non_result_recovery") {
                return null;
            }
            if (events[index].kind === "runtime:non_result") {
                return events[index];
            }
        }
        return null;
    }
}

export function createDomainRepositoryAdapter(options) {
    return new DomainRepositoryAdapter(options);
}

export function formatAttemptCommand(scope, fields = {}) {
    requireString(scope, "scope", { max: 128 });
    requirePlainObject(fields, "fields");
    return { scope, ...fields };
}
