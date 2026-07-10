import {
    EVENT_TYPES,
    OBSERVATION_STREAM_HASH_ALGORITHM,
    SNAPSHOT_EXECUTION_HASH_ALGORITHM,
    artifactRefsFromProvenance,
    canonicalEqual,
    canonicalJson,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    createExternalEvent,
    createInvestigationOpenedEvent,
    createMeasurementProvenance,
    createSnapshotProvenance,
    hashCanonical,
    reduceEvent,
    replayEvents,
    verifyEventChain,
} from "../domain/index.mjs";
import {
    ERROR_CODES as PERSISTENCE_ERROR_CODES,
    openRepository,
    sha256Hex,
} from "../persistence/index.mjs";
import {
    RECEIPT_VERSION,
    STREAM_HASH_ALGORITHM,
    hashReceipt,
    sha256Bytes,
} from "../measurement/index.mjs";
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

const DOMAIN_KIND_PREFIX = "domain:";
const OPERATIONAL_INVESTIGATION_SUFFIX = ".runtime-evidence";
const TERMINAL_METADATA = Object.freeze({
    [EVENT_TYPES.VERIFIED_RESULT]: "verified_result",
    [EVENT_TYPES.TARGET_UNREACHABLE]: "target_unreachable",
});
const SNAPSHOT_CLOSURE_HASH_RE =
    /^sha256:crucible-measurement-snapshot-closure-v1:[a-f0-9]{64}$/u;
const SNAPSHOT_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-measurement-snapshot-closure-v1";
const VALIDATION_RECEIPT_HASH_ALGORITHM =
    "sha256:crucible-runtime-validation-receipts-v1";
const IMPOSSIBILITY_CERTIFICATE_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-certificate-artifact-v1";
const IMPOSSIBILITY_RECEIPT_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-receipt-artifact-v1";
const IMPOSSIBILITY_STDOUT_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-stdout-artifact-v1";
const IMPOSSIBILITY_STDERR_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-stderr-artifact-v1";
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
    "harnessEntryHash",
    "parsed",
    "parserVersion",
    "runnerEpochId",
    "sandbox",
    "stagedDependencyHashes",
    "stagedExecutableHash",
    "startedAt",
    "stderrHash",
    "stdoutHash",
    "version",
]);

function isCasConflict(error) {
    return error?.code === PERSISTENCE_ERROR_CODES.CAS_CONFLICT;
}

function expectedTerminalKind(domainEvent) {
    return TERMINAL_METADATA[domainEvent.type] ?? null;
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

function receiptBindsExecutedBytes(receipt, snapshotHash) {
    const identity = receipt?.candidateSnapshotIdentitySummary;
    const mutation = receipt?.candidateSnapshotMutationCheck;
    return receipt?.version === RECEIPT_VERSION
        && receipt.candidateSnapshotHash === snapshotHash
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
        && receipt.executableHash === receipt.stagedExecutableHash
        && canonicalEqual(
            dependencyIdentity(receipt.dependencyHashes),
            dependencyIdentity(receipt.stagedDependencyHashes),
        );
}

function snapshotExecutionHash(receipt) {
    return hashCanonical({
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

        if (metadata.storage === "external") {
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
        } else if (metadata.storage === "inline") {
            let inline;
            try {
                inline = repository.getInlineArtifact(artifact.artifactId);
            } catch (error) {
                integrityFailure("Terminal closure inline artifact could not be read", {
                    artifactId: artifact.artifactId,
                    label,
                }, error);
            }
            const inlineBytes = Buffer.from(inline.bytes);
            if (inlineBytes.length !== metadata.sizeBytes
                || sha256Hex(inlineBytes) !== expectedHash) {
                integrityFailure("Terminal closure inline artifact checksum or size is invalid", {
                    artifactId: artifact.artifactId,
                    label,
                });
            }
            bytes.set(key, inlineBytes);
        } else {
            integrityFailure("Terminal closure artifact storage kind is invalid", {
                artifactId: artifact.artifactId,
                label,
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
        if (artifact.storage === "external") {
            if (artifact.durable !== true
                || artifact.hashAlgo !== "sha256"
                || artifact.hashValue !== expectedHash) {
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
            continue;
        }
        if (artifact.storage === "inline") {
            const inline = repository.getInlineArtifact(expected.artifactId);
            const inlineBytes = Buffer.from(inline.bytes);
            if (artifact.durable !== true
                || artifact.sizeBytes !== inlineBytes.length
                || sha256Hex(inlineBytes) !== expectedHash) {
                throw new RuntimeIntegrityError(
                    "Domain event provenance inline artifact checksum or size is invalid",
                    {
                        investigationId,
                        seq,
                        artifactId: expected.artifactId,
                    },
                );
            }
            continue;
        }
        throw new RuntimeIntegrityError(
            "Domain event provenance artifact storage kind is invalid",
            {
                investigationId,
                seq,
                artifactId: expected.artifactId,
                storage: artifact.storage,
            },
        );
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
    if (!exactKeys(receipt, MEASUREMENT_RECEIPT_KEYS)) {
        integrityFailure("Measurement receipt artifact does not contain the complete receipt schema", {
            artifactId: measurement.receiptArtifact.artifactId,
            label,
        });
    }
    if (hashReceipt(receipt) !== measurement.receiptHash
        || receipt.parserVersion !== measurement.parserVersion
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
        || sha256Bytes(stderr.bytes, STREAM_HASH_ALGORITHM) !== measurement.rawStderrHash) {
        integrityFailure("Raw output artifact bytes disagree with the full measurement receipt", {
            label,
        });
    }

    const rebuilt = createMeasurementProvenance({
        subjectId: measurement.subjectId,
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
    if (measurements.length !== 1 || provenance.proposalArtifact === null) {
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
    const proposalArtifact = reader.readJson(
        provenance.proposalArtifact,
        `candidate ${evidence.evidenceId} proposal`,
    );
    const value = proposalArtifact.value;
    if (!exactKeys(value, ["assignment", "promptContext", "promptContextHash", "proposal"])
        || value.promptContextHash !== provenance.promptContextHash
        || hashCanonical(value.promptContext, PROMPT_CONTEXT_HASH_ALGORITHM)
            !== provenance.promptContextHash
        || !canonicalEqual(value.assignment, value.promptContext?.assignment)
        || !canonicalEqual(value.assignment, expectedAssignment(command))
        || value.proposal?.candidateId !== command.candidateId
        || !canonicalEqual(measurements[0].receipt.parsed, observation.data)) {
        integrityFailure("Candidate proposal/context artifact is inconsistent with persisted evidence", {
            evidenceId: evidence.evidenceId,
        });
    }
    verifyProposalSnapshot(
        value.proposal,
        measurements[0],
        reader,
        `candidate ${evidence.evidenceId}`,
    );

    if (provenance.measurementReuseArtifact !== null) {
        const reused = reader.readJson(
            provenance.measurementReuseArtifact,
            `candidate ${evidence.evidenceId} measurement reuse`,
        ).value;
        const sourceEvidence = aggregate.evidence[reused?.sourceEvidenceId] ?? null;
        const sourceObservation = sourceEvidence === null
            ? null
            : aggregate.observations[sourceEvidence.observationId] ?? null;
        const sourceMeasurement = sourceEvidence?.receipt?.provenance?.measurements?.find(
            (item) => item.snapshot.snapshotHash === measurements[0].measurement.snapshot.snapshotHash,
        ) ?? null;
        if (!exactKeys(reused, [
            "candidateArtifactHash",
            "candidateId",
            "commandId",
            "duplicateOf",
            "policy",
            "snapshotId",
            "sourceEvidenceId",
            "sourceMeasurementAttemptId",
            "sourceObservationId",
            "sourceReceiptHash",
            "version",
        ])
            || reused.version !== 1
            || reused.policy !== "mark"
            || reused.commandId !== observation.commandId
            || reused.candidateId !== command.candidateId
            || reused.candidateArtifactHash !== measurements[0].measurement.snapshot.snapshotHash
            || reused.snapshotId !== measurements[0].measurement.snapshot.manifestArtifact.objectId
            || reused.duplicateOf !== evidence.duplicateOf
            || sourceEvidence === null
            || sourceObservation === null
            || reused.sourceObservationId !== sourceObservation.observationId
            || reused.sourceMeasurementAttemptId !== sourceObservation.receipt?.attemptId
            || reused.sourceReceiptHash !== sourceMeasurement?.receiptHash) {
            integrityFailure("Measurement-reuse artifact is inconsistent with its source evidence", {
                evidenceId: evidence.evidenceId,
            });
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
    if (provenance.validationCompositeArtifact === null
        || measurements.length !== aggregate.contract.validationCases.length) {
        integrityFailure("Validation evidence has an incomplete composite closure", {
            evidenceId: evidence.evidenceId,
        });
    }
    const bySubject = new Map(measurements.map((item) => [item.measurement.subjectId, item]));
    const caseMap = {};
    const receiptRoots = [];
    const validationCases = [...aggregate.contract.validationCases]
        .sort((left, right) => left.id.localeCompare(right.id));
    for (const validationCase of validationCases) {
        const measured = bySubject.get(validationCase.id);
        if (measured === undefined) {
            integrityFailure("Validation composite omits a frozen validation case", {
                evidenceId: evidence.evidenceId,
                caseId: validationCase.id,
            });
        }
        const outcome = measured.receipt.parsed?.pass === true ? "accept" : "reject";
        caseMap[validationCase.id] = {
            artifactHash: validationCase.artifactHash,
            expectation: validationCase.expectation,
            outcome,
            matched: outcome === validationCase.expectation,
            attemptId: measured.receipt.attemptId,
            parsed: measured.receipt.parsed,
            receiptHash: measured.measurement.receiptHash,
        };
        receiptRoots.push({
            id: validationCase.id,
            receiptHash: measured.measurement.receiptHash,
            attemptId: measured.receipt.attemptId,
        });
    }
    const compositeReceiptHash = hashCanonical(
        { cases: receiptRoots },
        VALIDATION_RECEIPT_HASH_ALGORITHM,
    );
    const composite = reader.readJson(
        provenance.validationCompositeArtifact,
        `validation ${evidence.evidenceId} composite`,
    ).value;
    const caseResults = validationCases.map((validationCase) => ({
        id: validationCase.id,
        artifactHash: validationCase.artifactHash,
        outcome: caseMap[validationCase.id].outcome,
    }));
    if (!exactKeys(composite, ["caseMap", "compositeReceiptHash"])
        || !canonicalEqual(composite.caseMap, caseMap)
        || composite.compositeReceiptHash !== compositeReceiptHash
        || !canonicalEqual(observation.data?.caseResults, caseResults)
        || !canonicalEqual(observation.data?.caseMap, caseMap)
        || observation.data?.compositeReceiptHash !== compositeReceiptHash) {
        integrityFailure("Validation composite artifact disagrees with its full receipts", {
            evidenceId: evidence.evidenceId,
        });
    }
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
    const expectedCertificate = {
        version: command?.certificateVersion,
        verdict: observation.data?.certificateVerdict,
        contractHash: aggregate.contractHash,
        harnessId: command?.harnessId,
        parserVersion: command?.parserVersion,
        verificationRequestHash: command?.requestHash,
        verificationSnapshotHash: measured.measurement.snapshot.snapshotHash,
        measurementReceiptHash: measured.measurement.receiptHash,
        verifiedFacts: observation.data?.verifiedFacts,
        parsedResult: measured.receipt.parsed,
    };
    const requestEntry = measured.snapshot.manifest.entries.length === 1
        ? measured.snapshot.manifest.entries[0]
        : null;
    const requestArtifact = requestEntry === null
        ? null
        : measured.snapshot.objectArtifacts.get(requestEntry.object) ?? null;
    const requestBytes = requestArtifact === null
        ? null
        : reader.read(
            requestArtifact,
            `impossibility ${evidence.evidenceId} verification request`,
        ).bytes;
    if (command?.kind !== "verify_impossibility"
        || requestEntry?.path !== "request.json"
        || requestBytes === null
        || requestBytes.toString("utf8") !== canonicalJson(command.request)
        || !canonicalEqual(certificate, expectedCertificate)
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
        || (evidence.purpose !== "validation"
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
    const expectedStdout = evidence.purpose === "validation"
        ? hashCanonical(stdoutHashes, OBSERVATION_STREAM_HASH_ALGORITHM)
        : measurements[0]?.measurement.rawStdoutHash ?? null;
    const expectedStderr = evidence.purpose === "validation"
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

export class DomainRepositoryAdapter {
    #repository;
    #investigationId;
    #operationalInvestigationId;

    constructor({ repository, investigationId, ensure = true } = {}) {
        if (repository === null
            || typeof repository !== "object"
            || typeof repository.appendEvents !== "function"
            || typeof repository.appendEventsWithAttemptTransition !== "function"
            || typeof repository.verifyInvestigation !== "function"
            || typeof repository.listArtifactRefsForEvent !== "function"
            || typeof repository.getArtifact !== "function"
            || typeof repository.getInlineArtifact !== "function") {
            throw new RuntimeConfigError("repository must be an EventRepository");
        }
        this.#repository = repository;
        this.#investigationId = requireIdentifier(investigationId, "investigationId");
        this.#operationalInvestigationId =
            `${this.#investigationId}${OPERATIONAL_INVESTIGATION_SUFFIX}`;
        if (ensure) {
            this.#repository.ensureInvestigation({
                investigationId: this.#investigationId,
                metadata: { role: "crucible-domain" },
            });
            this.#repository.ensureInvestigation({
                investigationId: this.#operationalInvestigationId,
                metadata: {
                    role: "crucible-runtime-evidence",
                    domainInvestigationId: this.#investigationId,
                },
            });
        }
    }

    get repository() {
        return this.#repository;
    }

    get investigationId() {
        return this.#investigationId;
    }

    get operationalInvestigationId() {
        return this.#operationalInvestigationId;
    }

    replay() {
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
            const aggregate = replayEvents(domainEvents);
            return { aggregate, domainEvents, repositoryEvents: rows, repositoryReport };
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

    verifyTerminalArtifactClosure({ artifactStore } = {}) {
        const replay = this.replay();
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
        for (const evidenceId of aggregate.evidenceOrder) {
            const evidence = aggregate.evidence[evidenceId] ?? null;
            if (evidence === null) {
                throw new RuntimeIntegrityError(
                    "Terminal evidence order references missing evidence",
                    { investigationId: this.#investigationId, evidenceId },
                );
            }
            if (evidence.sourceKind === "harness") {
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

        return {
            ...replay,
            artifactClosureReport: {
                ok: true,
                terminal: true,
                checkedArtifacts: reader.count(),
                checkedEvidence,
                checkedMeasurements,
            },
        };
    }

    openInvestigation(contract) {
        const current = this.replay();
        if (current.domainEvents.length !== 0) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                "Investigation already has domain events",
                { investigationId: this.#investigationId },
            );
        }
        return this.appendDomainEvent(createInvestigationOpenedEvent(contract), {
            aggregate: current.aggregate,
        });
    }

    appendDomainEvent(domainEvent, options = {}) {
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

    appendFromFactory(factory, { maxCasRetries = 8, attemptTransition = null } = {}) {
        if (typeof factory !== "function") {
            throw new RuntimeConfigError("appendFromFactory requires a function");
        }
        for (let attempt = 0; attempt <= maxCasRetries; attempt += 1) {
            const { aggregate } = this.replay();
            const domainEvent = factory(aggregate);
            if (domainEvent === null) {
                return { aggregate, domainEvent: null, repositoryEvent: null };
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

    resumeInvestigation() {
        return this.appendFromFactory((aggregate) => {
            if (aggregate.pause === null) return null;
            return constructInvestigationResumedEvent(aggregate);
        });
    }

    appendExternal(type, payload) {
        return this.appendFromFactory((aggregate) => createExternalEvent(aggregate, type, payload));
    }

    appendHarnessObservation(payload) {
        return this.appendFromFactory((aggregate) =>
            constructHarnessObservedEvent(aggregate, payload));
    }

    appendHarnessObservationFenced(payload, { attemptId, lease } = {}) {
        requireString(attemptId, "attemptId", { max: 256 });
        requirePlainObject(lease, "lease");
        return this.appendFromFactory(
            (aggregate) => constructHarnessObservedEvent(aggregate, payload),
            {
                attemptTransition: {
                    attemptId,
                    leaseId: lease.leaseId,
                    fencingToken: lease.fencingToken,
                    owner: lease.owner,
                    fromState: "dispatched",
                    toState: "observed",
                },
            },
        );
    }

    appendEvidenceCommit(input) {
        return this.appendFromFactory((aggregate) =>
            constructEvidenceCommittedEvent(aggregate, input));
    }

    appendEvidenceCommitFenced(input, { attemptId, lease } = {}) {
        requireString(attemptId, "attemptId", { max: 256 });
        requirePlainObject(lease, "lease");
        return this.appendFromFactory(
            (aggregate) => constructEvidenceCommittedEvent(aggregate, input),
            {
                attemptTransition: {
                    attemptId,
                    leaseId: lease.leaseId,
                    fencingToken: lease.fencingToken,
                    owner: lease.owner,
                    fromState: "observed",
                    toState: "committed",
                },
            },
        );
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

    acquireRunnerLease({ leaseId, owner } = {}) {
        requireString(leaseId, "leaseId", { max: 256 });
        requireString(owner, "owner", { max: 256 });
        const lease = this.#repository.acquireLease({
            investigationId: this.#investigationId,
            leaseId,
            owner,
        });
        const recovery = this.recoverStaleAttempts(lease);
        return { lease, recovery };
    }

    recoverStaleAttempts(lease) {
        requirePlainObject(lease, "lease");
        const attempts = this.#repository.listCommandAttempts(this.#investigationId);
        const abandoned = [];
        let uncertainDispatched = 0;
        for (const attempt of attempts) {
            if (attempt.state === "committed"
                || attempt.state === "abandoned"
                || attempt.fencingToken >= lease.fencingToken) {
                continue;
            }
            if (attempt.state === "dispatched" || attempt.state === "observed") {
                uncertainDispatched += 1;
            }
            abandoned.push(this.#repository.abandonStaleCommand({
                investigationId: this.#investigationId,
                attemptId: attempt.attemptId,
                leaseId: lease.leaseId,
                fencingToken: lease.fencingToken,
                owner: lease.owner,
            }));
        }
        return Object.freeze({
            abandoned: Object.freeze(abandoned),
            abandonedCount: abandoned.length,
            uncertainDispatched,
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
        });
    }

    dispatchAttempt(attemptId, lease) {
        return this.#repository.dispatchCommand({
            investigationId: this.#investigationId,
            attemptId,
            fencingToken: lease.fencingToken,
        });
    }

    observeAttempt(attemptId, lease) {
        return this.#repository.observeCommand({
            investigationId: this.#investigationId,
            attemptId,
            fencingToken: lease.fencingToken,
        });
    }

    commitAttempt(attemptId, lease) {
        return this.#repository.commitCommand({
            investigationId: this.#investigationId,
            attemptId,
            fencingToken: lease.fencingToken,
        });
    }

    getAttempt(attemptId) {
        return this.#repository.getCommandAttempt(attemptId);
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

export function openDomainRepositoryAdapter({
    file,
    investigationId,
    repositoryOptions = {},
} = {}) {
    const repository = openRepository({ ...repositoryOptions, file });
    const adapter = new DomainRepositoryAdapter({ repository, investigationId });
    return { repository, adapter };
}

export function formatAttemptCommand(scope, fields = {}) {
    requireString(scope, "scope", { max: 128 });
    requirePlainObject(fields, "fields");
    return { scope, ...fields };
}
