import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    DEFAULT_SEARCH_POLICY,
    createInvestigationOpenedEvent,
    createInvestigationContract,
    experimentAuthorityIdentity,
} from "../domain/index.mjs";
import * as experimentAuthorityApi from "../api/experiment-authority.mjs";
import { PARSER_VERSION } from "../measurement/index.mjs";
import { openRepository } from "../persistence/index.mjs";
import {
    RUNTIME_ERROR_CODES,
    createDomainRepositoryAdapter,
    formatAttemptCommand,
    inspectInvestigationDomainCompatibility,
} from "../runtime/index.mjs";
import { appendLegacyV3Investigation } from "./legacy-v3-fixture.mjs";
import {
    createExperimentAuthorityFixture,
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
} from "./experiment-authority-fixture.mjs";
import { makeV4ContractInput } from "./v4-contract-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(() => {
    const failures = [];
    for (const root of roots.splice(0)) {
        try {
            fs.rmSync(root, {
                recursive: true,
                force: true,
                maxRetries: 20,
                retryDelay: 25,
            });
        } catch (error) {
            failures.push(error);
        }
        if (fs.existsSync(root)) {
            failures.push(new Error(`domain adapter root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "domain adapter cleanup failed");
    }
});

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

function contract(overrides = {}) {
    return createInvestigationContract(makeV4ContractInput({
        objective: "exercise runtime domain adapter fencing",
        acceptancePredicate: { kind: "harness_pass" },
        hypothesisTopology: "finite_enumerable",
        criticality: "high",
        policyVersion: "policy-v1",
        workerModels: ["model-a"],
        candidatesPerRound: 1,
        maxRounds: 1,
        searchPolicy: DEFAULT_SEARCH_POLICY,
        ...overrides,
    }));
}

function withZeroSignature(authority) {
    const {
        identity: _identity,
        ...unsignedCore
    } = authority;
    const core = {
        ...unsignedCore,
        signature: Buffer.alloc(64).toString("base64"),
    };
    return Object.freeze({
        ...core,
        identity: experimentAuthorityIdentity(core),
    });
}

function openAdapter(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-adapter-fast-${label}-`));
    roots.push(root);
    const repository = openRepository({ file: path.join(root, "events.sqlite") });
    const resolvedContract = contract();
    const signed = createSignedInvestigationAuthority({
        contract: resolvedContract,
        experimentId: `runtime-${label}`,
        projectDir: root,
    });
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: signed.investigationId,
    });
    adapter.openInvestigation(
        resolvedContract,
        signed.capability,
        createRuntimeConfigAuthorityFixture(signed.investigationId),
    );
    return { repository, adapter };
}

describe("Crucible domain repository adapter fast component coverage", () => {
    it("persists storage exhaustion as a non-result without terminal authority", () => {
        const { repository, adapter } = openAdapter("storage-budget");
        try {
            const appended = adapter.appendStorageBudgetNonResult({
                investigationBytes: 100,
                investigationLimitBytes: 100,
                globalBytes: 200,
                globalLimitBytes: 200,
                requestedBytes: 1,
            });
            expect(appended.aggregate).toMatchObject({
                status: "non_result",
                terminal: null,
                nonResults: [{
                    code: "STORAGE_BUDGET_INCONCLUSIVE",
                    storage: {
                        investigationBytes: 100,
                        globalBytes: 200,
                    },
                }],
            });
            expect(adapter.appendStorageBudgetNonResult({
                investigationBytes: 100,
                investigationLimitBytes: 100,
                globalBytes: 200,
                globalLimitBytes: 200,
                requestedBytes: 1,
            }).domainEvent).toBeNull();
        } finally {
            repository.close();
        }
    });

    it("replays the same v4 aggregate after the repository opening event is sealed", () => {
        const { repository, adapter } = openAdapter("segments");
        try {
            const before = adapter.replay();
            const rotated = adapter.rotateSegmentsAtQuiescence({
                includeOperational: false,
                eventThreshold: 1,
                byteThreshold: Number.POSITIVE_INFINITY,
            });
            expect(rotated).toMatchObject({
                domain: {
                    rotated: true,
                    entry: {
                        investigationId: adapter.investigationId,
                        firstSeq: 1,
                        lastSeq: 1,
                        domainVersion: 4,
                    },
                },
                operational: null,
            });
            const after = adapter.replay();
            expect(after.aggregate).toEqual(before.aggregate);
            expect(after.domainEvents).toEqual(before.domainEvents);
            expect(after.repositoryReport.ok).toBe(true);
            expect(repository.getSegmentCatalog({ verify: true }).segments)
                .toHaveLength(1);
            const appended = adapter.appendKernelDecision();
            expect(appended.domainEvent.seq).toBe(2);
            expect(adapter.replay().aggregate).toEqual(appended.aggregate);
        } finally {
            repository.close();
        }
    });

    it("requires the opaque verified capability and persists only its signed envelope", () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".runtime-adapter-capability-"),
        );
        roots.push(root);
        const repository = openRepository({
            file: path.join(root, "events.sqlite"),
        });
        const resolvedContract = contract();
        const signed = createSignedInvestigationAuthority({
            contract: resolvedContract,
            experimentId: "runtime-capability",
            projectDir: root,
        });
        const adapter = createDomainRepositoryAdapter({
            repository,
            investigationId: signed.investigationId,
        });
        const runtimeAuthority = createRuntimeConfigAuthorityFixture(
            signed.investigationId,
        );
        try {
            expect(Object.keys(signed.capability)).toEqual([]);
            expect(Object.isFrozen(signed.capability)).toBe(true);
            expect(experimentAuthorityApi).not.toHaveProperty(
                "VerifiedExperimentAuthority",
            );
            expect(Object.values(experimentAuthorityApi).some(
                (value) => typeof value === "symbol",
            )).toBe(false);
            expect(() => new signed.capability.constructor(
                Object.freeze({ authority: signed.authority }),
            )).toThrow(TypeError);

            for (const forged of [
                signed.authority,
                Object.freeze({}),
                Object.freeze(Object.create(
                    Object.getPrototypeOf(signed.capability),
                )),
            ]) {
                expect(() => adapter.openInvestigation(
                    resolvedContract,
                    forged,
                    runtimeAuthority,
                )).toThrow(expect.objectContaining({
                    code: RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                }));
                expect(repository.countEvents(signed.investigationId)).toBe(0);
            }

            const opened = adapter.openInvestigation(
                resolvedContract,
                signed.capability,
                runtimeAuthority,
            );
            expect(opened.domainEvent.payload.experimentAuthority)
                .toEqual(signed.authority);
            expect(repository.countEvents(signed.investigationId)).toBe(1);
        } finally {
            repository.close();
        }
    });

    it("rejects an exact zero Ed25519 signature and recomputed opening hashes", () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".runtime-adapter-zero-signature-"),
        );
        roots.push(root);
        const repository = openRepository({
            file: path.join(root, "events.sqlite"),
        });
        const resolvedContract = contract();
        const signed = createSignedInvestigationAuthority({
            contract: resolvedContract,
            experimentId: "runtime-zero-signature",
            projectDir: root,
        });
        const zeroSignatureAuthority = withZeroSignature(signed.authority);
        const payload = zeroSignatureAuthority.manifest.experimentPayload;
        const adapter = createDomainRepositoryAdapter({
            repository,
            investigationId: signed.investigationId,
        });
        const runtimeAuthority = createRuntimeConfigAuthorityFixture(
            signed.investigationId,
        );
        try {
            expect(() => experimentAuthorityApi.verifyExperimentAuthority({
                authority: zeroSignatureAuthority,
                experimentId: payload.experimentId,
                projectDir: payload.projectDir,
                harnessSuiteId: payload.harnessSuiteId,
                contract: resolvedContract,
                investigationId: signed.investigationId,
                env: signed.env,
            })).toThrow(expect.objectContaining({
                code: experimentAuthorityApi
                    .EXPERIMENT_AUTHORITY_ERROR_CODES.SIGNATURE_INVALID,
            }));

            const forgedOpening = createInvestigationOpenedEvent(
                resolvedContract,
                zeroSignatureAuthority,
                runtimeAuthority,
            );
            expect(() => adapter.appendDomainEvent(forgedOpening))
                .toThrow(expect.objectContaining({
                    code: RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                }));
            expect(repository.countEvents(signed.investigationId)).toBe(0);
        } finally {
            repository.close();
        }
    });

    it("rejects capabilities bound to another contract, id, or trust key", () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".runtime-adapter-wrong-capability-"),
        );
        roots.push(root);
        const repository = openRepository({
            file: path.join(root, "events.sqlite"),
        });
        const resolvedContract = contract();
        const signed = createSignedInvestigationAuthority({
            contract: resolvedContract,
            experimentId: "runtime-bound-capability",
            projectDir: root,
        });
        const other = createSignedInvestigationAuthority({
            contract: resolvedContract,
            experimentId: "runtime-other-capability",
            projectDir: root,
        });
        const adapter = createDomainRepositoryAdapter({
            repository,
            investigationId: signed.investigationId,
        });
        const runtimeAuthority = createRuntimeConfigAuthorityFixture(
            signed.investigationId,
        );
        try {
            expect(() => adapter.openInvestigation(
                contract({ objective: "different authority-bound contract" }),
                signed.capability,
                runtimeAuthority,
            )).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
            }));
            expect(() => adapter.openInvestigation(
                resolvedContract,
                other.capability,
                runtimeAuthority,
            )).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
            }));

            const wrongIdAdapter = createDomainRepositoryAdapter({
                repository,
                investigationId: "runtime-wrong-capability-id",
            });
            expect(() => wrongIdAdapter.openInvestigation(
                resolvedContract,
                signed.capability,
                createRuntimeConfigAuthorityFixture(
                    "runtime-wrong-capability-id",
                ),
            )).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
            }));

            const replacementTrust = createExperimentAuthorityFixture();
            const payload = signed.authority.manifest.experimentPayload;
            expect(() => experimentAuthorityApi.verifyExperimentAuthority({
                authority: signed.authority,
                experimentId: payload.experimentId,
                projectDir: payload.projectDir,
                harnessSuiteId: payload.harnessSuiteId,
                contract: resolvedContract,
                investigationId: signed.investigationId,
                env: replacementTrust.env,
            })).toThrow(expect.objectContaining({
                code: experimentAuthorityApi
                    .EXPERIMENT_AUTHORITY_ERROR_CODES
                    .TRUST_FINGERPRINT_MISMATCH,
            }));

            expect(repository.countEvents(signed.investigationId)).toBe(0);
            expect(repository.countEvents("runtime-wrong-capability-id")).toBe(0);
        } finally {
            repository.close();
        }
    });

    it("refuses direct unsigned v4 investigation creation", () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".runtime-adapter-unsigned-"),
        );
        roots.push(root);
        const repository = openRepository({
            file: path.join(root, "events.sqlite"),
        });
        try {
            const adapter = createDomainRepositoryAdapter({
                repository,
                investigationId: "unsigned-forged-v4",
            });
            expect(() => adapter.openInvestigation(contract()))
                .toThrow(expect.objectContaining({
                    code: RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID,
                }));
            expect(repository.countEvents("unsigned-forged-v4")).toBe(0);
        } finally {
            repository.close();
        }
    });

    it("discovers actual v3 state read-only and blocks replay, resume, and append setup", () => {
        const root = fs.mkdtempSync(path.join(HERE, ".runtime-adapter-v3-"));
        roots.push(root);
        const repository = openRepository({
            file: path.join(root, "events.sqlite"),
        });
        const investigationId = "legacy-v3-runtime";
        try {
            appendLegacyV3Investigation(
                repository,
                investigationId,
                contract(),
            );
            expect(inspectInvestigationDomainCompatibility({
                repository,
                investigationId,
            })).toMatchObject({
                present: true,
                compatibility: "legacy_incompatible",
                compatible: false,
                domainVersion: 3,
                contractDomainVersion: null,
                eventCount: 1,
                readOnly: true,
                archiveable: false,
            });

            const readOnlyAdapter = createDomainRepositoryAdapter({
                repository,
                investigationId,
                ensure: false,
            });
            for (const operation of [
                () => readOnlyAdapter.replay(),
                () => readOnlyAdapter.resumeInvestigation(),
            ]) {
                expect(operation).toThrow(expect.objectContaining({
                    code: RUNTIME_ERROR_CODES.LEGACY_INCOMPATIBLE,
                    details: expect.objectContaining({
                        compatibility: "legacy_incompatible",
                        actualDomainVersion: 3,
                        restartRequired: true,
                    }),
                }));
            }
            expect(() => createDomainRepositoryAdapter({
                repository,
                investigationId,
            })).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.LEGACY_INCOMPATIBLE,
            }));
            expect(repository.countEvents(investigationId)).toBe(1);
            expect(repository.getInvestigation(
                `${investigationId}.runtime-evidence`,
            )).toBeNull();
        } finally {
            repository.close();
        }
    });

    it("abandons stale reserved and dispatched attempts before replacement work", () => {
        const { repository, adapter } = openAdapter("recovery");
        try {
            const first = adapter.acquireRunnerLease({
                leaseId: "lease-one",
                owner: "runner-one",
            });
            adapter.reserveAttempt({
                attemptId: "attempt-reserved",
                command: formatAttemptCommand("test", { id: 1 }),
                lease: first.lease,
            });
            adapter.reserveAttempt({
                attemptId: "attempt-dispatched",
                command: formatAttemptCommand("test", { id: 2 }),
                lease: first.lease,
            });
            adapter.dispatchAttempt("attempt-dispatched", first.lease);

            const second = adapter.acquireRunnerLease({
                leaseId: "lease-two",
                owner: "runner-two",
            });
            expect(second.recovery).toMatchObject({
                abandonedCount: 2,
                uncertainDispatched: 1,
            });
            expect(repository.getCommandAttempt("attempt-reserved").state)
                .toBe("abandoned");
            expect(repository.getCommandAttempt("attempt-dispatched").state)
                .toBe("abandoned");
        } finally {
            repository.close();
        }
    });

    it("keeps operational evidence outside the domain sequence", () => {
        const { repository, adapter } = openAdapter("operational");
        try {
            const before = adapter.replay().aggregate.seq;
            adapter.ingestOperationalEvidence({
                attemptId: "attempt-fast",
                evidenceKind: "component",
                kind: "runtime:test",
                payload: { bounded: true },
            });

            expect(adapter.replay().aggregate.seq).toBe(before);
            expect(adapter.listOperationalEvidence()).toHaveLength(1);
        } finally {
            repository.close();
        }
    });
});
