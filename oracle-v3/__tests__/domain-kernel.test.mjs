import { describe, expect, it } from "vitest";
import {
    ERROR_CODES,
    EVENT_TYPES,
    NON_RESULT_CODES,
    canonicalJson,
    computeEventHash,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    constructModelObservedEvent,
    createExternalEvent,
    createInitialAggregate,
    createInvestigationContract,
    createInvestigationOpenedEvent,
    decideNext,
    hashCanonical,
    reduceEvent,
    replayEvents,
    verifyEventChain,
} from "../domain/index.mjs";

function contractInput(overrides = {}) {
    return {
        objective: "Find a candidate with a passing harness score of at least 90",
        acceptancePredicate: {
            kind: "all",
            predicates: [
                { kind: "harness_pass" },
                {
                    kind: "metric_compare",
                    metric: "score",
                    operator: ">=",
                    value: 90,
                },
            ],
        },
        validationCases: [
            {
                id: "known-good",
                expectation: "accept",
                artifactHash: artifactHash("a"),
            },
            {
                id: "known-bad",
                expectation: "reject",
                artifactHash: artifactHash("b"),
            },
        ],
        harnessId: "primary-harness",
        hypothesisTopology: "finite_enumerable",
        criticality: "high",
        policyVersion: "policy-v1",
        parserVersion: "parser-v1",
        workerModels: ["model-alpha", "model-beta"],
        candidatesPerRound: 1,
        maxRounds: 4,
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        declaredLimits: { maxCommands: 10 },
        ...overrides,
    };
}

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

function passingValidationData(overrides = {}) {
    return {
        caseResults: [
            {
                id: "known-good",
                artifactHash: artifactHash("a"),
                outcome: "accept",
            },
            {
                id: "known-bad",
                artifactHash: artifactHash("b"),
                outcome: "reject",
            },
        ],
        ...overrides,
    };
}

function append(history, aggregate, event) {
    history.push(event);
    return reduceEvent(aggregate, event);
}

function openInvestigation(overrides = {}) {
    const contract = createInvestigationContract(contractInput(overrides));
    const history = [];
    let aggregate = createInitialAggregate();
    aggregate = append(
        history,
        aggregate,
        createInvestigationOpenedEvent(contract),
    );
    return { aggregate, contract, history };
}

function reserveAndDispatch(history, aggregate) {
    const reserve = constructKernelDecisionEvent(aggregate);
    aggregate = append(history, aggregate, reserve);
    const commandId = reserve.payload.commandId;
    aggregate = append(
        history,
        aggregate,
        createExternalEvent(aggregate, EVENT_TYPES.COMMAND_DISPATCHED, {
            commandId,
        }),
    );
    return { aggregate, commandId, command: reserve.payload.command };
}

function observeAndCommit(
    history,
    aggregate,
    commandId,
    {
        observationId,
        evidenceId,
        sourceKind = "harness",
        purpose,
        round,
        candidateId,
        data,
    },
) {
    aggregate = append(
        history,
        aggregate,
        sourceKind === "harness"
            ? constructHarnessObservedEvent(aggregate, {
                commandId,
                observationId,
                purpose,
                round,
                candidateId,
                receipt: {
                    attemptId: `attempt-${observationId}`,
                    runnerEpochId: "runner-epoch-1",
                    rawStdoutHash: hashCanonical({ observationId, stream: "stdout" }),
                    rawStderrHash: hashCanonical({ observationId, stream: "stderr" }),
                    candidateArtifactHash: purpose === "validation"
                        ? null
                        : hashCanonical({ observationId, artifact: true }),
                },
                data,
            })
            : constructModelObservedEvent(aggregate, {
                commandId,
                observationId,
                purpose,
                data,
            }),
    );
    aggregate = append(
        history,
        aggregate,
        constructEvidenceCommittedEvent(aggregate, {
            evidenceId,
            observationId,
        }),
    );
    return aggregate;
}

function validateInvestigation(context) {
    let { aggregate } = context;
    const dispatched = reserveAndDispatch(context.history, aggregate);
    aggregate = observeAndCommit(
        context.history,
        dispatched.aggregate,
        dispatched.commandId,
        {
            observationId: "validation-observation",
            evidenceId: "validation-evidence",
            purpose: "validation",
            data: passingValidationData({
                validationPassed: false,
                seedChecks: 4,
            }),
        },
    );
    const validation = constructKernelDecisionEvent(aggregate);
    expect(validation.type).toBe(EVENT_TYPES.VALIDATION_COMPLETED);
    aggregate = append(context.history, aggregate, validation);
    context.aggregate = aggregate;
    return context;
}

function commitCandidate(context, {
    observationId = "candidate-observation",
    evidenceId = "candidate-evidence",
    candidateId = "candidate-1",
    sourceKind = "harness",
    data = { pass: true, metrics: { score: 95 } },
} = {}) {
    const dispatched = reserveAndDispatch(context.history, context.aggregate);
    context.aggregate = observeAndCommit(
        context.history,
        dispatched.aggregate,
        dispatched.commandId,
        {
            observationId,
            evidenceId,
            sourceKind,
            purpose: "candidate",
            round: dispatched.command.round,
            candidateId,
            data,
        },
    );
    return context;
}

function forgeEvent(aggregate, type, payload) {
    const core = {
        seq: aggregate.lastSeq + 1,
        prevHash: aggregate.lastEventHash,
        type,
        payload,
    };
    return {
        ...core,
        eventHash: computeEventHash(core),
    };
}

describe("Oracle v3 event-sourced domain kernel", () => {
    it("replays deterministically and verifies the event chain", () => {
        const context = commitCandidate(validateInvestigation(openInvestigation()));
        expect(context.aggregate.evidence["candidate-evidence"]).toMatchObject({
            round: 1,
            candidateId: "candidate-1",
        });
        const terminalEvent = constructKernelDecisionEvent(context.aggregate);
        context.aggregate = append(context.history, context.aggregate, terminalEvent);

        const first = replayEvents(context.history);
        const second = replayEvents(JSON.parse(JSON.stringify(context.history)));
        expect(canonicalJson(first)).toBe(canonicalJson(second));
        expect(first).toEqual(context.aggregate);
        expect(verifyEventChain(context.history)).toEqual({
            valid: true,
            eventCount: context.history.length,
            lastSeq: context.aggregate.lastSeq,
            lastEventHash: context.aggregate.lastEventHash,
        });
    });

    it("detects hash-chain tampering", () => {
        const context = validateInvestigation(openInvestigation());
        const tampered = JSON.parse(JSON.stringify(context.history));
        const observed = tampered.find((event) => event.type === EVENT_TYPES.COMMAND_OBSERVED);
        observed.payload.data.seedChecks = 999;

        expect(() => verifyEventChain(tampered)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.EVENT_HASH_MISMATCH }),
        );
        expect(() => replayEvents(tampered)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.EVENT_HASH_MISMATCH }),
        );
    });

    it("freezes and pins the contract and acceptance predicate", () => {
        const input = contractInput();
        const contract = createInvestigationContract(input);
        input.objective = "changed later";
        input.acceptancePredicate.predicates[1].value = 0;
        input.validationCases[0].expectation = "reject";
        input.workerModels[0] = "changed-model";
        input.metrics[0].direction = "min";
        input.declaredLimits.maxCommands = 999;

        expect(contract.objective).not.toBe(input.objective);
        expect(contract.acceptancePredicate.predicates[1].value).toBe(90);
        expect(contract.validationCases[0].expectation).toBe("accept");
        expect(contract.workerModels[0]).toBe("model-alpha");
        expect(contract.metrics[0].direction).toBe("max");
        expect(contract.declaredLimits.maxCommands).toBe(10);
        expect(Object.isFrozen(contract)).toBe(true);
        expect(Object.isFrozen(contract.acceptancePredicate.predicates)).toBe(true);
        expect(Object.isFrozen(contract.validationCases)).toBe(true);
        expect(Object.isFrozen(contract.workerModels)).toBe(true);
        expect(Object.isFrozen(contract.metrics)).toBe(true);
        expect(() => {
            contract.acceptancePredicate.predicates[1].value = 0;
        }).toThrow(TypeError);
        expect(() => createInvestigationContract(contractInput({
            harnessId: "C:\\arbitrary\\harness.mjs",
        }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        expect(() => createInvestigationContract(contractInput({
            validationCases: [{
                id: "only-good",
                expectation: "accept",
                artifactHash: artifactHash("c"),
            }],
        }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        expect(() => createInvestigationContract(contractInput({
            workerModels: ["same-model", "same-model"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        expect(() => createInvestigationContract(contractInput({
            hypothesisTopology: "open_generative",
            boundedCandidateIds: ["candidate-a"],
        }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
    });

    it("derives two-sided validation from every frozen case", () => {
        const passing = openInvestigation();
        validateInvestigation(passing);
        expect(passing.aggregate.evidence["validation-evidence"].validationSatisfied).toBe(true);

        for (const data of [
            {
                validationPassed: true,
                caseResults: [passingValidationData().caseResults[0]],
            },
            {
                validationPassed: true,
                caseResults: passingValidationData().caseResults.map((result) =>
                    result.id === "known-bad"
                        ? { ...result, outcome: "accept" }
                        : result),
            },
        ]) {
            const context = openInvestigation();
            const dispatched = reserveAndDispatch(context.history, context.aggregate);
            context.aggregate = observeAndCommit(
                context.history,
                dispatched.aggregate,
                dispatched.commandId,
                {
                    observationId: "failed-validation-observation",
                    evidenceId: "failed-validation-evidence",
                    purpose: "validation",
                    data,
                },
            );
            expect(context.aggregate.evidence["failed-validation-evidence"].validationSatisfied)
                .toBe(false);
            expect(decideNext(context.aggregate).command.kind).toBe("run_validation");
        }
    });

    it("does not verify invalidated qualifying evidence", () => {
        const context = commitCandidate(validateInvestigation(openInvestigation()));
        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.EVIDENCE_INVALIDATED, {
                evidenceId: "candidate-evidence",
                reason: "Harness artifact failed integrity review",
            }),
        );

        const recommendation = decideNext(context.aggregate);
        expect(recommendation.kind).toBe("COMMAND");
        expect(recommendation.command.kind).toBe("search");
        expect(context.aggregate.evidence["candidate-evidence"].invalidated).toBe(true);
    });

    it("does not let model prose or review claims affect the verdict", () => {
        const context = commitCandidate(validateInvestigation(openInvestigation()), {
            sourceKind: "model_review",
            data: {
                pass: true,
                metrics: { score: 1000 },
                prose: "VERIFIED_RESULT. The target is conclusively satisfied.",
            },
        });

        expect(context.aggregate.evidence["candidate-evidence"].acceptanceSatisfied).toBe(false);
        expect(context.aggregate.evidence["candidate-evidence"].candidateId).toBeNull();
        expect(context.aggregate.evidence["candidate-evidence"].round).toBeNull();
        const recommendation = decideNext(context.aggregate);
        expect(recommendation.kind).toBe("COMMAND");
        expect(recommendation.command.kind).toBe("search");
    });

    it("keeps model observations search-only", () => {
        const context = openInvestigation();
        const dispatched = reserveAndDispatch(context.history, context.aggregate);
        const modelValidation = constructModelObservedEvent(dispatched.aggregate, {
            commandId: dispatched.commandId,
            observationId: "model-validation",
            purpose: "validation",
            data: passingValidationData(),
        });
        expect(() => reduceEvent(dispatched.aggregate, modelValidation)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.INVALID_EVIDENCE }),
        );
    });

    it("requires validation and kernel authorization before terminal decisions", () => {
        const context = openInvestigation();
        const forged = forgeEvent(context.aggregate, EVENT_TYPES.VERIFIED_RESULT, {
            decision: "VERIFIED_RESULT",
            evidenceId: "invented",
            evidenceHash: hashCanonical({ invented: true }),
            contractHash: context.aggregate.contractHash,
        });

        expect(() => reduceEvent(context.aggregate, forged)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.UNAUTHORIZED_DECISION }),
        );
        expect(decideNext(context.aggregate).command.kind).toBe("run_validation");
    });

    it("makes terminal decisions absorbing", () => {
        const context = commitCandidate(validateInvestigation(openInvestigation()));
        context.aggregate = append(
            context.history,
            context.aggregate,
            constructKernelDecisionEvent(context.aggregate),
        );
        expect(context.aggregate.terminal.decision).toBe("VERIFIED_RESULT");

        expect(() => createExternalEvent(
            context.aggregate,
            EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
            { epochId: "later", capabilities: [] },
        )).toThrow(expect.objectContaining({ code: ERROR_CODES.TERMINAL_STATE }));

        const annotation = forgeEvent(
            context.aggregate,
            EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
            { epochId: "later", capabilities: [] },
        );
        expect(() => reduceEvent(context.aggregate, annotation)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.TERMINAL_STATE }),
        );
    });

    it("resumes only through the kernel-owned transition and clears the persisted pause", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "open_generative",
        }));
        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.STOP_REQUESTED, {
                requestId: "pause-for-resume",
                reason: "operator pause",
                pauseRequested: true,
            }),
        );
        context.aggregate = append(
            context.history,
            context.aggregate,
            constructKernelDecisionEvent(context.aggregate),
        );
        expect(context.aggregate.pause).not.toBeNull();
        expect(context.aggregate.status).toBe("paused");
        expect(() => createExternalEvent(
            context.aggregate,
            EVENT_TYPES.INVESTIGATION_RESUMED,
            {},
        )).toThrow(expect.objectContaining({ code: ERROR_CODES.UNAUTHORIZED_DECISION }));

        const resumed = constructInvestigationResumedEvent(context.aggregate);
        context.aggregate = append(context.history, context.aggregate, resumed);
        expect(context.aggregate.pause).toBeNull();
        expect(context.aggregate.status).toBe("active");
        expect(context.aggregate.pauseHistory).toHaveLength(1);
        expect(decideNext(context.aggregate).command.kind).toBe("search");
    });

    it("forbids TARGET_UNREACHABLE for open-generative search and emits a budget non-result", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "open_generative",
            declaredLimits: { maxCommands: 1 },
        }));
        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.STOP_REQUESTED, {
                requestId: "stop-open",
                reason: "No improvement before the declared budget",
            }),
        );

        const recommendation = decideNext(context.aggregate);
        expect(recommendation.kind).toBe("NON_RESULT");
        expect(recommendation.code).toBe(NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE);
        const nonResult = constructKernelDecisionEvent(context.aggregate);
        expect(nonResult.type).toBe(EVENT_TYPES.NON_RESULT_RECORDED);
        expect(nonResult.type).not.toBe(EVENT_TYPES.TARGET_UNREACHABLE);
    });

    it("derives finite exhaustion only after every bounded candidate has evidence", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "finite_enumerable",
            workerModels: ["model-alpha"],
            candidatesPerRound: 2,
            maxRounds: 1,
            boundedCandidateIds: ["candidate-a", "candidate-b"],
        }));
        commitCandidate(context, {
            observationId: "candidate-a-observation",
            evidenceId: "candidate-a-evidence",
            candidateId: "candidate-a",
            data: {
                pass: false,
                searchSpaceExhausted: true,
                metrics: { score: 10 },
            },
        });
        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.STOP_REQUESTED, {
                requestId: "stop-too-early",
                reason: "One bounded candidate remains unmeasured",
            }),
        );
        const premature = decideNext(context.aggregate);
        expect(premature.event.type).toBe(EVENT_TYPES.SEARCH_STRATEGY_REVISED);
        context.aggregate = append(
            context.history,
            context.aggregate,
            constructKernelDecisionEvent(context.aggregate),
        );
        commitCandidate(context, {
            observationId: "candidate-b-observation",
            evidenceId: "candidate-b-evidence",
            candidateId: "candidate-b",
            data: { pass: false, metrics: { score: 20 } },
        });
        expect(decideNext(context.aggregate).command.kind).toBe("await_stop_request");

        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.STOP_REQUESTED, {
                requestId: "stop-finite",
                reason: "Every declared candidate was measured",
            }),
        );

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
            basis: {
                kind: "search_space_exhausted",
                topology: "finite_enumerable",
                boundedCandidateIds: ["candidate-a", "candidate-b"],
            },
        });
        context.aggregate = append(
            context.history,
            context.aggregate,
            constructKernelDecisionEvent(context.aggregate),
        );
        expect(context.aggregate.terminal.decision).toBe("TARGET_UNREACHABLE");
    });

    it("does not exhaust a bounded space through invalidated candidate evidence", () => {
        const context = validateInvestigation(openInvestigation({
            workerModels: ["model-alpha"],
            candidatesPerRound: 2,
            maxRounds: 1,
            boundedCandidateIds: ["candidate-a", "candidate-b"],
        }));
        for (const candidateId of ["candidate-a", "candidate-b"]) {
            commitCandidate(context, {
                observationId: `${candidateId}-observation`,
                evidenceId: `${candidateId}-evidence`,
                candidateId,
                data: { pass: false, metrics: { score: 10 } },
            });
        }
        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.EVIDENCE_INVALIDATED, {
                evidenceId: "candidate-b-evidence",
                reason: "Candidate artifact receipt was revoked",
            }),
        );
        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.STOP_REQUESTED, {
                requestId: "stop-invalidated-bounded",
                reason: "Attempted exhaustion with a missing current candidate",
            }),
        );

        expect(decideNext(context.aggregate).event.type).toBe(EVENT_TYPES.SEARCH_STRATEGY_REVISED);
    });

    it("selects the best accepted candidate by frozen metrics and closes the evidence", () => {
        const context = validateInvestigation(openInvestigation({
            acceptancePredicate: { kind: "harness_pass" },
            workerModels: ["model-alpha", "model-beta"],
            candidatesPerRound: 3,
            maxRounds: 1,
            metrics: [
                { key: "cost", direction: "min", epsilon: 0 },
                { key: "quality", direction: "max", epsilon: 0 },
            ],
        }));
        for (const candidate of [
            { candidateId: "candidate-z", cost: 10, quality: 5 },
            { candidateId: "candidate-a", cost: 10, quality: 7 },
            { candidateId: "candidate-b", cost: 8, quality: 1 },
        ]) {
            commitCandidate(context, {
                observationId: `${candidate.candidateId}-observation`,
                evidenceId: `${candidate.candidateId}-evidence`,
                candidateId: candidate.candidateId,
                data: {
                    pass: true,
                    metrics: {
                        cost: candidate.cost,
                        quality: candidate.quality,
                    },
                },
            });
        }

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
            candidateId: "candidate-b",
            evidenceId: "candidate-b-evidence",
        });
        expect(recommendation.event.payload.evidenceClosure).toEqual({
            validation: {
                evidenceId: "validation-evidence",
                evidenceHash: context.aggregate.evidence["validation-evidence"].commitEventHash,
            },
            candidates: [
                {
                    candidateId: "candidate-b",
                    evidenceId: "candidate-b-evidence",
                    evidenceHash: context.aggregate.evidence["candidate-b-evidence"].commitEventHash,
                },
                {
                    candidateId: "candidate-a",
                    evidenceId: "candidate-a-evidence",
                    evidenceHash: context.aggregate.evidence["candidate-a-evidence"].commitEventHash,
                },
                {
                    candidateId: "candidate-z",
                    evidenceId: "candidate-z-evidence",
                    evidenceHash: context.aggregate.evidence["candidate-z-evidence"].commitEventHash,
                },
            ],
        });
    });

    it("uses candidateId only after all epsilon-bucketed metrics tie", () => {
        const context = validateInvestigation(openInvestigation({
            workerModels: ["model-alpha"],
            candidatesPerRound: 2,
            maxRounds: 1,
            metrics: [{ key: "score", direction: "max", epsilon: 5 }],
        }));
        commitCandidate(context, {
            observationId: "candidate-z-observation",
            evidenceId: "candidate-z-evidence",
            candidateId: "candidate-z",
            data: { pass: true, metrics: { score: 101 } },
        });
        commitCandidate(context, {
            observationId: "candidate-a-observation",
            evidenceId: "candidate-a-evidence",
            candidateId: "candidate-a",
            data: { pass: true, metrics: { score: 102 } },
        });

        expect(decideNext(context.aggregate)).toMatchObject({
            decision: "VERIFIED_RESULT",
            candidateId: "candidate-a",
        });
    });

    it("rejects duplicate candidate IDs across committed harness evidence", () => {
        const context = validateInvestigation(openInvestigation({
            workerModels: ["model-alpha"],
            candidatesPerRound: 2,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            observationId: "first-candidate-observation",
            evidenceId: "first-candidate-evidence",
            candidateId: "same-candidate",
        });
        const dispatched = reserveAndDispatch(context.history, context.aggregate);
        context.aggregate = append(
            context.history,
            dispatched.aggregate,
            constructHarnessObservedEvent(dispatched.aggregate, {
                commandId: dispatched.commandId,
                observationId: "duplicate-candidate-observation",
                purpose: "candidate",
                round: dispatched.command.round,
                candidateId: "same-candidate",
                receipt: {
                    attemptId: "attempt-duplicate",
                    runnerEpochId: "runner-epoch-1",
                    rawStdoutHash: hashCanonical({ duplicate: "stdout" }),
                    rawStderrHash: hashCanonical({ duplicate: "stderr" }),
                    candidateArtifactHash: hashCanonical({ duplicate: "artifact" }),
                },
                data: { pass: true, metrics: { score: 96 } },
            }),
        );

        expect(() => constructEvidenceCommittedEvent(context.aggregate, {
            evidenceId: "duplicate-candidate-evidence",
            observationId: "duplicate-candidate-observation",
        })).toThrow(expect.objectContaining({ code: ERROR_CODES.DUPLICATE_ID }));
    });

    it("rejects duplicate identifiers and illegal command transitions", () => {
        const context = openInvestigation();
        context.aggregate = append(
            context.history,
            context.aggregate,
            createExternalEvent(context.aggregate, EVENT_TYPES.CAPABILITY_EPOCH_RECORDED, {
                epochId: "epoch-1",
                capabilities: ["node", "node"],
            }),
        );
        const duplicateEpoch = createExternalEvent(
            context.aggregate,
            EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
            { epochId: "epoch-1", capabilities: ["node"] },
        );
        expect(() => reduceEvent(context.aggregate, duplicateEpoch)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.DUPLICATE_ID }),
        );

        const reserve = constructKernelDecisionEvent(context.aggregate);
        context.aggregate = append(context.history, context.aggregate, reserve);
        const observedBeforeDispatch = constructHarnessObservedEvent(
            context.aggregate,
            {
                commandId: reserve.payload.commandId,
                observationId: "too-early",
                purpose: "validation",
                receipt: {
                    attemptId: "attempt-too-early",
                    runnerEpochId: "runner-epoch-1",
                    rawStdoutHash: hashCanonical({ tooEarly: "stdout" }),
                    rawStderrHash: hashCanonical({ tooEarly: "stderr" }),
                    candidateArtifactHash: null,
                },
                data: passingValidationData(),
            },
        );
        expect(() => reduceEvent(context.aggregate, observedBeforeDispatch)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.ILLEGAL_TRANSITION }),
        );

        expect(() => createExternalEvent(
            context.aggregate,
            EVENT_TYPES.COMMAND_OBSERVED,
            {
                commandId: reserve.payload.commandId,
                observationId: "forged-harness",
                sourceKind: "harness",
                purpose: "validation",
                data: passingValidationData(),
            },
        )).toThrow(expect.objectContaining({ code: ERROR_CODES.UNAUTHORIZED_DECISION }));
    });
});
