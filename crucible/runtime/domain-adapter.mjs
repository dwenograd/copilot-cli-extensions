import {
    EVENT_TYPES,
    canonicalEqual,
    canonicalJson,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    createExternalEvent,
    createInvestigationOpenedEvent,
    reduceEvent,
    replayEvents,
    verifyEventChain,
} from "../domain/index.mjs";
import {
    ERROR_CODES as PERSISTENCE_ERROR_CODES,
    openRepository,
} from "../persistence/index.mjs";
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
} from "./utils.mjs";

const DOMAIN_KIND_PREFIX = "domain:";
const OPERATIONAL_INVESTIGATION_SUFFIX = ".runtime-evidence";
const TERMINAL_METADATA = Object.freeze({
    [EVENT_TYPES.VERIFIED_RESULT]: "verified_result",
    [EVENT_TYPES.TARGET_UNREACHABLE]: "target_unreachable",
});

function isCasConflict(error) {
    return error?.code === PERSISTENCE_ERROR_CODES.CAS_CONFLICT;
}

function expectedTerminalKind(domainEvent) {
    return TERMINAL_METADATA[domainEvent.type] ?? null;
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

export class DomainRepositoryAdapter {
    #repository;
    #investigationId;
    #operationalInvestigationId;

    constructor({ repository, investigationId, ensure = true } = {}) {
        if (repository === null
            || typeof repository !== "object"
            || typeof repository.appendEvents !== "function"
            || typeof repository.appendEventsWithAttemptTransition !== "function"
            || typeof repository.verifyInvestigation !== "function") {
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
        const domainEvents = rows.map(assertRepositoryDomainRow);
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
