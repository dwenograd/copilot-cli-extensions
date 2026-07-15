import {
    ANALYSIS_SCHEMA_VERSION,
    LIMITS,
    validateAuditId,
    validateCandidateFinding,
    validateValidationDecision,
} from "./schemas.mjs";
import { validateRemediationPlan } from "./remediation.mjs";

const LEGAL_FINDING_TRANSITIONS = Object.freeze({
    candidate: Object.freeze(["validating"]),
    validating: Object.freeze(["validated", "refuted", "unresolved"]),
    validated: Object.freeze([]),
    refuted: Object.freeze([]),
    unresolved: Object.freeze(["validating"]),
});

function sameValue(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
}

function clone(value) {
    return structuredClone(value);
}

export class FindingLedger {
    #auditId;
    #maxFindings;
    #maxDecisions;
    #findings = new Map();
    #decisions = [];
    #remediation = null;

    constructor({
        auditId,
        maxFindings = LIMITS.findings,
        maxDecisions = LIMITS.validationDecisions,
    }) {
        this.#auditId = validateAuditId(auditId);
        if (!Number.isSafeInteger(maxFindings)
            || maxFindings < 1
            || maxFindings > LIMITS.findings) {
            throw new RangeError(`maxFindings must be between 1 and ${LIMITS.findings}`);
        }
        if (!Number.isSafeInteger(maxDecisions)
            || maxDecisions < 1
            || maxDecisions > LIMITS.validationDecisions) {
            throw new RangeError(
                `maxDecisions must be between 1 and ${LIMITS.validationDecisions}`,
            );
        }
        this.#maxFindings = maxFindings;
        this.#maxDecisions = maxDecisions;
    }

    get auditId() {
        return this.#auditId;
    }

    get size() {
        return this.#findings.size;
    }

    addCandidate(input) {
        const finding = validateCandidateFinding(input);
        if (finding.auditId !== this.#auditId) {
            throw new Error("finding auditId does not match ledger auditId");
        }
        if (finding.state !== "candidate") {
            throw new Error("new findings must start in candidate state");
        }
        const existing = this.#findings.get(finding.id);
        if (existing) {
            if (!sameValue(existing, finding)) {
                throw new Error(`conflicting finding id: ${finding.id}`);
            }
            return clone(existing);
        }
        if (this.#findings.size >= this.#maxFindings) {
            throw new RangeError(`finding limit exceeded (${this.#maxFindings})`);
        }
        this.#findings.set(finding.id, finding);
        return clone(finding);
    }

    beginValidation(findingId, { auditId } = {}) {
        this.#assertAuditId(auditId);
        const finding = this.#requireFinding(findingId);
        if (finding.state === "validating") return clone(finding);
        this.#assertTransition(finding.state, "validating");
        const updated = validateCandidateFinding({
            ...finding,
            state: "validating",
        });
        this.#findings.set(finding.id, updated);
        return clone(updated);
    }

    applyValidationDecision(input) {
        const decision = validateValidationDecision(input);
        if (decision.auditId !== this.#auditId) {
            throw new Error("validation decision auditId does not match ledger auditId");
        }
        const finding = this.#requireFinding(decision.findingId);
        const lastDecision = this.#decisions.at(-1);
        if (finding.state === decision.decision
            && lastDecision
            && sameValue(lastDecision, decision)) {
            return clone(finding);
        }
        if (finding.state !== "validating") {
            throw new Error(`finding ${finding.id} is not in validating state`);
        }
        this.#assertTransition(finding.state, decision.decision);
        if (this.#decisions.length >= this.#maxDecisions) {
            throw new RangeError(`validation decision limit exceeded (${this.#maxDecisions})`);
        }
        const updated = validateCandidateFinding({
            ...finding,
            state: decision.decision,
            severity: decision.severity,
            confidence: decision.confidence,
            maliciousProjectFit: decision.maliciousProjectFit,
            evidence: mergeEvidence(finding.evidence, decision.evidence),
        });
        this.#decisions.push(decision);
        this.#findings.set(finding.id, updated);
        return clone(updated);
    }

    getFinding(findingId) {
        const finding = this.#findings.get(findingId);
        return finding ? clone(finding) : null;
    }

    listFindings({ state } = {}) {
        const findings = [...this.#findings.values()];
        return findings
            .filter((finding) => !state || finding.state === state)
            .map((finding) => clone(finding));
    }

    listDecisions() {
        return this.#decisions.map((decision) => clone(decision));
    }

    setRemediationPlan(input) {
        const remediation = validateRemediationPlan(input);
        if (remediation.auditId !== this.#auditId) {
            throw new Error("remediation auditId does not match ledger auditId");
        }
        if (this.#remediation) {
            if (!sameValue(this.#remediation, remediation)) {
                throw new Error("conflicting remediation plan for this audit ledger");
            }
            return {
                idempotent: true,
                remediation: clone(this.#remediation),
            };
        }
        const referencedFindingIds = new Set();
        for (const candidate of remediation.candidates) {
            for (const findingId of candidate.sourceFindingIds) {
                const finding = this.#requireFinding(findingId);
                if (finding.state !== "validated") {
                    throw new Error(
                        `remediation candidate requires validated finding: ${findingId}`,
                    );
                }
                if (referencedFindingIds.has(findingId)) {
                    throw new Error(`duplicate remediation candidate for finding: ${findingId}`);
                }
                referencedFindingIds.add(findingId);
            }
        }
        for (const guidance of remediation.investigationGuidance) {
            for (const findingId of guidance.sourceFindingIds) {
                const finding = this.#requireFinding(findingId);
                if (finding.state !== "unresolved") {
                    throw new Error(
                        `investigation guidance requires unresolved finding: ${findingId}`,
                    );
                }
                if (referencedFindingIds.has(findingId)) {
                    throw new Error(`duplicate remediation metadata for finding: ${findingId}`);
                }
                referencedFindingIds.add(findingId);
            }
        }
        this.#remediation = remediation;
        return {
            idempotent: false,
            remediation: clone(remediation),
        };
    }

    getRemediationPlan() {
        return this.#remediation ? clone(this.#remediation) : null;
    }

    toDocument() {
        return Object.freeze({
            schemaVersion: ANALYSIS_SCHEMA_VERSION,
            auditId: this.#auditId,
            findings: Object.freeze(this.listFindings()),
            validationDecisions: Object.freeze(this.listDecisions()),
            remediation: this.getRemediationPlan(),
        });
    }

    #assertAuditId(auditId) {
        const normalized = validateAuditId(auditId);
        if (normalized !== this.#auditId) {
            throw new Error("auditId does not match ledger auditId");
        }
    }

    #requireFinding(findingId) {
        const finding = this.#findings.get(findingId);
        if (!finding) throw new Error(`unknown finding id: ${findingId}`);
        return finding;
    }

    #assertTransition(from, to) {
        if (!LEGAL_FINDING_TRANSITIONS[from]?.includes(to)) {
            throw new Error(`illegal finding state transition: ${from} -> ${to}`);
        }
    }
}

function mergeEvidence(left, right) {
    const merged = [];
    const seen = new Set();
    for (const evidence of [...left, ...right]) {
        const key = JSON.stringify(evidence);
        if (!seen.has(key)) {
            seen.add(key);
            merged.push(evidence);
        }
    }
    if (merged.length > LIMITS.evidencePerItem) {
        throw new RangeError(
            `merged evidence exceeds limit (${LIMITS.evidencePerItem})`,
        );
    }
    return merged;
}

export const __internals = Object.freeze({
    LEGAL_FINDING_TRANSITIONS,
    mergeEvidence,
});
