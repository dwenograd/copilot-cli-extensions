export const ASSURANCE_ANALYSIS_SCHEMA_REVISION = 6;

export const ASSURANCE_STAGES = Object.freeze([
    "acquired",
    "inventoried",
    "decoded",
    "semantically-covered",
    "scanned",
    "red-teamed",
    "traced",
    "validated",
    "finalized",
]);

const AUDIT_ID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SOURCE_NAMESPACE_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}$/;

export class AssuranceStateContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "AssuranceStateContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new AssuranceStateContractError(path, message);
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function objectShape(value, path, required) {
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    const allowed = new Set(required);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) fail(`${path}.${key}`, "unknown field");
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
}

function validateAuditId(value, path) {
    if (typeof value !== "string" || !AUDIT_ID_RE.test(value)) {
        fail(path, "must be a valid random audit ID");
    }
    return value.toLowerCase();
}

function validateSourceNamespace(value, path) {
    if (typeof value !== "string") fail(path, "must be a string");
    const normalized = value.normalize("NFKC").trim();
    if (!SOURCE_NAMESPACE_RE.test(normalized)) {
        fail(path, "has an invalid source namespace format");
    }
    return normalized;
}

function validateStage(value, path) {
    if (!ASSURANCE_STAGES.includes(value)) {
        fail(path, `must be one of: ${ASSURANCE_STAGES.join(", ")}`);
    }
    return value;
}

function cloneFrozen(value) {
    if (Array.isArray(value)) {
        return Object.freeze(value.map((entry) => cloneFrozen(entry)));
    }
    if (isPlainObject(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) {
            result[key] = cloneFrozen(entry);
        }
        return Object.freeze(result);
    }
    return value;
}

export function validateAssuranceStageState(value, path = "assuranceStageState") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "sourceNamespace",
        "current",
        "history",
    ]);
    if (value.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
        fail(
            `${path}.schemaVersion`,
            `must equal ${ASSURANCE_ANALYSIS_SCHEMA_REVISION}; baseline stage state is not assurance state`,
        );
    }
    const current = validateStage(value.current, `${path}.current`);
    if (!Array.isArray(value.history)) fail(`${path}.history`, "must be an array");
    if (value.history.length > ASSURANCE_STAGES.length) {
        fail(
            `${path}.history`,
            `must contain at most ${ASSURANCE_STAGES.length} entries`,
        );
    }
    const history = value.history.map((stage, index) =>
        validateStage(stage, `${path}.history[${index}]`));
    const expected = ASSURANCE_STAGES.slice(
        0,
        ASSURANCE_STAGES.indexOf(current) + 1,
    );
    if (history.length !== expected.length
        || history.some((stage, index) => stage !== expected[index])) {
        fail(`${path}.history`, "must be the legal assurance stage prefix ending at current");
    }
    return cloneFrozen({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        sourceNamespace: validateSourceNamespace(
            value.sourceNamespace,
            `${path}.sourceNamespace`,
        ),
        current,
        history,
    });
}

export function createInitialAssuranceStageState({ auditId, sourceNamespace } = {}) {
    return validateAssuranceStageState({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId,
        sourceNamespace,
        current: "acquired",
        history: ["acquired"],
    });
}

export function isAdjacentAssuranceStageTransition(from, to) {
    const fromIndex = ASSURANCE_STAGES.indexOf(from);
    return fromIndex >= 0 && ASSURANCE_STAGES[fromIndex + 1] === to;
}

export function transitionAssuranceStageState(value, {
    auditId,
    sourceNamespace,
    from,
    to,
} = {}) {
    const current = validateAssuranceStageState(value);
    const normalizedAuditId = validateAuditId(auditId, "transition.auditId");
    const normalizedNamespace = validateSourceNamespace(
        sourceNamespace,
        "transition.sourceNamespace",
    );
    if (normalizedAuditId !== current.auditId) {
        fail("transition.auditId", "does not match the assurance stage state audit ID");
    }
    if (normalizedNamespace !== current.sourceNamespace) {
        fail(
            "transition.sourceNamespace",
            "does not match the assurance stage state source namespace",
        );
    }
    validateStage(from, "transition.from");
    validateStage(to, "transition.to");
    if (current.current !== from) {
        fail(
            "transition.from",
            `is stale; expected ${from}, current is ${current.current}`,
        );
    }
    if (to === from) return current;
    if (!isAdjacentAssuranceStageTransition(from, to)) {
        fail("transition.to", `illegal assurance stage transition: ${from} -> ${to}`);
    }
    return validateAssuranceStageState({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        current: to,
        history: [...current.history, to],
    });
}
