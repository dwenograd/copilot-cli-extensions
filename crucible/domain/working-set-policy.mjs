import {
    CONTRACT_LIMITS,
} from "./constants.mjs";
import {
    immutableCanonical,
} from "./canonical.mjs";
import {
    ContractError,
} from "./errors.mjs";

export const WORKING_SET_POLICY_VERSION = 1;
export const DIAGNOSTIC_RETENTION_MODES = Object.freeze([
    "defer",
    "sealed_rollup",
]);

const POLICY_KEYS = Object.freeze([
    "diagnosticRetention",
    "maintenanceIntervalMs",
    "orphanGraceMs",
    "perAttemptBytes",
    "perInvestigationBytes",
    "segmentByteThreshold",
    "segmentEventThreshold",
    "terminalReserveBytes",
    "version",
    "walCheckpointBytes",
    "walCheckpointIntervalMs",
    "warningBasisPoints",
]);
const DIAGNOSTIC_RETENTION_KEYS = Object.freeze([
    "bundleRequiredContentTypes",
    "maxOriginalAgeMs",
    "maxOriginalBytes",
    "mode",
    "nonAuthoritativeContentTypes",
]);
const CONTENT_TYPE_RE =
    /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/u;

function exactKeys(value, expected, field) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new ContractError(`${field} must be an object`, { field });
    }
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
        throw new ContractError(`${field} has unexpected or missing keys`, {
            field,
            actual,
            expected: wanted,
        });
    }
}

function integer(value, field, {
    minimum = 0,
    maximum = Number.MAX_SAFE_INTEGER,
} = {}) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new ContractError(
            `${field} must be a safe integer from ${minimum} through ${maximum}`,
            { field, value, minimum, maximum },
        );
    }
    return value;
}

function contentTypes(value, field) {
    if (!Array.isArray(value) || value.length > 64) {
        throw new ContractError(`${field} must be an array of at most 64 content types`, {
            field,
        });
    }
    const normalized = value.map((item, index) => {
        if (typeof item !== "string"
            || item.length > 255
            || !CONTENT_TYPE_RE.test(item)) {
            throw new ContractError(`${field}[${index}] is not a bounded content type`, {
                field,
                index,
            });
        }
        return item.toLowerCase();
    });
    if (new Set(normalized).size !== normalized.length) {
        throw new ContractError(`${field} must not contain duplicates`, { field });
    }
    return normalized.sort();
}

function normalizeDiagnosticRetention(value) {
    exactKeys(
        value,
        DIAGNOSTIC_RETENTION_KEYS,
        "workingSetPolicy.diagnosticRetention",
    );
    if (!DIAGNOSTIC_RETENTION_MODES.includes(value.mode)) {
        throw new ContractError(
            "workingSetPolicy.diagnosticRetention.mode is unsupported",
            { mode: value.mode },
        );
    }
    const nonAuthoritativeContentTypes = contentTypes(
        value.nonAuthoritativeContentTypes,
        "workingSetPolicy.diagnosticRetention.nonAuthoritativeContentTypes",
    );
    const bundleRequiredContentTypes = contentTypes(
        value.bundleRequiredContentTypes,
        "workingSetPolicy.diagnosticRetention.bundleRequiredContentTypes",
    );
    const overlap = nonAuthoritativeContentTypes.filter((item) =>
        bundleRequiredContentTypes.includes(item));
    if (overlap.length > 0) {
        throw new ContractError(
            "diagnostic retention cannot classify one content type as both deletable and bundle-required",
            { overlap },
        );
    }
    if (value.mode === "sealed_rollup"
        && nonAuthoritativeContentTypes.length === 0) {
        throw new ContractError(
            "sealed_rollup requires an explicit non-authoritative content-type allowlist",
        );
    }
    return {
        mode: value.mode,
        maxOriginalAgeMs: integer(
            value.maxOriginalAgeMs,
            "workingSetPolicy.diagnosticRetention.maxOriginalAgeMs",
            { maximum: 365 * 24 * 60 * 60 * 1000 },
        ),
        maxOriginalBytes: integer(
            value.maxOriginalBytes,
            "workingSetPolicy.diagnosticRetention.maxOriginalBytes",
            { maximum: CONTRACT_LIMITS.maxResourceBytes },
        ),
        nonAuthoritativeContentTypes,
        bundleRequiredContentTypes,
    };
}

export const DEFAULT_WORKING_SET_POLICY = immutableCanonical({
    version: WORKING_SET_POLICY_VERSION,
    perAttemptBytes: 4 * 1024 * 1024,
    perInvestigationBytes: 4 * 1024 * 1024 * 1024,
    warningBasisPoints: 9_000,
    terminalReserveBytes: 2 * 1024 * 1024,
    walCheckpointBytes: 16 * 1024 * 1024,
    walCheckpointIntervalMs: 60_000,
    segmentEventThreshold: 50_000,
    segmentByteThreshold: 256 * 1024 * 1024,
    maintenanceIntervalMs: 30_000,
    orphanGraceMs: 24 * 60 * 60 * 1000,
    diagnosticRetention: {
        mode: "defer",
        maxOriginalAgeMs: 0,
        maxOriginalBytes: 0,
        nonAuthoritativeContentTypes: [],
        bundleRequiredContentTypes: [],
    },
});

export function normalizeWorkingSetPolicy(input) {
    exactKeys(input, POLICY_KEYS, "workingSetPolicy");
    if (input.version !== WORKING_SET_POLICY_VERSION) {
        throw new ContractError(
            `workingSetPolicy.version must be ${WORKING_SET_POLICY_VERSION}`,
            { version: input.version },
        );
    }
    const perAttemptBytes = integer(
        input.perAttemptBytes,
        "workingSetPolicy.perAttemptBytes",
        { minimum: 1, maximum: CONTRACT_LIMITS.maxResourceBytes },
    );
    const perInvestigationBytes = integer(
        input.perInvestigationBytes,
        "workingSetPolicy.perInvestigationBytes",
        { minimum: 1, maximum: CONTRACT_LIMITS.maxResourceBytes },
    );
    const terminalReserveBytes = integer(
        input.terminalReserveBytes,
        "workingSetPolicy.terminalReserveBytes",
        { minimum: 1, maximum: CONTRACT_LIMITS.maxResourceBytes },
    );
    if (terminalReserveBytes >= perInvestigationBytes
        || perAttemptBytes > perInvestigationBytes - terminalReserveBytes) {
        throw new ContractError(
            "workingSetPolicy must leave enough reserved storage for terminal/non-result closure",
            {
                perAttemptBytes,
                perInvestigationBytes,
                terminalReserveBytes,
            },
        );
    }
    const warningBasisPoints = integer(
        input.warningBasisPoints,
        "workingSetPolicy.warningBasisPoints",
        { minimum: 1, maximum: 9_999 },
    );
    const walCheckpointBytes = integer(
        input.walCheckpointBytes,
        "workingSetPolicy.walCheckpointBytes",
        { minimum: 1, maximum: perInvestigationBytes },
    );
    const segmentByteThreshold = integer(
        input.segmentByteThreshold,
        "workingSetPolicy.segmentByteThreshold",
        { minimum: 1, maximum: perInvestigationBytes },
    );
    return immutableCanonical({
        version: WORKING_SET_POLICY_VERSION,
        perAttemptBytes,
        perInvestigationBytes,
        warningBasisPoints,
        terminalReserveBytes,
        walCheckpointBytes,
        walCheckpointIntervalMs: integer(
            input.walCheckpointIntervalMs,
            "workingSetPolicy.walCheckpointIntervalMs",
            { minimum: 1, maximum: 24 * 60 * 60 * 1000 },
        ),
        segmentEventThreshold: integer(
            input.segmentEventThreshold,
            "workingSetPolicy.segmentEventThreshold",
            { minimum: 1, maximum: 10_000_000 },
        ),
        segmentByteThreshold,
        maintenanceIntervalMs: integer(
            input.maintenanceIntervalMs,
            "workingSetPolicy.maintenanceIntervalMs",
            { minimum: 1, maximum: 24 * 60 * 60 * 1000 },
        ),
        orphanGraceMs: integer(
            input.orphanGraceMs,
            "workingSetPolicy.orphanGraceMs",
            { maximum: 365 * 24 * 60 * 60 * 1000 },
        ),
        diagnosticRetention: normalizeDiagnosticRetention(
            input.diagnosticRetention,
        ),
    });
}

export function diagnosticOriginalDeletionAllowed(policy, {
    contentType,
    authoritative,
    bundleRequired,
    sealedSummary,
} = {}) {
    const normalized = normalizeWorkingSetPolicy(policy);
    const normalizedContentType =
        typeof contentType === "string" ? contentType.toLowerCase() : null;
    return normalized.diagnosticRetention.mode === "sealed_rollup"
        && authoritative === false
        && bundleRequired === false
        && sealedSummary === true
        && normalizedContentType !== null
        && normalized.diagnosticRetention.nonAuthoritativeContentTypes
            .includes(normalizedContentType)
        && !normalized.diagnosticRetention.bundleRequiredContentTypes
            .includes(normalizedContentType);
}
