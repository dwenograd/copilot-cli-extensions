// __corpus__/runner/failureClassifier.mjs
// Maps execution failures to corpus outcomes. Keep patterns generic and sparse.

export const FAILURE_CLASSES = Object.freeze({
    RATELIMIT: "SKIPPED-RATELIMIT",
    VANISHED: "SKIPPED-VANISHED",
    AV_TRIPPED: "AV-TRIPPED",
    INCONCLUSIVE: "INCONCLUSIVE",
    PREPARE_FAILED: "FAILED-PREPARE",
    SCAN_FAILED: "FAILED-SCAN",
    TRACE_FAILED: "FAILED-TRACE",
    VALIDATE_FAILED: "FAILED-VALIDATE",
    FINALIZE_FAILED: "FAILED-FINALIZE",
    FAILED_EXECUTION: "FAILED-EXECUTION",
});

const STAGE_CLASS = Object.freeze({
    prepare: FAILURE_CLASSES.PREPARE_FAILED,
    scan: FAILURE_CLASSES.SCAN_FAILED,
    trace: FAILURE_CLASSES.TRACE_FAILED,
    validate: FAILURE_CLASSES.VALIDATE_FAILED,
    finalize: FAILURE_CLASSES.FINALIZE_FAILED,
});

function joinText(input) {
    if (input == null) return "";
    if (typeof input === "string") return input;
    if (input instanceof Error) return `${input.message || ""}\n${input.stack || ""}`;
    if (typeof input === "object") {
        return [input.message, input.stderr, input.stdout, input.error, input.reason]
            .filter(Boolean)
            .join("\n");
    }
    return String(input);
}

function councilFailureRatio(input) {
    const failures = Number(input.councilFailures ?? input.failedRoles ?? 0);
    const total = Number(input.councilTotal ?? input.totalRoles ?? 0);
    if (!Number.isFinite(failures) || !Number.isFinite(total) || total <= 0) return 0;
    return failures / total;
}

export function classifyFailure(input = {}) {
    const text = joinText(input).toLowerCase();

    if (/defender|quarantine|threat\s+detected|event\s+id\s+1116|antivirus|\bav\b/.test(text)) {
        return result(FAILURE_CLASSES.AV_TRIPPED, "local protection alert; abort corpus run", { abort: true });
    }

    if (/rate\s*limit|secondary\s+limit|too\s+many\s+requests|\bhttp\s*403\b/.test(text)) {
        return result(FAILURE_CLASSES.RATELIMIT, "GitHub rate limit or abuse guard", { skipped: true, retryable: true });
    }

    if (/\b404\b|not\s+found|repository\s+(deleted|disabled|unavailable)|\bgone\b/.test(text)) {
        return result(FAILURE_CLASSES.VANISHED, "repository no longer available", { skipped: true });
    }

    if (councilFailureRatio(input) > 0.10) {
        return result(FAILURE_CLASSES.INCONCLUSIVE, "more than ten percent of council roles failed");
    }

    if (input.parseError) {
        return result(FAILURE_CLASSES.FAILED_EXECUTION, "report parse failed");
    }

    if (input.failureStage && STAGE_CLASS[input.failureStage]) {
        return result(
            STAGE_CLASS[input.failureStage],
            input.failureReason || `${input.failureStage} stage did not complete`,
            { stage: input.failureStage },
        );
    }

    if (Number.isFinite(Number(input.exitCode)) && Number(input.exitCode) !== 0) {
        return result(FAILURE_CLASSES.FAILED_EXECUTION, `process exited ${Number(input.exitCode)}`);
    }

    if (text.trim()) {
        return result(FAILURE_CLASSES.FAILED_EXECUTION, "unclassified execution failure");
    }

    return result(null, "no failure detected");
}

export function classifyStageFailure({
    finalStage = null,
    failureStage = null,
    failureReason = null,
    blockers = [],
} = {}) {
    const inferred = failureStage
        || (finalStage === "acquired" ? "prepare": finalStage === "prepared" ? "scan": finalStage === "scanned" ? "trace": finalStage === "traced" ? "validate": finalStage === "validated" ? "finalize": null);
    if (!inferred) return result(null, "no stage failure detected");
    const blockerReason = blockers.map((blocker) =>
        typeof blocker === "string"
            ? blocker: blocker?.code || blocker?.kind).filter(Boolean).join(",");
    return result(
        STAGE_CLASS[inferred],
        failureReason || blockerReason || `${inferred} stage did not complete`,
        { stage: inferred },
    );
}

function result(classification, reason, extra = {}) {
    return {
        classification,
        reason,
        skipped: Boolean(extra.skipped),
        retryable: Boolean(extra.retryable),
        abort: Boolean(extra.abort),
        stage: extra.stage || null,
    };
}

export const __internals = {
    joinText,
    councilFailureRatio,
    STAGE_CLASS,
};
