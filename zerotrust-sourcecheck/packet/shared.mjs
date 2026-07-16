// Shared pure helpers for packet renderers.

const FINDING_SEVERITIES = Object.freeze([
    "critical",
    "high",
    "medium",
    "low",
    "info",
]);
const REQUIRED_FINDING_FIELDS = Object.freeze([
    "severity",
    "confidence",
    "exploit_prerequisites",
    "benign_context_explanation",
    "verification_step",
]);
const DYNAMIC_EVALUATION_RE = /\b(?:eval|Function|exec|compile|Invoke-Expression|vm\.runInNewContext)\s*\(/iu;
const REMOTE_FETCH_RE = /\b(?:curl|wget|Invoke-WebRequest|iwr|fetch|requests?\.get|urllib\.request|Net\.WebClient)\b/iu;
const DECODER_RE = /\b(?:atob|base64|fromBase64|Buffer\.from|Convert\.FromBase64String|decode)\b/iu;
const COMMAND_EXECUTION_RE = /\b(?:powershell|pwsh|cmd(?:\.exe)?|sh|bash|zsh|node|python|ruby|perl|Start-Process|child_process|subprocess|os\.system)\b/iu;
const EXTENDED_PICTOGRAPHIC_RE = /\p{Extended_Pictographic}/u;

/**
 * Deterministic verdict mapping. Finding counts and cross-validation counts
 * never average down a credible singleton: the highest credible severity wins.
 * Coverage incompleteness takes precedence over every trusted verdict.
 */
export function mapOverallVerdict(findings, {
    mandatoryAcquisitionComplete = true,
    councilCoverageComplete = true,
} = {}) {
    if (mandatoryAcquisitionComplete !== true || councilCoverageComplete !== true) {
        return "incomplete";
    }
    let highestIndex = FINDING_SEVERITIES.length;
    for (const finding of Array.isArray(findings) ? findings: []) {
        if (!finding || finding.credible === false || finding.dismissed === true) continue;
        const severity = String(finding.severity || "").toLowerCase();
        const index = FINDING_SEVERITIES.indexOf(severity);
        if (index >= 0 && index < highestIndex) highestIndex = index;
    }
    if (highestIndex === 0) return "critical";
    if (highestIndex === 1) return "high";
    if (highestIndex === 2) return "medium";
    if (highestIndex === 3 || highestIndex === 4) return "low";
    return "no red flags found";
}

export function validateFindingContract(finding, { councilDerived = false } = {}) {
    const missingFields = REQUIRED_FINDING_FIELDS.filter((field) => {
        const value = finding?.[field];
        return typeof value !== "string" || value.trim().length === 0;
    });
    if (!FINDING_SEVERITIES.includes(String(finding?.severity || "").toLowerCase())) {
        if (!missingFields.includes("severity")) missingFields.push("severity");
    }
    if (!["high", "medium", "low"].includes(String(finding?.confidence || "").toLowerCase())) {
        if (!missingFields.includes("confidence")) missingFields.push("confidence");
    }
    if (councilDerived
        && (!Number.isInteger(finding?.cross_validation_count)
            || finding.cross_validation_count < 1)) {
        missingFields.push("cross_validation_count");
    }
    return {
        valid: missingFields.length === 0,
        missingFields,
    };
}

/**
 * Score a repository filter declaration together with any discovered driver
 * commands. A normal Git LFS declaration is expected metadata, not a finding.
 */
export function scoreGitAttributesFilter({
    attributesLine = "",
    cleanCommand = "",
    smudgeCommand = "",
    processCommand = "",
} = {}) {
    const match = String(attributesLine).match(/(?:^|\s)filter=([^\s]+)/iu);
    if (!match) {
        return { finding: false, severity: null, classification: "no-filter" };
    }
    const filterName = match[1].toLowerCase();
    const commands = [cleanCommand, smudgeCommand, processCommand]
        .map((value) => String(value || "").trim())
        .filter(Boolean);
    const canonicalLfs = commands.every((command) =>
        /^git-lfs\s+(?:clean|smudge|filter-process)(?:\s|$)/iu.test(command));
    if (filterName === "lfs" && canonicalLfs) {
        return {
            finding: false,
            severity: null,
            classification: "standard-git-lfs",
            confidence: "high",
        };
    }

    const commandText = commands.join("\n");
    const fetches = REMOTE_FETCH_RE.test(commandText);
    const decodes = DECODER_RE.test(commandText);
    const dynamicallyEvaluates = DYNAMIC_EVALUATION_RE.test(commandText)
        || /\b(?:Invoke-Expression|iex)\b/iu.test(commandText);
    const executes = COMMAND_EXECUTION_RE.test(commandText) || dynamicallyEvaluates;
    let severity = "low";
    if (commands.length > 0) severity = "medium";
    if (fetches || executes) severity = "high";
    if ((fetches || decodes) && executes) severity = "critical";
    return {
        finding: true,
        severity,
        classification: commands.length > 0
            ? "custom-filter-with-driver": "custom-filter-declaration",
        confidence: commands.length > 0 ? "high": "medium",
    };
}

function invisibleKind(codePoint) {
    if (codePoint >= 0xE0000 && codePoint <= 0xE007F) return "tags";
    if ((codePoint >= 0xFE00 && codePoint <= 0xFE0F)
        || (codePoint >= 0xE0100 && codePoint <= 0xE01EF)) return "variation-selector";
    if ((codePoint >= 0xE000 && codePoint <= 0xF8FF)
        || (codePoint >= 0xF0000 && codePoint <= 0xFFFFD)
        || (codePoint >= 0x100000 && codePoint <= 0x10FFFD)) return "private-use";
    if (codePoint >= 0x202A && codePoint <= 0x202E) return "bidi";
    if (codePoint >= 0x2066 && codePoint <= 0x2069) return "bidi";
    if ((codePoint >= 0x200B && codePoint <= 0x200F)
        || (codePoint >= 0x2028 && codePoint <= 0x202F)
        || (codePoint >= 0x2060 && codePoint <= 0x206F)) return "control";
    if (codePoint === 0xFEFF) return "bom";
    return null;
}

function adjacentCodePoint(text, index, direction) {
    if (direction < 0) {
        const prefix = text.slice(0, index);
        const chars = Array.from(prefix);
        return chars.length > 0 ? chars.at(-1): "";
    }
    const codePoint = text.codePointAt(index);
    const width = codePoint === undefined ? 0: String.fromCodePoint(codePoint).length;
    return Array.from(text.slice(index + width))[0] || "";
}

/**
 * Contextual invisible-Unicode scoring used by the packet's deterministic
 * rules. The byte scanner remains broad; this classifier separates expected
 * presentation characters from payload-shaped or control-flow abuse.
 */
export function scoreInvisibleUnicode(text, { filePath = "" } = {}) {
    const source = String(text || "");
    const suspicious = [];
    const counts = {};
    let currentRun = 0;
    let maxRun = 0;
    for (let index = 0; index < source.length;) {
        const codePoint = source.codePointAt(index);
        const char = String.fromCodePoint(codePoint);
        const kind = invisibleKind(codePoint);
        if (!kind) {
            currentRun = 0;
            index += char.length;
            continue;
        }
        let benign = kind === "bom" && index === 0;
        if (kind === "variation-selector") {
            const previous = adjacentCodePoint(source, index, -1);
            benign = EXTENDED_PICTOGRAPHIC_RE.test(previous);
        } else if (kind === "control" && codePoint === 0x200D) {
            const previous = adjacentCodePoint(source, index, -1);
            const next = adjacentCodePoint(source, index, 1);
            benign = EXTENDED_PICTOGRAPHIC_RE.test(previous)
                && EXTENDED_PICTOGRAPHIC_RE.test(next);
        }
        if (benign) {
            currentRun = 0;
        } else {
            suspicious.push({ index, codePoint, kind });
            counts[kind] = (counts[kind] || 0) + 1;
            currentRun += 1;
            maxRun = Math.max(maxRun, currentRun);
        }
        index += char.length;
    }

    if (suspicious.length === 0) {
        return {
            finding: false,
            severity: null,
            confidence: "high",
            suspiciousCount: 0,
            maxRun: 0,
            counts: {},
        };
    }

    const payloadShaped = maxRun >= 8 || suspicious.length >= 16;
    const dynamicEvaluation = DYNAMIC_EVALUATION_RE.test(source);
    const executionSensitivePath = /(?:^|[\\/])(?:package\.json|build\.rs|setup\.py|extension\.[cm]?[jt]s|scripts?)(?:$|[\\/])/iu.test(filePath);
    let severity = "medium";
    if (counts.tags > 0 || counts.bidi > 0) severity = "high";
    if (payloadShaped || (dynamicEvaluation && suspicious.length > 0)
        || (executionSensitivePath && counts.tags > 0)) {
        severity = "critical";
    }
    return {
        finding: true,
        severity,
        confidence: severity === "critical" ? "high": "medium",
        suspiciousCount: suspicious.length,
        maxRun,
        counts,
        payloadShaped,
        dynamicEvaluation,
    };
}

// Shared lifecycle prose used by URL and local packets.

export function renderSweepAndCloseBlock({ buildRoot }) {
    return `### Sweep scratch, then close audit state

Run the normal sandbox-only sweep with parent sweeping explicitly disabled:

\`\`\`
zerotrust_sweep_audit_scratch({
  // build_root defaults to the active audit's trusted build_root
  also_sweep_parent: false
})
\`\`\`

Parent sweeping is opt-in and may affect unrelated files. Only if
\`${buildRoot}\`'s parent is dedicated audit scratch, first inspect it:

\`\`\`
zerotrust_sweep_audit_scratch({
  also_sweep_parent: true,
  dry_run: true
})
\`\`\`

After reviewing that candidate list, an explicit parent sweep may be run with
\`also_sweep_parent: true\` and \`dry_run: false\`.

If any cleanup or sweep call fails, **do not close the audit**. Report the
error and retry while the trusted audit context is still active. After every
requested destructive cleanup step succeeds, close state:

\`\`\`
zerotrust_close_audit({})
\`\`\`

\`zerotrust_close_audit\` is non-destructive and idempotent.`;
}
