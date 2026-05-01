import { Buffer } from "node:buffer";
import { z } from "zod";
import {
    DEFAULT_DEBATERS,
    CHEAP_DEBATERS,
    DEFAULT_JUDGE,
    CHEAP_JUDGE,
    DEFAULT_TRIPLE_DUCK_JUDGE,
    CHEAP_TRIPLE_DUCK_JUDGE,
    DEFAULT_TRIPLE_PLAN_JUDGE,
    CHEAP_TRIPLE_PLAN_JUDGE,
    COUNCIL_ROLE_NAMES,
    DEFAULT_COUNCIL_ROLES,
    CHEAP_COUNCIL_ROLES,
    DEFAULT_COUNCIL_JUDGE,
    CHEAP_COUNCIL_JUDGE,
} from "./models.mjs";

// Credential-storage path patterns. These are the SAME high-confidence path
// patterns enforced by `_shared/policy.mjs` HARD_BLOCK_PATTERNS on free-text
// fields like `topic` / `context` / `focus`. Mirrored here (rather than
// imported) because schema validation runs before policy wrapping; we want
// `paths:`/`files:` scope entries blocked at parse time so the failure
// message is structurally part of the schema error rather than emerging
// later from the policy layer. Keep the two lists in sync if either changes.
const CREDENTIAL_PATH_PATTERNS = [
    { label: "~/.ssh", pattern: /~[/\\]\.ssh/i },
    { label: ".ssh/", pattern: /\.ssh[/\\]/i },
    { label: "id_rsa", pattern: /id_rsa/i },
    { label: "id_ed25519", pattern: /id_ed25519/i },
    { label: "id_ecdsa", pattern: /id_ecdsa/i },
    { label: "id_dsa", pattern: /id_dsa/i },
    { label: "~/.aws/credentials", pattern: /~[/\\]\.aws[/\\]credentials/i },
    { label: "~/.aws/config", pattern: /~[/\\]\.aws[/\\]config/i },
    { label: ".aws/credentials", pattern: /\.aws[/\\]credentials/i },
    { label: ".aws/config", pattern: /\.aws[/\\]config/i },
    { label: ".npmrc", pattern: /\.npmrc/i },
    { label: "kubeconfig", pattern: /kubeconfig/i },
];

function pathLooksLikeCredentialStore(path) {
    return CREDENTIAL_PATH_PATTERNS.find(({ pattern }) => pattern.test(path));
}

const FREE_TEXT_CAP = 65536;
const SEVERITIES = ["critical", "high", "medium", "low", "nit"];

const trimString = () => z.string().transform((s) => s.trim());
const severityThresholdSchema = trimString().pipe(z.enum(SEVERITIES));

const freeText = (fieldName) => z.string()
    .max(FREE_TEXT_CAP, { message: `${fieldName} exceeds 64KB cap` })
    .superRefine((value, ctx) => {
        if (Buffer.byteLength(value, "utf8") > FREE_TEXT_CAP) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: `${fieldName} exceeds 64KB cap`,
            });
        }
    })
    .transform((s) => s.trim());

const requiredFreeText = (fieldName) => freeText(fieldName)
    .refine((s) => s.length > 0, {
        message: `${fieldName} is required and must be a non-empty string`,
    });

const nonEmptyTrimmedString = (fieldName) => trimString()
    .refine((s) => s.length > 0, {
        message: `${fieldName} must be a non-empty string`,
    });

// Model ID grammar: alphanumeric plus dot, underscore, hyphen. Catches every
// real model ID in MODEL_FALLBACK_MAP (e.g. claude-opus-4.7-xhigh,
// gpt-5.5, claude-sonnet-4.6) and rejects anything containing whitespace,
// markdown, control chars, or anything that could be used to inject packet
// instructions when the value is later rendered into the protocol markdown.
// 80-char cap is well above any real model ID; rejects absurd inputs early.
const MODEL_ID_RE = /^[A-Za-z0-9._\-]+$/;
const MODEL_ID_MAX_LEN = 80;

const safeModelId = (fieldName) => trimString()
    .refine((s) => s.length > 0, {
        message: `${fieldName} must be a non-empty string`,
    })
    .refine((s) => s.length <= MODEL_ID_MAX_LEN, {
        message: `${fieldName} model ID too long (max ${MODEL_ID_MAX_LEN} chars)`,
    })
    .refine((s) => MODEL_ID_RE.test(s), {
        message: `${fieldName} model ID contains disallowed characters (allowed: alphanumeric, '.', '_', '-')`,
    });

const distinctSafeModelArray = (fieldName, length) => z.array(safeModelId(fieldName))
    .length(length, { message: `${fieldName} must be an array of exactly ${length} model IDs` })
    .superRefine((values, ctx) => {
        if (new Set(values).size !== values.length) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: `${fieldName} must contain ${length} distinct model IDs`,
            });
        }
    });

const trioModels = distinctSafeModelArray("models", 3);
const debateModels = distinctSafeModelArray("debaters", 2);

// Branch / commit grammar:
// - reject leading `-` (would interpolate as a git flag — `git diff --output=...`)
// - reject `..` segments (range expressions in git refspecs / path traversal in files)
// - branch: standard git ref characters only
// - commit: same as branch plus `~`/`^` for symbolic refs (HEAD~1, HEAD^^),
//   but the literal SHA case stays valid because hex is a subset.
const branchNameRe = /^(?!-)[A-Za-z0-9._/\-]+$/;
const commitRefRe = /^(?!-)[A-Za-z0-9._/\-~^]+$/;
const filePathRe = /^[^;|&`$<>\r\n]+$/;
const literalScopes = new Set(["staged", "unstaged", "all-uncommitted"]);

function hasParentSegment(path) {
    return path.split(/[\\/]+/).some((segment) => segment === "..");
}

function hasRangeOperator(ref) {
    return ref.includes("..");
}

function validateScope(scope) {
    if (literalScopes.has(scope)) {
        return true;
    }

    if (scope.startsWith("branch:")) {
        const branch = scope.slice("branch:".length);
        return branch.length > 0
            && branchNameRe.test(branch)
            && !hasRangeOperator(branch);
    }

    if (scope.startsWith("commit:")) {
        const ref = scope.slice("commit:".length);
        return ref.length > 0
            && commitRefRe.test(ref)
            && !hasRangeOperator(ref);
    }

    if (scope.startsWith("files:") || scope.startsWith("paths:")) {
        // `files:<list>` and `paths:<list>` use the same path validation.
        // Difference is in handler/packet behavior: `files:` produces a git
        // diff against HEAD; `paths:` produces NO diff and reviewers `view`
        // the files directly (used when there's no useful baseline OR to
        // sidestep the sub-agent-spawned-shell hang pattern).
        //
        // Credential-store paths are blocked HERE (in addition to the
        // free-text policy layer) because reviewers will `view` the file
        // contents directly and ship them to 3 third-party model providers
        // — exfiltration. The block is on the path string, not the file
        // contents, so the rejection happens at parse time.
        const prefix = scope.startsWith("files:") ? "files:" : "paths:";
        const rawList = scope.slice(prefix.length);
        if (!rawList.trim()) {
            return false;
        }
        return rawList.split(",").every((rawPath) => {
            const path = rawPath.trim();
            return path.length > 0
                && filePathRe.test(path)
                && !hasParentSegment(path)
                && !pathLooksLikeCredentialStore(path);
        });
    }

    return false;
}

const scopeSchema = trimString().superRefine((scope, ctx) => {
    if (!validateScope(scope)) {
        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "scope must be one of staged, unstaged, all-uncommitted, branch:<name>, commit:<sha>, files:<comma-list>, or paths:<comma-list> with safe values",
        });
    }
});

const cheapWithoutOverrides = (overrideFields) => (value) => {
    if (value.cheap !== true) {
        return true;
    }
    return overrideFields.every((field) => value[field] === undefined);
};

const cheapOverrideMessage = (tool, fields) => `${tool}: cheap is mutually exclusive with explicit ${fields.join(" or ")} overrides`;

export const tripleDuckSchema = z.object({
    topic: requiredFreeText("topic"),
    context: freeText("context").optional(),
    models: trioModels.optional(),
    focus: freeText("focus").optional(),
    judge: safeModelId("judge").optional(),
    cheap: z.boolean().optional(),
    max_premium_calls: z.number().int().min(1).optional(),
}).refine(cheapWithoutOverrides(["models"]), {
    // NOTE: judge is intentionally NOT in the override list — `cheap: true`
    // + `judge: "claude-opus-4.7-xhigh"` is a sensible config (cheap reviewer
    // trio, premium judge) and we want to allow it.
    message: cheapOverrideMessage("triple-duck", ["models"]),
}).transform((value) => {
    const usingCheap = value.cheap === true;
    const effectiveJudge = value.judge
        ?? (usingCheap ? CHEAP_TRIPLE_DUCK_JUDGE : DEFAULT_TRIPLE_DUCK_JUDGE);
    return { ...value, effectiveJudge };
});

export const triplePlanSchema = z.object({
    task: requiredFreeText("task"),
    context: freeText("context").optional(),
    constraints: freeText("constraints").optional(),
    models: trioModels.optional(),
    judge: safeModelId("judge").optional(),
    cheap: z.boolean().optional(),
    max_premium_calls: z.number().int().min(1).optional(),
}).refine(cheapWithoutOverrides(["models"]), {
    // See note in tripleDuckSchema — cheap + explicit judge is allowed.
    message: cheapOverrideMessage("triple-plan", ["models"]),
}).transform((value) => {
    const usingCheap = value.cheap === true;
    const effectiveJudge = value.judge
        ?? (usingCheap ? CHEAP_TRIPLE_PLAN_JUDGE : DEFAULT_TRIPLE_PLAN_JUDGE);
    return { ...value, effectiveJudge };
});

export const tripleReviewSchema = z.object({
    scope: scopeSchema.optional(),
    models: trioModels.optional(),
    focus: freeText("focus").optional(),
    max_rounds: z.number().int().min(1).max(10).default(3),
    severity_threshold: severityThresholdSchema.default("high"),
    cheap: z.boolean().optional(),
    max_premium_calls: z.number().int().min(1).optional(),
}).refine(cheapWithoutOverrides(["models"]), {
    message: cheapOverrideMessage("triple-review", ["models"]),
});

export const debateSchema = z.object({
    question: requiredFreeText("question"),
    position_a: freeText("position_a").optional(),
    position_b: freeText("position_b").optional(),
    context: freeText("context").optional(),
    rounds: z.number().int().min(1).max(4).default(1),
    debaters: debateModels.optional(),
    judge: safeModelId("judge").optional(),
    cheap: z.boolean().optional(),
    max_premium_calls: z.number().int().min(1).optional(),
})
    .refine(cheapWithoutOverrides(["debaters", "judge"]), {
        message: cheapOverrideMessage("debate", ["debaters", "judge"]),
    })
    .refine((value) => {
        const hasA = !!value.position_a;
        const hasB = !!value.position_b;
        return hasA === hasB;
    }, {
        message: "position_a and position_b must be supplied together (both or neither)",
    })
    .transform((value) => {
        const usingCheap = value.cheap === true;
        const effectiveDebaters = value.debaters
            ?? (usingCheap ? CHEAP_DEBATERS : DEFAULT_DEBATERS);
        const effectiveJudge = value.judge
            ?? (usingCheap ? CHEAP_JUDGE : DEFAULT_JUDGE);

        return {
            ...value,
            effectiveDebaters,
            effectiveJudge,
        };
    })
    .refine((value) => {
        if (!Array.isArray(value.effectiveDebaters) || typeof value.effectiveJudge !== "string") {
            return true;
        }
        return !value.effectiveDebaters.includes(value.effectiveJudge);
    }, {
        message: "judge must differ from both debaters to remain independent",
    });


// duck-council schema: 6 role-specialized reviewers + 1 judge.
// Roles override is an OBJECT (not positional array) — self-documenting and
// avoids silent role-swap errors that a 6-element array would invite.
const councilRoleObjectSchema = z.object(
    Object.fromEntries(
        COUNCIL_ROLE_NAMES.map((role) => [role, safeModelId(`roles.${role}`).optional()]),
    ),
).strict();

export const duckCouncilSchema = z.object({
    topic: requiredFreeText("topic"),
    context: freeText("context").optional(),
    focus: freeText("focus").optional(),
    roles: councilRoleObjectSchema.optional(),
    judge: safeModelId("judge").optional(),
    skip_judge: z.boolean().optional(),
    cheap: z.boolean().optional(),
    max_premium_calls: z.number().int().min(1).optional(),
})
    .refine((value) => {
        if (value.cheap !== true) return true;
        // Treat an empty/all-undefined roles object as "no override" so it
        // doesn't trip the mutual-exclusion gate. Only roles with at least
        // one defined value conflict with cheap mode.
        if (value.roles === undefined) return true;
        return Object.values(value.roles).every((v) => v === undefined);
    }, {
        // Same pattern as triple-duck/triple-plan: cheap + explicit judge IS
        // allowed (cheap reviewer trio + premium judge is sensible). Only
        // `roles` overrides conflict with cheap mode.
        message: cheapOverrideMessage("duck-council", ["roles"]),
    })
    .transform((value) => {
        const usingCheap = value.cheap === true;
        const baseAssignment = usingCheap ? CHEAP_COUNCIL_ROLES : DEFAULT_COUNCIL_ROLES;
        // Normalize empty/all-undefined roles object to undefined so the
        // handler's `isUserOverride` check and the packet's cheap-mode banner
        // both behave correctly when the caller passes `roles: {}`.
        const hasAnyRoleOverride = value.roles !== undefined
            && Object.values(value.roles).some((v) => v !== undefined);
        const normalizedRoles = hasAnyRoleOverride ? value.roles : undefined;
        // Merge user-provided roles over defaults (per-role partial override).
        const effectiveRoles = { ...baseAssignment };
        if (normalizedRoles) {
            for (const role of COUNCIL_ROLE_NAMES) {
                if (normalizedRoles[role] !== undefined) {
                    effectiveRoles[role] = normalizedRoles[role];
                }
            }
        }
        const effectiveJudge = value.judge
            ?? (usingCheap ? CHEAP_COUNCIL_JUDGE : DEFAULT_COUNCIL_JUDGE);
        return { ...value, roles: normalizedRoles, effectiveRoles, effectiveJudge };
    });
