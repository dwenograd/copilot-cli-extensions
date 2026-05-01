// _shared/scrub.mjs

const SCRUBBERS = [
    {
        type: "aws-access-key",
        // Matches both long-lived AKIA and STS-session ASIA keys.
        pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
        replacement: "[REDACTED-AWS-KEY]",
    },
    {
        type: "github-token",
        // All current GitHub token prefixes: PAT (ghp_), OAuth (gho_),
        // user-server (ghu_), server-server (ghs_), refresh (ghr_).
        pattern: /gh[opsur]_[A-Za-z0-9]{36}/g,
        replacement: "[REDACTED-GH-TOKEN]",
    },
    {
        type: "github-pat-fine",
        pattern: /github_pat_[A-Za-z0-9_]{82}/g,
        replacement: "[REDACTED-GH-TOKEN]",
    },
    {
        type: "private-key",
        // Matches PKCS#1 (RSA), SEC1 (EC), OpenSSH, DSA, plain PKCS#8
        // (`BEGIN PRIVATE KEY`), `BEGIN ENCRYPTED PRIVATE KEY`, AND
        // PGP-armored private keys (`BEGIN PGP PRIVATE KEY BLOCK`).
        // Both `PRIVATE KEY` and `PRIVATE KEY BLOCK` end markers handled.
        pattern: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
        replacement: "[REDACTED-PRIVATE-KEY]",
    },
    {
        type: "bearer-token",
        // Capture the field-name and the separator (with whatever quoting
        // and whitespace the user wrote) so the function-replacement can
        // restore them — the prior fixed-string replacement turned
        // `"Authorization": "Bearer abc"` into `"Authorization: Bearer
        // [REDACTED-BEARER]"` (mismatched quote, invalid JSON).
        // Case-insensitive: HTTP header names + auth schemes are case-insensitive.
        pattern: /(authorization)(["']?\s*:\s*["']?\s*)bearer\s+[A-Za-z0-9._~+/=\-]+/gi,
        replacement: (_match, name, sep) => `${name}${sep}Bearer [REDACTED-BEARER]`,
    },
    {
        type: "db-conn",
        // Exclude common structural delimiters (quotes, commas, brackets,
        // semicolons, backticks) from the password class. Without these,
        // JSON/CSV inputs like `["postgres://...","mysql://..."]` greedily
        // span across the second URL and lose data, even though pass-4's
        // `[^\s]+` stopped whitespace-separated cases.
        pattern: /(postgres|postgresql|mongodb|mysql):\/\/[^:\s"'`,;\]\}<>]+:[^\s"'`,;\]\}<>]+@([^\s@"'`,;\]\}<>]+)/g,
        replacement: (_match, scheme, host) => `${scheme}://[REDACTED-DB-CRED]@${host}`,
    },
];

// Explicitly not scrubbed: email addresses, generic JWT-shaped strings (`eyJ…`),
// generic `api_key=…` patterns, and generic `password=…` patterns. These were
// rejected in the plan because false positives would erode trust.
export function scrub(text) {
    let scrubbed = String(text ?? "");
    const redactions = [];

    for (const { type, pattern, replacement } of SCRUBBERS) {
        let count = 0;
        scrubbed = scrubbed.replace(pattern, (...args) => {
            count += 1;
            return typeof replacement === "function" ? replacement(...args) : replacement;
        });

        if (count > 0) {
            redactions.push({ type, count });
        }
    }

    return { text: scrubbed, redactions };
}
