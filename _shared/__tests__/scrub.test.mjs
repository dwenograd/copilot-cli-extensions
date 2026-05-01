import { describe, expect, it } from "vitest";

import { scrub } from "../scrub.mjs";

describe("scrub", () => {
    it("scrubs AWS access keys", () => {
        const result = scrub("my key is AKIAIOSFODNN7EXAMPLE more text");

        expect(result.text).toBe("my key is [REDACTED-AWS-KEY] more text");
        expect(result.redactions).toEqual([{ type: "aws-access-key", count: 1 }]);
    });

    it("scrubs GitHub classic PATs", () => {
        const result = scrub("ghp_abcdefghijklmnopqrstuvwxyz0123456789");

        expect(result.text).toBe("[REDACTED-GH-TOKEN]");
        expect(result.redactions).toEqual([{ type: "github-token", count: 1 }]);
    });

    // Regression coverage for security-pattern widenings (passes 1, 2, 3).
    // These prevent silent re-tightening of any pattern from passing tests.
    it.each([
        ["ghs_", `ghs_${"a".repeat(36)}`],
        ["ghu_", `ghu_${"b".repeat(36)}`],
        ["ghr_", `ghr_${"c".repeat(36)}`],
        ["gho_", `gho_${"d".repeat(36)}`],
    ])("scrubs %s GitHub token prefix (regression)", (_label, token) => {
        const result = scrub(token);
        expect(result.text).toBe("[REDACTED-GH-TOKEN]");
        expect(result.redactions).toEqual([{ type: "github-token", count: 1 }]);
    });

    it("scrubs AWS STS session keys (ASIA prefix; regression)", () => {
        const result = scrub("session key ASIAIOSFODNN7EXAMPLE here");
        expect(result.text).toBe("session key [REDACTED-AWS-KEY] here");
        expect(result.redactions).toEqual([{ type: "aws-access-key", count: 1 }]);
    });

    it("scrubs PKCS#8 plain private key (no algorithm prefix; regression)", () => {
        const pem = "-----BEGIN PRIVATE KEY-----\nabcdefg\n-----END PRIVATE KEY-----";
        const result = scrub(pem);
        expect(result.text).toBe("[REDACTED-PRIVATE-KEY]");
        expect(result.redactions).toEqual([{ type: "private-key", count: 1 }]);
    });

    it("scrubs ENCRYPTED PRIVATE KEY blocks (regression)", () => {
        const pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabcdefg\n-----END ENCRYPTED PRIVATE KEY-----";
        const result = scrub(pem);
        expect(result.text).toBe("[REDACTED-PRIVATE-KEY]");
        expect(result.redactions).toEqual([{ type: "private-key", count: 1 }]);
    });

    it("scrubs PGP-armored private key blocks (BLOCK suffix; pass 3 fix)", () => {
        const pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabcdef\n-----END PGP PRIVATE KEY BLOCK-----";
        const result = scrub(pgp);
        expect(result.text).toBe("[REDACTED-PRIVATE-KEY]");
        expect(result.redactions).toEqual([{ type: "private-key", count: 1 }]);
    });

    it("scrubs bearer tokens containing tilde (regression for round-1 widening)", () => {
        const result = scrub("Authorization: Bearer abc~def.ghi");
        expect(result.text).toBe("Authorization: Bearer [REDACTED-BEARER]");
        expect(result.redactions).toEqual([{ type: "bearer-token", count: 1 }]);
    });

    it("scrubs UPPERCASE Authorization headers (case-insensitive; pass 3 fix)", () => {
        const result = scrub("AUTHORIZATION: Bearer abc123_def456");
        expect(result.text).toContain("[REDACTED-BEARER]");
        expect(result.text).not.toContain("abc123_def456");
        expect(result.redactions).toEqual([{ type: "bearer-token", count: 1 }]);
    });

    it("scrubs lowercase 'bearer' scheme variant (case-insensitive; pass 3 fix)", () => {
        const result = scrub("Authorization: bearer abc123");
        expect(result.text).toContain("[REDACTED-BEARER]");
        expect(result.redactions).toEqual([{ type: "bearer-token", count: 1 }]);
    });

    it("scrubs a multi-line PEM private key block into a single marker", () => {
        const pem = [
            "before",
            "-----BEGIN RSA PRIVATE KEY-----",
            "abc123",
            "def456",
            "-----END RSA PRIVATE KEY-----",
            "after",
        ].join("\n");

        const result = scrub(pem);

        expect(result.text).toBe("before\n[REDACTED-PRIVATE-KEY]\nafter");
        expect(result.redactions).toEqual([{ type: "private-key", count: 1 }]);
    });

    it("scrubs bearer authorization headers while preserving the header shape", () => {
        const result = scrub("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ.signed");

        expect(result.text).toBe("Authorization: Bearer [REDACTED-BEARER]");
        expect(result.redactions).toEqual([{ type: "bearer-token", count: 1 }]);
    });

    it("scrubs JSON-quoted Authorization headers and PRESERVES surrounding quotes (pass 4 fix)", () => {
        const input = '{"Authorization": "Bearer abc123_def456"}';
        const result = scrub(input);
        expect(result.text).toContain("[REDACTED-BEARER]");
        expect(result.text).not.toContain("abc123_def456");
        // Pass 4 fix: replacement now preserves the original quoting/separator
        // so JSON stays valid round-trippable.
        expect(result.text).toBe('{"Authorization": "Bearer [REDACTED-BEARER]"}');
        expect(result.redactions).toEqual([{ type: "bearer-token", count: 1 }]);
    });

    it("scrubs single-quoted Authorization headers and preserves quoting (pass 4 fix)", () => {
        const input = "'Authorization':'Bearer xyz_token_value'";
        const result = scrub(input);
        expect(result.text).toContain("[REDACTED-BEARER]");
        expect(result.text).not.toContain("xyz_token_value");
        expect(result.text).toBe("'Authorization':'Bearer [REDACTED-BEARER]'");
    });

    it("scrubs database connection credentials while preserving scheme and host", () => {
        const result = scrub("postgres://admin:secret@db.internal:5432/app");

        expect(result.text).toBe("postgres://[REDACTED-DB-CRED]@db.internal:5432/app");
        expect(result.redactions).toEqual([{ type: "db-conn", count: 1 }]);
    });

    it("scrubs DB conn with literal `@` in password (pass 3 fix)", () => {
        const result = scrub("postgres://user:p@ss@host/db");
        // The greedy-but-non-whitespace match correctly anchors the closing
        // `@` against the host, so the full password (including `@`) is
        // redacted without leaking the trailing `ss` fragment.
        expect(result.text).toBe("postgres://[REDACTED-DB-CRED]@host/db");
        expect(result.redactions).toEqual([{ type: "db-conn", count: 1 }]);
    });

    it("does NOT collapse multiple DB URLs across whitespace (pass 4 regression)", () => {
        // Pass 3's greedy `.+` would have spanned the whitespace and consumed
        // both URLs into a single redaction. Pass 4's `[^\s]+` prevents this.
        const result = scrub("postgres://u:p@h1 and mysql://v:q@h2");
        expect(result.text).toBe("postgres://[REDACTED-DB-CRED]@h1 and mysql://[REDACTED-DB-CRED]@h2");
        expect(result.redactions).toEqual([{ type: "db-conn", count: 2 }]);
    });

    it("does NOT collapse multiple DB URLs in JSON arrays (pass 5 regression)", () => {
        // Pass 4's `[^\s]+` still spanned across `,` and `"` in JSON.
        // Pass 5's expanded delimiter exclusion fixes this.
        const result = scrub(String.raw`["postgres://u:p@h1","mysql://u2:p2@h2"]`);
        expect(result.text).toBe('["postgres://[REDACTED-DB-CRED]@h1","mysql://[REDACTED-DB-CRED]@h2"]');
        expect(result.redactions).toEqual([{ type: "db-conn", count: 2 }]);
    });

    it("does NOT collapse multiple DB URLs in JSON objects (pass 5 regression)", () => {
        const result = scrub(String.raw`{"primary":"postgres://u:p@h1","secondary":"postgres://x:y@h2"}`);
        expect(result.text).toBe('{"primary":"postgres://[REDACTED-DB-CRED]@h1","secondary":"postgres://[REDACTED-DB-CRED]@h2"}');
        expect(result.redactions).toEqual([{ type: "db-conn", count: 2 }]);
    });

    it("scrubs mixed input with multiple secret types and counts each type", () => {
        const fineGrainedToken = `github_pat_${"a".repeat(82)}`;
        const oauthToken = `gho_${"b".repeat(36)}`;
        const input = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            fineGrainedToken,
            oauthToken,
            "Authorization: Bearer abc.def/ghi=+",
            "mysql://user:pass@mysql.internal/db",
        ].join(" ");

        const result = scrub(input);

        expect(result.text).toBe([
            "[REDACTED-AWS-KEY]",
            "[REDACTED-GH-TOKEN]",
            "[REDACTED-GH-TOKEN]",
            "[REDACTED-GH-TOKEN]",
            "Authorization: Bearer [REDACTED-BEARER]",
            "mysql://[REDACTED-DB-CRED]@mysql.internal/db",
        ].join(" "));
        expect(result.redactions).toEqual([
            { type: "aws-access-key", count: 1 },
            // ghp_ and gho_ both now collapse to a single `github-token` type
            // (combined regex catches all gh{p,o,s,u,r}_ prefixes).
            { type: "github-token", count: 2 },
            { type: "github-pat-fine", count: 1 },
            { type: "bearer-token", count: 1 },
            { type: "db-conn", count: 1 },
        ]);
    });

    it("does not scrub email addresses", () => {
        expect(scrub("auth-team@example.com")).toEqual({
            text: "auth-team@example.com",
            redactions: [],
        });
    });

    it("does not scrub generic JWT-shaped strings in code", () => {
        expect(scrub("const token = 'eyJabc';")).toEqual({
            text: "const token = 'eyJabc';",
            redactions: [],
        });
    });

    it("does not scrub generic api_key patterns", () => {
        expect(scrub("api_key=abc123")).toEqual({
            text: "api_key=abc123",
            redactions: [],
        });
    });

    it("does not scrub discussion of Bearer without a literal token header", () => {
        expect(scrub("using a Bearer token")).toEqual({
            text: "using a Bearer token",
            redactions: [],
        });
    });

    it("does not scrub discussion of the AKIA prefix without a literal key", () => {
        expect(scrub("discussing AKIA prefix")).toEqual({
            text: "discussing AKIA prefix",
            redactions: [],
        });
    });

    it("scrubs the AWS docs example when included in code as an intentional acceptable false positive", () => {
        const result = scrub("const example = 'AKIAIOSFODNN7EXAMPLE';");

        expect(result.text).toBe("const example = '[REDACTED-AWS-KEY]';");
        expect(result.redactions).toEqual([{ type: "aws-access-key", count: 1 }]);
    });

    it("handles empty and whitespace-only strings", () => {
        expect(scrub("")).toEqual({ text: "", redactions: [] });
        expect(scrub("   \n\t  ")).toEqual({ text: "   \n\t  ", redactions: [] });
    });

    it("does not double-scrub already-scrubbed text", () => {
        expect(scrub("[REDACTED-AWS-KEY]")).toEqual({
            text: "[REDACTED-AWS-KEY]",
            redactions: [],
        });
    });
});
