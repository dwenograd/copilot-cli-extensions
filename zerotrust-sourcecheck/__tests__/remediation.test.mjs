// __tests__/remediation.test.mjs — Section 9b (defang/delete/keep)
// wording tests. The same Section 9b block is rendered into:
//   - local-source packets (audit_local_source[_council])
//   - build-mode packets (audit_and_*_build*)
// It is NOT rendered into:
//   - API-direct audit packets (audit_source[_council])
//   - verify_release
//   - metadata_only
//
// These tests pin the wording so a change to the safety invariants
// can't silently slip through.

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import nodePath from "node:path";
import { tmpdir } from "node:os";

import { runHandler } from "../handler.mjs";

let tmpRoot;
let validDir;

before(() => {
    tmpRoot = mkdtempSync(nodePath.join(tmpdir(), "zerotrust-remed-"));
    validDir = nodePath.join(tmpRoot, "sample-project-fixture");
    mkdirSync(validDir);
});

after(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
});

// ---- Modes that MUST contain Section 9b ----

describe("Section 9b present in local-source modes", () => {
    test("audit_local_source contains remediation block", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source",
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /Section 9b — Remediation/);
    });

    test("audit_local_source_council contains remediation block", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source_council",
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /Section 9b — Remediation/);
    });
});

describe("Section 9b present in build modes (existing modes gain the new block)", () => {
    test("audit_and_safe_build contains remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_and_safe_build",
            i_understand_build_executes_code: true,
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /Section 9b — Remediation/);
    });

    test("audit_and_full_build contains remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_and_full_build",
            i_understand_build_executes_code: true,
            unsafe: true,
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /Section 9b — Remediation/);
    });

    test("audit_and_safe_build_council contains remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_and_safe_build_council",
            i_understand_build_executes_code: true,
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /Section 9b — Remediation/);
    });

    test("audit_and_full_build_council contains remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_and_full_build_council",
            i_understand_build_executes_code: true,
            unsafe: true,
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /Section 9b — Remediation/);
    });
});

// ---- Modes that MUST NOT contain Section 9b ----

describe("Section 9b absent from API-direct + metadata + release modes", () => {
    test("audit_source (API-direct) does NOT contain remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_source",
        });
        assert.equal(r.resultType, "success");
        assert.doesNotMatch(r.textResultForLlm, /Section 9b — Remediation/);
    });

    test("audit_source_council (API-direct) does NOT contain remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_source_council",
        });
        assert.equal(r.resultType, "success");
        assert.doesNotMatch(r.textResultForLlm, /Section 9b — Remediation/);
    });

    test("verify_release does NOT contain remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar/releases",
            mode: "verify_release",
        });
        assert.equal(r.resultType, "success");
        assert.doesNotMatch(r.textResultForLlm, /Section 9b — Remediation/);
    });

    test("metadata_only does NOT contain remediation block", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "metadata_only",
        });
        assert.equal(r.resultType, "success");
        assert.doesNotMatch(r.textResultForLlm, /Section 9b — Remediation/);
    });
});

// ---- Verbatim safety-invariant presence ----

describe("Section 9b — load-bearing safety invariants present verbatim", () => {
    function findRemediationBlock(invocation) {
        const r = runHandler(invocation);
        assert.equal(r.resultType, "success");
        return r.textResultForLlm;
    }

    const localInvocation = {
        local_path: validDir,
        i_understand_local_path_reads_my_disk: true,
        mode: "audit_local_source_council",
    };

    const buildInvocation = {
        url: "https://github.com/foo/bar",
        mode: "audit_and_safe_build_council",
        i_understand_build_executes_code: true,
    };

    for (const [label, invocation] of [["local", localInvocation], ["build", buildInvocation]]) {
        test(`(${label}) contains "defang" + "delete project" + "keep as-is"`, () => {
            const out = findRemediationBlock(invocation);
            assert.match(out, /\*\*defang\*\*/);
            assert.match(out, /\*\*delete project\*\*/);
            assert.match(out, /\*\*keep as-is\*\*/);
        });

        test(`(${label}) contains "NEVER auto-apply" invariant`, () => {
            const out = findRemediationBlock(invocation);
            assert.match(out, /NEVER auto-apply/);
        });

        test(`(${label}) contains "NEVER batch" invariant`, () => {
            const out = findRemediationBlock(invocation);
            assert.match(out, /NEVER batch/);
        });

        test(`(${label}) contains backup-file naming pattern`, () => {
            const out = findRemediationBlock(invocation);
            assert.match(out, /\.zerotrust-backup-/);
        });

        test(`(${label}) contains mandatory rationale for "keep"`, () => {
            const out = findRemediationBlock(invocation);
            // The packet wraps "Refuse 'keep' without a written\n  rationale"
            // across a line break; allow whitespace between "written" and "rationale".
            assert.match(out, /Refuse "keep" without a written\s+rationale/);
        });

        test(`(${label}) contains re-audit recommendation`, () => {
            const out = findRemediationBlock(invocation);
            assert.match(out, /re-run.*sourcecheck.*invocation/i);
        });

        test(`(${label}) contains path-pinning instruction`, () => {
            const out = findRemediationBlock(invocation);
            // The block says "the pinned path for this audit is **exactly** ..."
            assert.match(out, /pinned path for this audit is \*\*exactly\*\*/);
        });
    }
});

// ---- Pinned-path identity ----

describe("Section 9b pinned-path identity", () => {
    test("local mode pins to localPath", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source_council",
        });
        assert.equal(r.resultType, "success");
        const resolved = nodePath.resolve(validDir);
        assert.ok(
            r.textResultForLlm.includes(`pinned path for this audit is **exactly** \`${resolved}\``),
            "local Section 9b should pin to resolved localPath",
        );
    });

    test("build mode pins to expectedClonePath (not the local fixture path)", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_and_safe_build_council",
            i_understand_build_executes_code: true,
        });
        assert.equal(r.resultType, "success");
        // The pinned path for build modes is the expectedClonePath under build_root.
        // We don't know the exact placeholder-SHA path string without parsing,
        // but it must contain the build_root and the owner-repo prefix.
        assert.match(r.textResultForLlm, /pinned path for this audit is \*\*exactly\*\* `[^`]*foo-bar[^`]*`/);
    });
});
