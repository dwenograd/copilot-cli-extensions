// __tests__/localMode.test.mjs — handler + packet integration tests
// for the local-source audit modes (audit_local_source[_council]).

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import nodePath from "node:path";
import { tmpdir } from "node:os";

import { runHandler } from "../handler.mjs";
import {
    safeCloneHandler,
    safeInstallHandler,
    safeBuildHandler,
    safeListTreeHandler,
    safeFetchFileHandler,
} from "../safeWrappers/index.mjs";

// ---- Fixtures ----

let tmpRoot;
let validDir;

before(() => {
    tmpRoot = mkdtempSync(nodePath.join(tmpdir(), "zerotrust-localmode-"));
    validDir = nodePath.join(tmpRoot, "sample-project");
    mkdirSync(validDir);
    writeFileSync(nodePath.join(validDir, "index.js"), "console.log('x');");
});

after(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
});

// Convenience: deterministic sessionId per test so audits don't collide.
function sessionFor(name) {
    return `localmode-test-${name}-${Math.random().toString(36).slice(2)}`;
}

// ---- Handler-level arg validation ----

describe("local_path handler — argument validation", () => {
    test("rejects when both url and local_path supplied", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            local_path: validDir,
        });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /mutually exclusive/);
    });

    test("rejects when neither url nor local_path supplied", () => {
        const r = runHandler({});
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /either `url` .* or `local_path`/);
    });

    test("rejects local_path without the ack flag", () => {
        const r = runHandler({ local_path: validDir });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /i_understand_local_path_reads_my_disk/);
    });

    test("rejects invalid local_path (non-existent)", () => {
        const r = runHandler({
            local_path: nodePath.join(tmpRoot, "does-not-exist"),
            i_understand_local_path_reads_my_disk: true,
        });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /local_path rejected/);
    });

    test("rejects URL-only mode paired with local_path", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_source",
        });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /not valid for local_path/);
    });

    test("rejects build mode paired with local_path", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_and_safe_build",
        });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /not valid for local_path/);
    });

    test("rejects URL-driven mode paired with audit_local_source (mismatched mode + url)", () => {
        const r = runHandler({
            url: "https://github.com/foo/bar",
            mode: "audit_local_source",
        });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /requires `local_path`/);
    });

    test("rejects ref override paired with local_path", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            ref: "baseline.0",
        });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /ref is not valid in local_path mode/);
    });
});

// ---- Handler-level success paths ----

describe("local_path handler — success paths", () => {
    test("succeeds with audit_local_source (non-council)", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source",
        });
        assert.equal(r.resultType, "success");
        // The local packet renders with the local mode label.
        assert.match(r.textResultForLlm, /LOCAL-SOURCE audit packet/);
        assert.match(r.textResultForLlm, /audit_local_source/);
        // Contains the resolved localPath.
        assert.ok(
            r.textResultForLlm.includes(nodePath.resolve(validDir)),
            "packet should contain resolved localPath",
        );
    });

    test("defaults to audit_local_source_council when mode omitted", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /audit_local_source_council/);
        // Council manifest is rendered (look for role IDs).
        assert.match(r.textResultForLlm, /install-build-hook/);
    });

    test("packet routes role agents to view/grep/glob, not safe_fetch_file", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source_council",
        });
        assert.equal(r.resultType, "success");
        // The local packet's role-source-access rule uses view/grep/glob.
        assert.match(r.textResultForLlm, /view.*grep.*glob/);
        // Local mode should NOT instruct safe_fetch_file or safe_list_tree.
        // (They appear in the "What you must NOT do" section as refusals,
        // which is fine — but they should NOT appear as the primary
        // source-access rule. We check that the renderRolePrompt output
        // doesn't include the API-direct ground rule text.)
        assert.doesNotMatch(
            r.textResultForLlm,
            /This audit is API-DIRECT — the repository is NOT cloned to disk/,
        );
    });

    test("packet contains the CONTAINMENT rule per role", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source_council",
        });
        assert.equal(r.resultType, "success");
        // CONTAINMENT is the load-bearing rule injected via promptTemplate.
        assert.match(r.textResultForLlm, /CONTAINMENT \(load-bearing\)/);
    });

    test("packet contains the current remediation flow", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source_council",
        });
        assert.equal(r.resultType, "success");
        assert.match(r.textResultForLlm, /Step E — Remediation decisions before finalization/);
        assert.match(r.textResultForLlm, /defang/);
        assert.match(r.textResultForLlm, /delete-project/);
        assert.match(r.textResultForLlm, /keep-as-is/);
        assert.match(r.textResultForLlm, /Never auto-apply/i);
        assert.match(r.textResultForLlm, /one finding at a time/i);
        assert.match(r.textResultForLlm, /\.zerotrust-backup-/);
    });

    test("packet finalizes the local report once through the active local identity", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source",
        });
        assert.equal(r.resultType, "success");
        assert.equal(
            (r.textResultForLlm.match(/zerotrust_finalize_report\(\{/g) || []).length,
            1,
        );
        assert.match(r.textResultForLlm, /Local reports accept no\s+owner\/repo\/SHA\/path fields/);
        assert.match(r.textResultForLlm, /finalizeResult\.reportPath/);
        assert.doesNotMatch(
            r.textResultForLlm,
            /New-Item\s+-ItemType\s+Directory[^\n]*(?:_reports|REPORT\.md)/i,
        );
    });

    test("packet pins the remediation path to the localPath, not arbitrary", () => {
        const r = runHandler({
            local_path: validDir,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source_council",
        });
        assert.equal(r.resultType, "success");
        const resolved = nodePath.resolve(validDir);
        // The remediation prose names the pinned path as the only delete target.
        assert.ok(
            r.textResultForLlm.includes(`pinned path for this audit is **exactly** \`${resolved}\``),
            "remediation must pin the delete path to the resolved localPath",
        );
    });
});

// ---- Wrapper refusal in local-source mode ----

describe("safe-wrappers refuse in local-source mode", () => {
    test("safe_clone refuses with explicit local-mode message", async () => {
        const sessionId = sessionFor("clone");
        const r = runHandler(
            {
                local_path: validDir,
                i_understand_local_path_reads_my_disk: true,
            },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        const cloneRes = await safeCloneHandler(
            { url: "https://github.com/foo/bar" },
            { sessionId },
        );
        assert.equal(cloneRes.resultType, "failure");
        assert.match(cloneRes.textResultForLlm, /local-source mode/);
    });

    test("safe_install refuses with explicit local-mode message", async () => {
        const sessionId = sessionFor("install");
        const r = runHandler(
            {
                local_path: validDir,
                i_understand_local_path_reads_my_disk: true,
            },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        const installRes = await safeInstallHandler(
            {
                ecosystem: "npm",
                clone_path: nodePath.join(
                    "C:\\test\\zerotrust-sourcecheck",
                    "irrelevant-12345",
                ),
            },
            { sessionId },
        );
        assert.equal(installRes.resultType, "failure");
        assert.match(installRes.textResultForLlm, /local-source mode/);
    });

    test("safe_build refuses with explicit local-mode message", async () => {
        const sessionId = sessionFor("build");
        const r = runHandler(
            {
                local_path: validDir,
                i_understand_local_path_reads_my_disk: true,
            },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        const buildRes = await safeBuildHandler(
            {
                ecosystem: "npm",
                clone_path: nodePath.join(
                    "C:\\test\\zerotrust-sourcecheck",
                    "irrelevant-12345",
                ),
            },
            { sessionId },
        );
        assert.equal(buildRes.resultType, "failure");
        assert.match(buildRes.textResultForLlm, /local-source mode/);
    });

    test("safe_list_tree refuses with explicit local-mode message", async () => {
        const sessionId = sessionFor("listtree");
        const r = runHandler(
            {
                local_path: validDir,
                i_understand_local_path_reads_my_disk: true,
            },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        const treeRes = await safeListTreeHandler(
            { owner: "foo", repo: "bar" },
            { sessionId },
        );
        assert.equal(treeRes.resultType, "failure");
        assert.match(treeRes.textResultForLlm, /local-source mode/);
    });

    test("safe_fetch_file refuses with explicit local-mode message", async () => {
        const sessionId = sessionFor("fetchfile");
        const r = runHandler(
            {
                local_path: validDir,
                i_understand_local_path_reads_my_disk: true,
            },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        const fetchRes = await safeFetchFileHandler(
            {
                owner: "foo",
                repo: "bar",
                sha: "a".repeat(40),
                path: "README.md",
            },
            { sessionId },
        );
        assert.equal(fetchRes.resultType, "failure");
        assert.match(fetchRes.textResultForLlm, /local-source mode/);
    });
});
