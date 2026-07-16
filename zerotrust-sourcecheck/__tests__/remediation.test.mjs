import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import nodePath from "node:path";
import { tmpdir } from "node:os";

import { runHandler } from "../handler.mjs";

let tmpRoot;
let localPath;

before(() => {
    tmpRoot = mkdtempSync(nodePath.join(tmpdir(), "zerotrust-remed-"));
    localPath = nodePath.join(tmpRoot, "sample-project");
    mkdirSync(localPath);
});

after(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
});

function packet(args) {
    const result = runHandler(args);
    assert.equal(result.resultType, "success");
    return result.textResultForLlm;
}

function localPacket() {
    return packet({
        local_path: localPath,
        i_understand_local_path_reads_my_disk: true,
        mode: "audit_local_source_council",
    });
}

function buildPacket() {
    return packet({
        url: "https://github.com/foo/bar",
        mode: "audit_and_safe_build_council",
        i_understand_build_executes_code: true,
    });
}

test("all source-audit modes retain remediation decisions before finalization", () => {
    for (const args of [
        { url: "https://github.com/foo/bar", mode: "audit_source" },
        { url: "https://github.com/foo/bar", mode: "audit_source_council" },
        { url: "https://github.com/foo/bar/releases/tag/baseline", mode: "verify_release" },
        {
            url: "https://github.com/foo/bar",
            mode: "audit_and_safe_build",
            i_understand_build_executes_code: true,
        },
        {
            local_path: localPath,
            i_understand_local_path_reads_my_disk: true,
            mode: "audit_local_source",
        },
    ]) {
        const out = packet(args);
        assert.match(out, /Step E — Remediation decisions before finalization/);
        assert.ok(
            out.indexOf("Step E — Remediation decisions before finalization")
                < out.indexOf("const finalizeResult = zerotrust_finalize_report({"),
        );
    }
    assert.doesNotMatch(
        packet({ url: "https://github.com/foo/bar", mode: "metadata_only" }),
        /Remediation decisions before finalization/,
    );
});

test("remediation preserves all-severity one-finding safety invariants", () => {
    for (const out of [localPacket(), buildPacket()]) {
        assert.match(out, /every active non-refuted finding, regardless of impact severity/i);
        assert.match(out, /Do NOT\s+collapse MEDIUM\/LOW\/INFO findings/);
        assert.match(out, /NEVER auto-apply/);
        assert.match(out, /NEVER batch/);
        assert.match(out, /\*\*defang\*\*/);
        assert.match(out, /\*\*delete-project\*\*/);
        assert.match(out, /\*\*keep-as-is\*\*/);
        assert.match(out, /Approve this one finding's proposed diff exactly as shown\? \(yes\/no\)/);
        assert.match(out, /explicit one-finding approval/);
        assert.match(out, /\.zerotrust-backup-<utc-ts>/);
        assert.match(out, /Never execute project code/i);
        assert.match(out, /build output as proof/i);
        assert.match(out, /Refuse\s+`keep-as-is` without a written rationale/i);
        assert.match(out, /fresh invocation/i);
        assert.match(out, /structured `operatorDecisions = \[\]`/);
        assert.match(out, /Do NOT call\s+`zerotrust_finalize_report` inside this block/);
        assert.match(out, /Do NOT write REPORT\.md\/FINDINGS\.json directly/);
        assert.equal((out.match(/zerotrust_finalize_report\(\{/g) || []).length, 1);
    }
});

test("local remediation pins delete and defang to the exact local root", () => {
    const out = localPacket();
    const resolved = nodePath.resolve(localPath);
    assert.ok(out.includes(`pinned project path for this audit is **exactly** \`${resolved}\``));
    assert.match(out, /delete-project.*delete only that root/is);
    assert.match(out, /defang.*exact evidence-bound file beneath it/is);
});

test("build remediation uses only the wrapper-returned clone identity", () => {
    const out = buildPacket();
    assert.match(
        out,
        /pinned project path for remediation is \*\*exactly\*\*\s+`cloneResult\.boundContext\.clonePath`/,
    );
    assert.match(out, /Never substitute the placeholder path/);
});

test("API-direct remediation records intent without pretending local mutation occurred", () => {
    const out = packet({
        url: "https://github.com/foo/bar",
        mode: "audit_source_council",
    });
    assert.match(out, /has no on-disk source tree to modify or delete/);
    assert.match(out, /Record `defang` or `delete-project` as requested operator intent only/);
});

test("remediation consumes only validated identities and preserves graph limitations", () => {
    const out = localPacket();
    assert.match(out, /validationFinal\.analysisSnapshot/);
    assert.match(out, /Refuted findings have no remediation entry/);
    assert.match(out, /alternate-path-remains/);
    assert.match(out, /graph-incomplete/);
    assert.match(out, /confidentPatchAllowed: false/);
});
