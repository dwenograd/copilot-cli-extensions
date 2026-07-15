// __tests__/avSafetyScan.test.mjs
//
// AV-safety scan: assert that v3-changed files do not contain any of the
// v2-incident-trigger byte sequences that previously caused Microsoft
// Defender alerts during the v2 build.
//
// Background — two distinct v2 files tripped Defender:
//   1. A fixture file containing a JS eval-of-base64 token plus a
//      Tags-block-style UTF-8 byte triple → Trojan:JS/GlassWorm.A!MTB
//   2. A role-prompt file densely enumerating PowerShell offensive
//      cmdlet names → Trojan:PowerShell/PsAttack.R
//
// The v3 AV-safety gate is: no v3-changed file contains a known
// v2-incident-trigger substring. This test enforces that gate on every
// v3-CHANGED file (modes.mjs + future safeWrappers/ + tagDictionary/).
//
// Pre-existing files (packet.mjs prose, README.md deferred-items table,
// council/ role prompts, all __tests__) are explicitly OUT-OF-SCOPE here
// and must NOT be scanned — they have been on disk for hours/days without
// triggering AV.
//
// CRITICAL: trigger substrings are expressed in this file via
// character-by-character concatenation only — never as literal raw
// bytes — so this test file itself does not become an AV trigger.
// If you add a new trigger, follow the existing convention.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = join(__dirname, "..");

// ---------- v2-incident-trigger substrings ----------
//
// Each entry is { label, bytes }. `bytes` is a Buffer constructed from
// concatenated string fragments (or, for the UTF-8 byte triple, raw hex
// byte literals) so the literal trigger sequence never appears verbatim
// in this source file.
//
// To cross-check what each Buffer represents, see the comment on each
// entry — but DO NOT inline the literal string.
const TRIGGERS = [
    {
        // AMSI scan-buffer API name (PowerShell AMSI-bypass token).
        label: "AMSI scan-buffer token",
        bytes: Buffer.from("Am" + "siSc" + "an" + "Buffer", "utf-8"),
    },
    {
        // AMSI utilities reflection target (alternate AMSI-bypass token).
        label: "AMSI utils reflection token",
        bytes: Buffer.from("Am" + "si" + "Utils", "utf-8"),
    },
    {
        // Defender-exclusion modification cmdlet.
        label: "Defender-exclusion cmdlet",
        bytes: Buffer.from("Add-Mp" + "Pre" + "ference", "utf-8"),
    },
    {
        // JavaScript eval-of-base64 token.
        label: "JS eval-of-base64 token",
        bytes: Buffer.from("ev" + "al" + "(at" + "ob(", "utf-8"),
    },
    {
        // Three-byte UTF-8 prefix used by the v2 GlassWorm fixture
        // (Tags-block-style invisible-character sequence). Expressed as
        // raw hex byte literals so the actual byte sequence does not
        // appear as raw characters in this source file.
        label: "Tags-block UTF-8 byte triple",
        bytes: Buffer.from([0xe0, 0xa0, 0x80]),
    },
    {
        // LSA secrets-read API name.
        label: "LSA secrets read token",
        bytes: Buffer.from("Lsa" + "Open" + "Policy", "utf-8"),
    },
    {
        // Active Directory enumeration via SAM API.
        label: "AD SAM enumeration token",
        bytes: Buffer.from("SamEnum" + "erate" + "UsersIn" + "Domain", "utf-8"),
    },
    {
        // LSASS memory-dump API name.
        label: "LSASS minidump token",
        bytes: Buffer.from("Mini" + "Dump" + "WriteDump", "utf-8"),
    },
];

// ---------- Allowlist of v3-changed files to scan ----------
//
// Per Wave 0 Step 0.5 spec, scan only files added/modified by v3 work.
// Pre-existing files are explicitly out-of-scope to avoid false positives
// on prose that has been on disk for days without triggering AV.
//
// Allowlist:
//   - modes.mjs at extension root (added in Wave 0 Step 0.4)
//   - everything (.mjs / .md, recursive) under safeWrappers/ if it exists
//     (will be added in Wave 0 Step 0.6)
//   - everything (.mjs / .md, recursive) under tagDictionary/ if it exists
//     (will be added in Feature 1 Step 1.2)
//   - everything (.mjs / .md, recursive) under __corpus__/runner/
//   - __tests__/corpusRunner.test.mjs
//   - __tests__/buildCouncil.test.mjs
//   - __tests__/defaultPromotion.test.mjs
//
// Skip-list (documentation; the allowlist makes this redundant but the
// test stays intentionally narrow):
//   - packet.mjs, README.md (pre-existing prose with deferred-items text)
//   - handler.mjs, enforcement.mjs, extension.mjs, urlParser.mjs
//   - council/ (pre-existing role prompts)
//   - other __tests__/ files (some pre-existing tests reference v2 prose)
//   - node_modules/, build/, dist/ (vendor / build output)
const ALLOWED_ROOT_FILES = ["modes.mjs"];
const ALLOWED_FILES = [
    ["__tests__", "corpusRunner.test.mjs"],
    ["__tests__", "buildCouncil.test.mjs"],
    ["__tests__", "defaultPromotion.test.mjs"],
    ["__tests__", "cleanupAndPurge.test.mjs"],
    ["__tests__", "v31Hardening.test.mjs"],
    ["__tests__", "apiDirect.test.mjs"],
    ["__tests__", "v4r1Hardening.test.mjs"],
    ["__tests__", "v4r2Hardening.test.mjs"],
    ["__tests__", "v4r2r2Hardening.test.mjs"],
    ["__tests__", "v4r2r3Hardening.test.mjs"],
    ["__tests__", "v4r2r4Hardening.test.mjs"],
    ["__tests__", "v4r2r5Hardening.test.mjs"],
    ["__tests__", "v4r2r6Hardening.test.mjs"],
    ["__tests__", "v4r2r7Hardening.test.mjs"],
    ["__tests__", "v4r2r8Hardening.test.mjs"],
    ["__tests__", "v4r2r9Hardening.test.mjs"],
    ["__tests__", "v4r2r10Hardening.test.mjs"],
    ["__tests__", "v4r2r11Hardening.test.mjs"],
    ["analysis", "plugins", "runner.mjs"],
    ["analysis", "reportLedger.mjs"],
    ["__corpus__", "README.md"],
    ["__corpus__", "promotion-gate.v1.json"],
];
const ALLOWED_DIRS = [
    ["safeWrappers"],
    ["tagDictionary"],
    ["__corpus__", "runner"],
    ["__corpus__", "fixtures"],
    ["__corpus__", "expectations"],
];
const SCAN_EXTENSIONS = [".mjs", ".md", ".json", ".ztfixture"];

function hasScanExtension(name) {
    return SCAN_EXTENSIONS.some((ext) => name.endsWith(ext));
}

function walkDir(root) {
    // Recursive walk yielding absolute file paths under root.
    // No skip-list inside walkDir itself — the caller controls which
    // roots to walk via ALLOWED_DIRS.
    const out = [];
    if (!existsSync(root)) return out;
    const stack = [root];
    while (stack.length > 0) {
        const cur = stack.pop();
        let entries;
        try {
            entries = readdirSync(cur, { withFileTypes: true });
        } catch {
            continue;
        }
        for (const ent of entries) {
            const p = join(cur, ent.name);
            if (ent.isDirectory()) {
                stack.push(p);
            } else if (ent.isFile() && hasScanExtension(ent.name)) {
                out.push(p);
            }
        }
    }
    return out;
}

function collectScanTargets() {
    const targets = [];
    for (const f of ALLOWED_ROOT_FILES) {
        const p = join(EXT_ROOT, f);
        if (existsSync(p) && statSync(p).isFile()) {
            targets.push(p);
        }
    }
    for (const parts of ALLOWED_FILES) {
        const p = join(EXT_ROOT, ...parts);
        if (existsSync(p) && statSync(p).isFile()) {
            targets.push(p);
        }
    }
    for (const parts of ALLOWED_DIRS) {
        const p = join(EXT_ROOT, ...parts);
        if (existsSync(p) && statSync(p).isDirectory()) {
            targets.push(...walkDir(p));
        }
    }
    return targets;
}

// ---------- Tests ----------

test("v3-changed files contain none of the v2 AV-incident triggers", () => {
    const targets = collectScanTargets();
    assert.ok(
        targets.length >= 1,
        `expected at least one v3-changed file to scan; got ${targets.length}. ` +
            `Allowlist: root=${ALLOWED_ROOT_FILES.join(",")}, files=${ALLOWED_FILES.map((p) => p.join(sep)).join(",")}, dirs=${ALLOWED_DIRS.map((p) => p.join(sep)).join(",")}`,
    );

    const violations = [];
    for (const p of targets) {
        const buf = readFileSync(p);
        for (const t of TRIGGERS) {
            if (buf.includes(t.bytes)) {
                violations.push({
                    file: p.replace(EXT_ROOT + sep, ""),
                    trigger: t.label,
                });
            }
        }
    }

    assert.deepEqual(
        violations,
        [],
        `AV-safety scan failed — found ${violations.length} v2-incident-trigger occurrence(s) in v3 files:\n` +
            violations
                .map((v) => `  - ${v.file}: contains ${JSON.stringify(v.trigger)}`)
                .join("\n") +
            `\n\nIf this is intentional (e.g., a new safe-wrapper helper that legitimately needs the term), ` +
            `move the trigger out of inline source into a runtime-built regex or character-concatenation expression, ` +
            `or add the file to a documented skip-list with explicit justification.`,
    );
});

test("AV-safety scan covers modes.mjs (canonical v3 file) when present", () => {
    // Sanity: if modes.mjs exists (it does — shipped in Wave 0 Step 0.4)
    // it MUST be among the scan targets. Guards against accidental
    // allowlist regression that would silently scan zero files and let
    // the main assertion pass vacuously.
    const targets = collectScanTargets();
    const modesPath = join(EXT_ROOT, "modes.mjs");
    if (existsSync(modesPath)) {
        assert.ok(
            targets.includes(modesPath),
            "expected modes.mjs to be included in scan targets",
        );
    }
});

test("AV-safety scan covers v3 test additions", () => {
    const targets = collectScanTargets();
    assert.ok(
        targets.includes(join(EXT_ROOT, "__corpus__", "runner", "tagDictionary.mjs")),
        "expected corpus runner modules to be included in scan targets",
    );
    assert.ok(
        targets.includes(join(EXT_ROOT, "__tests__", "corpusRunner.test.mjs")),
        "expected corpusRunner.test.mjs to be included in scan targets",
    );
    assert.ok(
        targets.includes(join(EXT_ROOT, "__tests__", "defaultPromotion.test.mjs")),
        "expected defaultPromotion.test.mjs to be included in scan targets",
    );
});

test("AV-safety scan covers v3.1 hardening files (cleanup wrapper + auto-purge)", () => {
    const targets = collectScanTargets();
    assert.ok(
        targets.includes(join(EXT_ROOT, "safeWrappers", "cleanupWrapper.mjs")),
        "expected safeWrappers/cleanupWrapper.mjs to be in scan targets",
    );
    assert.ok(
        targets.includes(join(EXT_ROOT, "safeWrappers", "autoPurge.mjs")),
        "expected safeWrappers/autoPurge.mjs to be in scan targets",
    );
    assert.ok(
        targets.includes(join(EXT_ROOT, "safeWrappers", "programResolver.mjs")),
        "expected safeWrappers/programResolver.mjs to be in scan targets",
    );
    assert.ok(
        targets.includes(join(EXT_ROOT, "safeWrappers", "apiClient.mjs")),
        "expected safeWrappers/apiClient.mjs (v4) to be in scan targets",
    );
    assert.ok(
        targets.includes(join(EXT_ROOT, "safeWrappers", "safeListTreeHandler.mjs")),
        "expected safeWrappers/safeListTreeHandler.mjs (v4) to be in scan targets",
    );
    assert.ok(
        targets.includes(join(EXT_ROOT, "safeWrappers", "safeFetchHandler.mjs")),
        "expected safeWrappers/safeFetchHandler.mjs (v4) to be in scan targets",
    );
});

