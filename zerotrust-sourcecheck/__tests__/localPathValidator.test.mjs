// __tests__/localPathValidator.test.mjs — pure unit tests
// (node:test style to match the rest of zerotrust-sourcecheck/__tests__).

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import nodePath from "node:path";
import { tmpdir } from "node:os";

import { validateLocalPath, slugForPath, pathLooksLikeCredentialStore } from "../localPathValidator.mjs";

let tmpRoot;
let validDir;
let validFile;

before(() => {
    tmpRoot = mkdtempSync(nodePath.join(tmpdir(), "zerotrust-lpv-"));
    validDir = nodePath.join(tmpRoot, "subdir");
    validFile = nodePath.join(tmpRoot, "file.txt");
    mkdirSync(validDir);
    writeFileSync(validFile, "x");
});

after(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
});

describe("validateLocalPath - input shape", () => {
    test("rejects empty string", () => {
        const r = validateLocalPath("");
        assert.equal(r.ok, false);
        assert.match(r.error, /non-empty string/);
    });

    test("rejects non-string", () => {
        for (const v of [undefined, null, 42, {}, [], true]) {
            const r = validateLocalPath(v);
            assert.equal(r.ok, false);
            assert.match(r.error, /non-empty string/);
        }
    });

    test("rejects overly long input", () => {
        const r = validateLocalPath("C:\\" + "a".repeat(2050));
        assert.equal(r.ok, false);
        assert.match(r.error, /too long/);
    });
});

describe("validateLocalPath - path shape", () => {
    test("rejects relative path", () => {
        const r = validateLocalPath("./foo");
        assert.equal(r.ok, false);
        assert.match(r.error, /absolute/);
    });

    test("rejects bare relative basename", () => {
        const r = validateLocalPath("foo");
        assert.equal(r.ok, false);
        assert.match(r.error, /absolute/);
    });

    test("rejects UNC path", () => {
        const r = validateLocalPath("\\\\server\\share\\repo");
        assert.equal(r.ok, false);
        assert.match(r.error, /UNC/);
    });

    test("rejects long-path prefix", () => {
        const r = validateLocalPath("\\\\?\\C:\\foo");
        assert.equal(r.ok, false);
        assert.match(r.error, /UNC/);
    });

    test("rejects path with .. segment", () => {
        const r = validateLocalPath("C:\\Users\\..\\Windows");
        assert.equal(r.ok, false);
        assert.match(r.error, /'\.\.'/);
    });

    test("rejects path with .. anywhere in tree", () => {
        const r = validateLocalPath("C:\\foo\\..\\..\\bar");
        assert.equal(r.ok, false);
        assert.match(r.error, /'\.\.'/);
    });
});

describe("validateLocalPath - credential-store rejection", () => {
    const cases = [
        ["C:\\Users\\testuser\\.ssh", ".ssh/"],
        ["C:\\Users\\testuser\\.ssh\\id_rsa", ".ssh/"],
        ["C:\\Users\\testuser\\.aws", ".aws/"],
        ["C:\\Users\\testuser\\.docker", ".docker/"],
        ["C:\\Users\\testuser\\.kube\\config", ".kube/"],
        ["C:\\Users\\testuser\\.gnupg", ".gnupg/"],
        ["C:\\Users\\testuser\\.password-store", ".password-store/"],
        ["C:\\Users\\testuser\\AppData\\Roaming\\Microsoft\\Credentials", "Microsoft\\Credentials"],
        ["C:\\Users\\testuser\\AppData\\Local\\Microsoft\\Vault", "Microsoft\\Vault"],
        ["C:\\Users\\testuser\\AppData\\Roaming\\Microsoft\\Protect", "Microsoft\\Protect"],
        ["C:\\path\\to\\id_ed25519", "id_ed25519"],
        ["C:\\foo\\.npmrc", ".npmrc"],
        ["C:\\foo\\kubeconfig", "kubeconfig"],
    ];

    for (const [path, expectedLabel] of cases) {
        test(`rejects ${path} (matched ${expectedLabel})`, () => {
            const r = validateLocalPath(path);
            assert.equal(r.ok, false);
            assert.match(r.error, /credential-store/);
            assert.ok(r.error.includes(expectedLabel), `expected error to include "${expectedLabel}", got: ${r.error}`);
        });
    }

    test("does NOT reject paths that contain dot-prefixed segments unrelated to creds", () => {
        assert.equal(pathLooksLikeCredentialStore("C:\\projects\\my-app\\.github"), undefined);
        assert.equal(pathLooksLikeCredentialStore("C:\\projects\\my-app\\.vscode"), undefined);
    });

    test("does NOT reject 'aws' or 'kube' or 'docker' substrings that aren't credential dirs", () => {
        assert.equal(pathLooksLikeCredentialStore("C:\\AI\\aws-sdk-js"), undefined);
        assert.equal(pathLooksLikeCredentialStore("C:\\AI\\my-kube-stuff"), undefined);
        assert.equal(pathLooksLikeCredentialStore("C:\\AI\\docker-compose-examples"), undefined);
    });
});

describe("validateLocalPath - filesystem checks", () => {
    test("rejects non-existent path", () => {
        const r = validateLocalPath(nodePath.join(tmpRoot, "definitely-does-not-exist-abc123"));
        assert.equal(r.ok, false);
        assert.match(r.error, /does not exist/);
    });

    test("rejects a file (not a directory)", () => {
        const r = validateLocalPath(validFile);
        assert.equal(r.ok, false);
        assert.match(r.error, /must be a directory/);
    });

    test("rejects a root-level symbolic link", (t) => {
        const linkPath = nodePath.join(tmpRoot, "subdir-link");
        try {
            symlinkSync(validDir, linkPath, "dir");
        } catch {
            t.skip("symlink not supported on this platform/user");
            return;
        }
        try {
            const r = validateLocalPath(linkPath);
            assert.equal(r.ok, false);
            assert.match(r.error, /symbolic link/);
        } finally {
            try { rmSync(linkPath, { force: true }); } catch { /* ignore */ }
        }
    });

    test("accepts a valid absolute directory and returns {resolved, slug}", () => {
        const r = validateLocalPath(validDir);
        assert.equal(r.ok, true);
        assert.equal(r.resolved, nodePath.resolve(validDir));
        assert.equal(r.slug, "subdir");
    });

    test("normalizes mixed separators in input", () => {
        const mixed = validDir.replace(/\\/g, "/");
        const r = validateLocalPath(mixed);
        assert.equal(r.ok, true);
        assert.equal(r.resolved, nodePath.resolve(validDir));
    });
});

describe("slugForPath", () => {
    test("computes simple slug from basename", () => {
        assert.equal(slugForPath("C:\\projects\\my-project"), "my-project");
    });

    test("lowercases mixed-case basenames", () => {
        assert.equal(slugForPath("C:\\projects\\MyProject"), "myproject");
    });

    test("replaces disallowed chars with hyphens", () => {
        assert.equal(slugForPath("C:\\projects\\Some Weird Name!"), "some-weird-name");
    });

    test("collapses runs of hyphens", () => {
        assert.equal(slugForPath("C:\\projects\\foo!!!bar"), "foo-bar");
    });

    test("trims leading/trailing dots and hyphens", () => {
        assert.equal(slugForPath("C:\\AI\\---foo---"), "foo");
        assert.equal(slugForPath("C:\\AI\\.hidden"), "hidden");
    });

    test("preserves allowed chars (letters, digits, dot, underscore, hyphen)", () => {
        assert.equal(slugForPath("C:\\AI\\foo.bar.baz"), "foo.bar.baz");
        assert.equal(slugForPath("C:\\AI\\my_project-previous"), "my_project-previous");
    });

    test("truncates to 60 chars", () => {
        const long = "C:\\AI\\" + "a".repeat(120);
        const slug = slugForPath(long);
        assert.ok(slug.length <= 60, `slug length ${slug.length} > 60`);
        assert.equal(slug, "a".repeat(60));
    });

    test("falls back to 'root' when basename is empty", () => {
        assert.equal(slugForPath("/"), "root");
    });

    test("falls back to 'root' when slug normalization strips everything", () => {
        assert.equal(slugForPath("C:\\AI\\!!!"), "root");
    });
});
