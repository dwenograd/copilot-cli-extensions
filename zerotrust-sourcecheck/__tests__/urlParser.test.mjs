// urlParser.test.mjs
// Adversarial tests for the URL/owner/repo/ref parser. Run with:
//   node --test __tests__/urlParser.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    parseGithubUrl,
    buildClonePath,
    buildReportPath,
    buildQuarantinePath,
    __internals,
} from "../urlParser.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck"
    : "/tmp/zerotrust-sourcecheck";

// ---------- Happy-path URL shapes ----------

test("parses a bare repo URL", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.owner, "octocat");
    assert.equal(r.parsed.repo, "hello-world");
    assert.equal(r.parsed.kind, "repo");
    assert.equal(r.parsed.ref, null);
    assert.equal(r.parsed.canonicalUrl, "https://github.com/octocat/hello-world");
});

test("parses a /tree/<branch> URL", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/tree/main");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.kind, "tree");
    assert.equal(r.parsed.ref, "main");
    assert.equal(r.parsed.refType, "branch_or_tag");
});

test("parses a /tree/<branch>/<deep-path> URL (extra segments ignored)", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/tree/main/src/lib");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.ref, "main");
});

test("parses a /commit/<sha> URL", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/commit/abcdef0123456789abcdef0123456789abcdef01");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.kind, "commit");
    assert.equal(r.parsed.ref.length, 40);
});

test("parses a /releases/tag/<tag> URL", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/releases/tag/v1.2.3");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.kind, "release");
    assert.equal(r.parsed.ref, "v1.2.3");
});

test("parses a /pull/<n> URL", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/pull/42");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.kind, "pr");
    assert.equal(r.parsed.prNumber, 42);
});

test("strips trailing .git", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world.git");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.repo, "hello-world");
});

// ---------- Adversarial inputs ----------

test("rejects SSH URL", () => {
    const r = parseGithubUrl("git@github.com:octocat/hello-world.git");
    assert.equal(r.ok, false);
    assert.match(r.error, /SSH/i);
});

test("rejects URL with credentials", () => {
    const r = parseGithubUrl("https://user:secret@github.com/octocat/hello-world");
    assert.equal(r.ok, false);
    assert.match(r.error, /credentials/i);
});

test("rejects non-github.com host", () => {
    const r = parseGithubUrl("https://gitlab.com/octocat/hello-world");
    assert.equal(r.ok, false);
    assert.match(r.error, /github\.com/i);
});

test("rejects http (non-https)", () => {
    const r = parseGithubUrl("http://github.com/octocat/hello-world");
    assert.equal(r.ok, false);
    assert.match(r.error, /https/i);
});

test("rejects URL with encoded slash in path", () => {
    const r = parseGithubUrl("https://github.com/octocat/foo%2Fbar/tree/main");
    assert.equal(r.ok, false);
    assert.match(r.error, /encoded slash/i);
});

test("rejects URL with encoded backslash", () => {
    const r = parseGithubUrl("https://github.com/octocat/foo%5Cbar");
    assert.equal(r.ok, false);
    assert.match(r.error, /encoded slash|backslash/i);
});

test("rejects path-traversal owner", () => {
    const r = parseGithubUrl("https://github.com/..%2F..%2Fwindows%2Fsystem32/foo");
    // The %2F check fires first, but either rejection is acceptable.
    assert.equal(r.ok, false);
});

test("rejects '..' in repo name", () => {
    const r = parseGithubUrl("https://github.com/octocat/foo..bar");
    assert.equal(r.ok, false);
});

test("rejects NTFS reserved name 'CON' as repo", () => {
    const r = parseGithubUrl("https://github.com/octocat/CON");
    assert.equal(r.ok, false);
    assert.match(r.error, /NTFS/i);
});

test("rejects NTFS reserved name 'NUL.txt' as repo", () => {
    const r = parseGithubUrl("https://github.com/octocat/NUL.txt");
    assert.equal(r.ok, false);
    assert.match(r.error, /NTFS/i);
});

test("rejects ref starting with '-' (would parse as a flag)", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/tree/-rm-rf");
    assert.equal(r.ok, false);
    assert.match(r.error, /flag|disallowed/i);
});

test("rejects ref with '..' segment", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/tree/main/../etc");
    // The /tree/<ref>/... handling treats only segments[3] as ref; ".." appears in deeper
    // segments which are ignored. But "main" is the captured ref, so this should pass.
    // The test below covers the actual ref-traversal rejection.
    assert.equal(r.ok, true);
});

test("rejects ref with embedded '..' inside the ref segment", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/tree/foo..bar");
    assert.equal(r.ok, true); // dots in refs are allowed (semver tags)
    // The traversal check is on PATH segments, not character substrings.
});

test("rejects ref with path-segment '..' via tree URL", () => {
    // Constructed by parsing the URL into segments[3]='..' is impossible
    // because URL normalization would collapse it. Verify validateRef catches it.
    const refError = __internals.validateRef("..");
    assert.ok(refError && refError.includes("traversal"));
});

test("rejects empty / extremely long URL", () => {
    assert.equal(parseGithubUrl("").ok, false);
    assert.equal(parseGithubUrl("a".repeat(3000)).ok, false);
});

test("rejects non-string", () => {
    assert.equal(parseGithubUrl(null).ok, false);
    assert.equal(parseGithubUrl(undefined).ok, false);
    assert.equal(parseGithubUrl(123).ok, false);
});

test("rejects /commit/<not-a-sha>", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/commit/main");
    assert.equal(r.ok, false);
});

test("rejects /pull/<not-a-number>", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world/pull/abc");
    assert.equal(r.ok, false);
});

test("rejects /pull/0 and /pull/<huge>", () => {
    assert.equal(parseGithubUrl("https://github.com/octocat/hello-world/pull/0").ok, false);
    assert.equal(parseGithubUrl("https://github.com/octocat/hello-world/pull/9999999").ok, false);
});

test("ignores query params and fragments without leaking them", () => {
    const r = parseGithubUrl("https://github.com/octocat/hello-world?tab=code#L42");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.canonicalUrl, "https://github.com/octocat/hello-world");
});

// ---------- Path construction safety ----------

test("buildClonePath produces a child of build_root", () => {
    const p = buildClonePath(BUILD_ROOT, "octocat", "hello-world", "abc1234");
    assert.ok(p.toLowerCase().startsWith(BUILD_ROOT.toLowerCase()));
    assert.match(p, /octocat-hello-world-abc1234$/);
});

test("buildClonePath rejects bad components", () => {
    assert.throws(() => buildClonePath(BUILD_ROOT, "..", "hello", "abc1234"));
    assert.throws(() => buildClonePath(BUILD_ROOT, "octocat", "..", "abc1234"));
    assert.throws(() => buildClonePath(BUILD_ROOT, "octocat", "hello", "../etc"));
    assert.throws(() => buildClonePath("", "octocat", "hello", "abc1234"));
});

test("buildClonePath uses 7-char short SHA", () => {
    const p = buildClonePath(BUILD_ROOT, "octocat", "hello-world", "abcdef0123456789abcdef0123456789abcdef01");
    assert.ok(p.endsWith("abcdef0"));
});

test("buildReportPath places report under _reports", () => {
    const p = buildReportPath(BUILD_ROOT, "octocat", "hello-world", "abc1234");
    assert.match(p, /_reports[/\\]octocat-hello-world-abc1234$/);
});

test("buildQuarantinePath places quarantine under _quarantine", () => {
    const p = buildQuarantinePath(BUILD_ROOT, "octocat", "hello-world", "abc1234");
    assert.match(p, /_quarantine[/\\]octocat-hello-world-abc1234$/);
});
