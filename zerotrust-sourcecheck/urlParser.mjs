// urlParser.mjs — pure URL/owner/repo/ref parsing and validation.
// No I/O, no joinSession dependency — fully unit-testable in isolation.
//
// Threat model: the URL is attacker-controlled. We must:
// - Reject anything that isn't an https://github.com/<owner>/<repo>[/...] URL
// - Strictly validate owner/repo/ref against GitHub's actual rules
//   (and Windows-safe subset for any value that becomes a path segment)
// - Reject NTFS reserved names, traversal sequences, encoded slashes,
//   credentials in the URL, and refs containing shell metacharacters
// - Reconstruct the canonical URL and target build path from validated
//   components — never concatenate raw user input into either

import nodePath from "node:path";

// GitHub username rules: 1-39 chars, alphanumeric or hyphens, can't start
// with a hyphen. We allow consecutive hyphens since the parser only ever
// sees the result; GitHub will reject invalid names server-side.
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;

// GitHub repo rules: 1-100 chars, alphanumeric / dot / underscore / hyphen.
// Reject leading dot (would be a hidden dir on POSIX) and any `..` substring.
const REPO_RE = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$/;

// Git ref rules (subset): alphanumeric / dot / underscore / slash / hyphen.
// Reject any `..` segment, leading/trailing slash, double-slash. Up to 255 chars.
const REF_RE = /^[A-Za-z0-9._/-]{1,255}$/;

// NTFS reserved device names — case-insensitive, including with extensions.
const NTFS_RESERVED = new Set([
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
]);

function isNtfsReserved(name) {
    const stem = name.toLowerCase().split(".")[0];
    return NTFS_RESERVED.has(stem);
}

function validateRef(ref) {
    if (!ref) return null;
    if (!REF_RE.test(ref)) return `ref contains disallowed characters: ${JSON.stringify(ref)}`;
    if (ref.split("/").some((seg) => seg === ".." || seg === "." || seg === "")) {
        return `ref contains traversal or empty segment: ${JSON.stringify(ref)}`;
    }
    if (ref.startsWith("/") || ref.endsWith("/") || ref.includes("//")) {
        return `ref has leading/trailing/double slash: ${JSON.stringify(ref)}`;
    }
    if (ref.startsWith("-")) {
        return `ref starts with '-' (would be parsed as a flag): ${JSON.stringify(ref)}`;
    }
    return null;
}

// Re-exported for use by safeCloneHandler — refs supplied directly to the
// wrapper bypass parseGithubUrl's validation otherwise.
export { validateRef };

// Strip a trailing `.git` suffix (case-insensitive) from the LAST path segment.
function stripDotGit(repo) {
    if (/\.git$/i.test(repo)) return repo.slice(0, -4);
    return repo;
}

/**
 * Parse and validate a GitHub URL. Returns either:
 *   { ok: true, parsed: { owner, repo, ref, refType, prNumber, kind, canonicalUrl } }
 *     where kind ∈ "repo" | "tree" | "commit" | "release" | "pr"
 *           refType ∈ "branch_or_tag" | "commit" | "release_tag" | "pr_head" | null
 *   { ok: false, error: "<reason>" }
 *
 * Accepted URL shapes (after `.git` stripping and query/fragment removal):
 *   https://github.com/<owner>/<repo>
 *   https://github.com/<owner>/<repo>/tree/<ref>[/...optional path]
 *   https://github.com/<owner>/<repo>/blob/<ref>[/...optional path]
 *   https://github.com/<owner>/<repo>/commit/<sha>
 *   https://github.com/<owner>/<repo>/releases/tag/<tag>
 *   https://github.com/<owner>/<repo>/releases  (-> defaults to repo, kind=release)
 *   https://github.com/<owner>/<repo>/pull/<n>
 *
 * Rejected: SSH URLs, embedded credentials, non-github.com hosts,
 * URL-encoded slashes/backslashes anywhere in the path.
 */
export function parseGithubUrl(input) {
    if (typeof input !== "string" || input.length === 0) {
        return { ok: false, error: "url must be a non-empty string" };
    }
    if (input.length > 2048) {
        return { ok: false, error: "url too long (>2048 chars)" };
    }
    if (/^[a-z]+@[^/]+:/i.test(input)) {
        return { ok: false, error: "SSH URLs are not supported; use https://github.com/..." };
    }

    let parsed;
    try {
        parsed = new URL(input);
    } catch {
        return { ok: false, error: "url is not a valid URL" };
    }

    if (parsed.protocol !== "https:") {
        return { ok: false, error: `protocol must be https, got ${parsed.protocol}` };
    }
    if (parsed.host !== "github.com") {
        return { ok: false, error: `host must be github.com, got ${parsed.host}` };
    }
    if (parsed.username || parsed.password) {
        return { ok: false, error: "URL must not contain credentials" };
    }

    // Reject URL-encoded slashes/backslashes in the raw pathname BEFORE
    // decoding — these are how traversal-via-encoding attacks slip past
    // naive parsers.
    if (/%2[fF]|%5[cC]/.test(parsed.pathname)) {
        return { ok: false, error: "URL contains encoded slash/backslash in path" };
    }

    // Decode and split the path.
    const rawSegments = parsed.pathname.split("/").filter(Boolean);
    const segments = rawSegments.map((s) => {
        try {
            return decodeURIComponent(s);
        } catch {
            return s;
        }
    });

    if (segments.length < 2) {
        return { ok: false, error: "URL must include /<owner>/<repo>" };
    }

    const owner = segments[0];
    let repo = stripDotGit(segments[1]);

    if (!OWNER_RE.test(owner)) {
        return { ok: false, error: `invalid owner ${JSON.stringify(owner)}` };
    }
    if (!REPO_RE.test(repo)) {
        return { ok: false, error: `invalid repo ${JSON.stringify(repo)}` };
    }
    if (repo.includes("..")) {
        return { ok: false, error: `repo contains '..': ${JSON.stringify(repo)}` };
    }
    if (isNtfsReserved(owner) || isNtfsReserved(repo)) {
        return { ok: false, error: `owner/repo conflicts with NTFS reserved name` };
    }
    if (repo.endsWith(".") || repo.endsWith(" ")) {
        return { ok: false, error: `repo has trailing dot or space (NTFS-unsafe)` };
    }

    let kind = "repo";
    let ref = null;
    let refType = null;
    let prNumber = null;

    if (segments.length >= 4 && (segments[2] === "tree" || segments[2] === "blob")) {
        kind = "tree";
        // GitHub /tree/<ref>/<path-into-tree> URLs are ambiguous from URL
        // alone: "main/src/lib" could mean branch "main" with path "src/lib"
        // OR a literal branch name "main/src/lib". GitHub disambiguates by
        // checking which actually exists; we cannot do that without an API
        // call. Preserve the longstanding "first segment is the ref, rest
        // is path-into-tree" interpretation. Slash-containing refs (e.g.
        // `release/1.0`) must be supplied via the explicit `ref:` argument
        // or by providing a /commit/<sha> URL instead.
        ref = segments[3];
        refType = "branch_or_tag";
    } else if (segments.length >= 4 && segments[2] === "commit") {
        kind = "commit";
        ref = segments[3];
        refType = "commit";
        if (!/^[0-9a-fA-F]{7,40}$/.test(ref)) {
            return { ok: false, error: `commit URL must end in a SHA, got ${JSON.stringify(ref)}` };
        }
    } else if (segments.length >= 4 && segments[2] === "releases" && segments[3] === "tag") {
        if (segments.length < 5) return { ok: false, error: "releases/tag URL missing tag name" };
        kind = "release";
        // Slash-containing tags ARE supported here because there's no
        // path-into-tree ambiguity for /releases/tag/<tag> (everything
        // after /tag/ is the tag name). gpt-5.5 reviewer Finding #6.
        ref = segments.slice(4).join("/");
        refType = "release_tag";
    } else if (segments.length >= 3 && segments[2] === "releases") {
        kind = "release";
        ref = null;
        refType = null;
    } else if (segments.length >= 4 && segments[2] === "pull") {
        kind = "pr";
        const n = Number(segments[3]);
        if (!Number.isInteger(n) || n <= 0 || n > 1_000_000) {
            return { ok: false, error: `invalid PR number ${JSON.stringify(segments[3])}` };
        }
        prNumber = n;
        // Set ref to the synthetic PR-head refspec so safe_clone resolves to
        // the actual PR head commit instead of falling back to HEAD (the
        // default branch). Without this the audit silently audits the WRONG
        // commit. Use the GitHub-supported refs/pull/<n>/head form.
        ref = `refs/pull/${n}/head`;
        refType = "pr_head";
    }

    const refError = validateRef(ref);
    if (refError) return { ok: false, error: refError };

    return {
        ok: true,
        parsed: {
            owner,
            repo,
            ref,
            refType,
            prNumber,
            kind,
            canonicalUrl: `https://github.com/${owner}/${repo}`,
        },
    };
}

function ensureValidComponents(owner, repo, shortSha) {
    if (!OWNER_RE.test(owner)) throw new Error(`invalid owner: ${owner}`);
    if (!REPO_RE.test(repo)) throw new Error(`invalid repo: ${repo}`);
    if (!/^[0-9a-fA-F]{4,40}$/.test(shortSha)) {
        throw new Error(`invalid shortSha: ${shortSha}`);
    }
}

function containedJoin(buildRoot, ...subSegments) {
    if (!buildRoot || typeof buildRoot !== "string") {
        throw new Error("buildRoot must be a non-empty string");
    }
    const resolvedRoot = nodePath.resolve(buildRoot);
    const candidate = nodePath.resolve(resolvedRoot, ...subSegments);
    const rel = nodePath.relative(resolvedRoot, candidate);
    if (rel.startsWith("..") || nodePath.isAbsolute(rel)) {
        throw new Error(`path escape: ${candidate} not under ${resolvedRoot}`);
    }
    return candidate;
}

/**
 * Build the per-clone target directory under buildRoot. Returns an absolute
 * path that is GUARANTEED to be a child of buildRoot. Throws on any
 * containment violation — failing closed is the right behavior for a
 * path-construction primitive in a security tool.
 */
export function buildClonePath(buildRoot, owner, repo, shortSha) {
    ensureValidComponents(owner, repo, shortSha);
    const dirName = `${owner}-${repo}-${shortSha.toLowerCase().slice(0, 7)}`;
    if (isNtfsReserved(dirName)) {
        throw new Error(`computed dir name conflicts with NTFS reserved name: ${dirName}`);
    }
    return containedJoin(buildRoot, dirName);
}

/**
 * Build the per-audit report directory: <buildRoot>\_reports\<owner>-<repo>-<short>.
 * Reports live OUTSIDE the cloned (untrusted) tree.
 */
export function buildReportPath(buildRoot, owner, repo, shortSha) {
    ensureValidComponents(owner, repo, shortSha);
    return containedJoin(
        buildRoot,
        "_reports",
        `${owner}-${repo}-${shortSha.toLowerCase().slice(0, 7)}`,
    );
}

/**
 * Build the per-audit quarantine directory for release assets:
 *   <buildRoot>\_quarantine\<owner>-<repo>-<short>
 * Same containment guarantees as buildReportPath.
 */
export function buildQuarantinePath(buildRoot, owner, repo, shortSha) {
    ensureValidComponents(owner, repo, shortSha);
    return containedJoin(
        buildRoot,
        "_quarantine",
        `${owner}-${repo}-${shortSha.toLowerCase().slice(0, 7)}`,
    );
}

// Exported for unit tests; not part of the public surface.
export const __internals = {
    OWNER_RE,
    REPO_RE,
    REF_RE,
    isNtfsReserved,
    validateRef,
    stripDotGit,
};
