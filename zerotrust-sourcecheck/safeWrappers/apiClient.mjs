// safeWrappers/apiClient.mjs
//
// Pure helper around `gh api` for v4 API-direct audits — fetches GitHub
// content without ever writing source bytes to disk.
//
// Why `gh api` and not raw HTTPS:
//   - Re-uses the operator's existing GitHub authentication (5000 req/hr
//     authenticated vs. 60 req/hr unauth).
//   - `gh` is already installed (it's the documented dependency for the
//     wider extension).
//   - Avoids needing to bundle an HTTP client; execFileSync is simpler.
//
// Trust model:
//   - All `gh` invocations go through resolveTrustedProgram (round-11
//     hardening) so a repo-planted `gh.cmd` cannot shadow-execute.
//   - File contents are returned in-memory only. Callers pass them to
//     the agent for analysis; they never touch the filesystem.
//   - There is a per-fetch byte cap (configurable). Above the cap, only
//     SHA256 + size + first-N-bytes are returned (so the audit can still
//     reason about large files without pulling them into memory).

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

import { resolveTrustedProgram } from "./programResolver.mjs";

// Per-fetch caps:
//   - DEFAULT_MAX_FILE_BYTES (5MB): hard ceiling for any fetch attempt.
//     Files over this return metadata + 4KB preview only.
//   - DEFAULT_TEXT_INLINE_BYTES (256KB): max text content returned inline.
//     Larger TEXT files get truncated to this size with a `truncated: true`
//     marker. Most source files are well under 256KB.
//   - BINARY_PREVIEW_BYTES (256): magic-byte preview for binaries. Just
//     enough to confirm file type (PE "MZ", ELF "\x7fELF", ZIP "PK\x03\x04",
//     etc.) without returning the full binary.
//
// v4.1 hardening: BINARY content is NEVER returned in full (no `base64`
// field). The agent gets size + sha256 + magic-byte preview only. This
// closes the spill-via-runtime-temp-file attack: a 552KB malware .exe
// previously would have returned ~750KB of base64 in the JSON response,
// which the Copilot CLI runtime spills to %LOCALAPPDATA%\Temp\copilot-
// tool-output-*.txt, where Defender then sees it. With this hardening,
// the response for that .exe is ~400 bytes — way under any spill threshold.
export const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
export const DEFAULT_TEXT_INLINE_BYTES = 256 * 1024;   // 256 KB
export const DEFAULT_PREVIEW_BYTES = 4096;             // first 4 KB of >maxBytes files
export const BINARY_PREVIEW_BYTES = 256;               // magic-byte preview for binaries
const GH_TIMEOUT_MS = 60_000;

const OWNER_RE = /^[A-Za-z0-9._-]{1,100}$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
// Path inside repo: forward-slash-separated, allowed chars only, no `..`.
const REPO_PATH_RE = /^[A-Za-z0-9._/-]{1,1024}$/;

function ensureValidOwnerRepo(owner, repo) {
    if (typeof owner !== "string" || !OWNER_RE.test(owner) || owner === "." || owner === "..") {
        throw new Error(`invalid owner: ${JSON.stringify(owner)}`);
    }
    if (typeof repo !== "string" || !REPO_RE.test(repo) || repo === "." || repo === "..") {
        throw new Error(`invalid repo: ${JSON.stringify(repo)}`);
    }
}

function ensureValidSha(sha) {
    if (typeof sha !== "string" || !SHA_RE.test(sha)) {
        throw new Error(`invalid sha: ${JSON.stringify(sha)}`);
    }
}

function ensureValidPath(path) {
    if (typeof path !== "string" || !REPO_PATH_RE.test(path)) {
        throw new Error(`invalid repo path: ${JSON.stringify(path)}`);
    }
    if (path.includes("..") || path.startsWith("/") || path.endsWith("/") || path.includes("//")) {
        throw new Error(`repo path has traversal / leading-trailing slash / double slash: ${JSON.stringify(path)}`);
    }
}

function runGh(args) {
    const program = resolveTrustedProgram("gh", { forbiddenRoots: [] });
    if (!program) {
        throw new Error(`could not resolve a trusted absolute path for 'gh' on PATH. Install GitHub CLI (gh) system-wide.`);
    }
    let stdout;
    try {
        stdout = execFileSync(program, args, {
            encoding: "utf-8",
            timeout: GH_TIMEOUT_MS,
            windowsHide: true,
            env: { ...process.env, GH_PROMPT_DISABLED: "1" },
            stdio: ["ignore", "pipe", "pipe"],
            maxBuffer: 32 * 1024 * 1024, // 32 MB
        });
    } catch (err) {
        const stderr = err.stderr ? String(err.stderr) : "";
        throw new Error(`gh ${args[0]} failed: ${err.message}${stderr ? `\nstderr: ${stderr.slice(-500)}` : ""}`);
    }
    return stdout;
}

/**
 * Resolve a ref (branch / tag / sha-prefix / "HEAD") to a 40-char SHA via the
 * GitHub API. Returns the SHA on success, throws on failure.
 *
 * refType is one of: "release_tag" | "branch_or_tag" | "pr_head" | "commit" | null
 *   - "commit": ref is already a SHA (validated by caller); we just check shape.
 *   - "release_tag": queries refs/tags/<ref>, peels annotated tags.
 *   - "branch_or_tag": queries refs/heads/<ref> first, falls back to refs/tags/<ref>.
 *   - "pr_head": ref is "refs/pull/<n>/head"; query that.
 *   - null/unknown: tries "branch_or_tag" semantics.
 */
export function resolveRefToSha(owner, repo, ref, refType) {
    ensureValidOwnerRepo(owner, repo);
    if (refType === "commit" || (typeof ref === "string" && SHA_RE.test(ref))) {
        ensureValidSha(ref);
        return ref;
    }

    const refToResolve = ref || "HEAD";
    if (typeof refToResolve !== "string" || !/^[A-Za-z0-9._/\-]{1,255}$/.test(refToResolve)) {
        throw new Error(`invalid ref: ${JSON.stringify(refToResolve)}`);
    }

    // For HEAD, use the default-branch resolution path
    if (refToResolve === "HEAD") {
        const repoMeta = JSON.parse(runGh(["api", `repos/${owner}/${repo}`]));
        const defaultBranch = repoMeta.default_branch;
        if (!defaultBranch || typeof defaultBranch !== "string") {
            throw new Error(`gh api repos/${owner}/${repo} did not return a default_branch`);
        }
        const branchInfo = JSON.parse(runGh(["api", `repos/${owner}/${repo}/branches/${defaultBranch}`]));
        const sha = branchInfo?.commit?.sha;
        if (!sha || !SHA_RE.test(sha)) {
            throw new Error(`could not resolve HEAD for ${owner}/${repo} (default branch ${defaultBranch})`);
        }
        return sha;
    }

    let candidatePaths;
    switch (refType) {
        case "release_tag":
            candidatePaths = [`repos/${owner}/${repo}/git/refs/tags/${refToResolve}`];
            break;
        case "pr_head": {
            // ref is "refs/pull/<n>/head"; extract the number
            const m = refToResolve.match(/^refs\/pull\/(\d+)\/head$/);
            if (!m) throw new Error(`pr_head ref must be refs/pull/<n>/head, got ${JSON.stringify(refToResolve)}`);
            candidatePaths = [`repos/${owner}/${repo}/pulls/${m[1]}`];
            break;
        }
        case "branch_or_tag":
        default:
            candidatePaths = [
                `repos/${owner}/${repo}/git/refs/heads/${refToResolve}`,
                `repos/${owner}/${repo}/git/refs/tags/${refToResolve}`,
            ];
            break;
    }

    let lastError;
    for (const apiPath of candidatePaths) {
        let raw;
        try {
            raw = runGh(["api", apiPath]);
        } catch (err) {
            lastError = err;
            continue;
        }
        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (err) {
            lastError = err;
            continue;
        }

        // PR-head shape
        if (refType === "pr_head") {
            const sha = parsed?.head?.sha;
            if (sha && SHA_RE.test(sha)) return sha;
            lastError = new Error(`PR API response missing head.sha`);
            continue;
        }

        // git/refs shape
        const objectSha = parsed?.object?.sha;
        const objectType = parsed?.object?.type;
        if (objectSha && SHA_RE.test(objectSha)) {
            // Annotated tag: peel to commit by fetching the tag object
            if (refType === "release_tag" && objectType === "tag") {
                try {
                    const tagObj = JSON.parse(runGh(["api", `repos/${owner}/${repo}/git/tags/${objectSha}`]));
                    const peeled = tagObj?.object?.sha;
                    if (peeled && SHA_RE.test(peeled)) return peeled;
                } catch (err) {
                    // fall through to returning the tag-object SHA as a last resort
                }
            }
            return objectSha;
        }
        lastError = new Error(`gh api ${apiPath} returned no usable object.sha`);
    }
    throw new Error(`could not resolve ref ${JSON.stringify(refToResolve)} for ${owner}/${repo}: ${lastError?.message || "no candidates resolved"}`);
}

/**
 * List the repo's tree at the given SHA, recursively. Returns an array of
 * { path, type, size, sha } entries. Tree may be truncated by GitHub for
 * very large repos — caller is told via `truncated: true` in the result.
 *
 * v4.2: also enforces our own entry-count cap (default 5000) to bound the
 * response size — a malicious repo with attacker-controlled file names
 * could otherwise flood the response with payload-shaped path strings,
 * triggering a runtime spill of the tool output.
 */
const DEFAULT_MAX_ENTRIES = 5000;

export function listTree(owner, repo, sha, { maxEntries = DEFAULT_MAX_ENTRIES } = {}) {
    ensureValidOwnerRepo(owner, repo);
    ensureValidSha(sha);
    const raw = runGh(["api", `repos/${owner}/${repo}/git/trees/${sha}?recursive=1`]);
    const parsed = JSON.parse(raw);
    const allEntries = Array.isArray(parsed?.tree) ? parsed.tree : [];

    let entries = allEntries;
    let entriesTruncated = false;
    if (entries.length > maxEntries) {
        entries = entries.slice(0, maxEntries);
        entriesTruncated = true;
    }

    return {
        sha: parsed?.sha || sha,
        truncated: !!parsed?.truncated,
        entriesTruncated,
        totalEntryCount: allEntries.length,
        entries: entries.map((e) => ({
            path: e.path,
            type: e.type,
            size: e.size || 0,
            sha: e.sha,
        })),
    };
}

/**
 * Fetch a single file's contents at the given SHA. See header for return shapes.
 *
 * Order of checks:
 *   1. Binary detection FIRST (across the WHOLE buffer, not just first 8KB —
 *      v4.2 hardening for polyglot files that put clean ASCII first then
 *      binary payload). If binary: return metadata + 256-byte preview, no
 *      base64 content. This branch ignores `maxBytes` so an attacker can't
 *      force the larger 4KB-preview branch by passing a tiny `max_bytes`.
 *   2. Hard-ceiling check (size > maxBytes). For text files only — binaries
 *      already returned above.
 *   3. Text inline-cap (size > maxTextBytes → truncate).
 *   4. Default text return.
 */

// v4.2 hardening: binary classification helper. Extracted so it's
// independently unit-testable without mocking runGh.
//
// A buffer is binary if EITHER:
//   (a) any byte in the WHOLE buffer is null (not just the first 8KB —
//       that bound was bypassable via polyglot files with clean ASCII
//       prefix and binary payload further in), OR
//   (b) the file extension matches the binary allowlist (defense in
//       depth against null-byte-free binary formats: encoded scripts,
//       custom packers, signed certs, etc.).
//
// v4-r2 hardening (3/3 reviewer consensus): TEXT script formats that
// auditors MUST be able to read in full (.ps1 / .psm1 / .psd1 / .bat /
// .cmd / .wsf / .hta / .svg / .vbs) are deliberately EXCLUDED from
// BINARY_EXT_RE. They're typically the primary attack surface for
// supply-chain payloads on Windows, and the audit's Section 5 Category C
// pattern checks (outbound-network and process-launch cmdlets, and so
// on — no offensive cmdlet names enumerated here, see AV-safety guard
// in the test suite) require their full text to be visible. The
// whole-buffer null-byte scan still catches polyglot binaries that
// masquerade with a script extension. Genuinely-encoded/obfuscated
// scripts (.jse / .vbe) STAY in the binary set — they're designed to
// be opaque and should be surfaced as a finding rather than decoded.
//
// v4-r2 round-2 hardening (gpt-5.5 R2 F4 high): UTF-16-encoded text
// scripts contain null bytes by design (every other byte for ASCII
// chars). Without UTF-16 handling, an attacker could save a malicious
// install.ps1 / build.cmd as UTF-16LE and the whole-buffer null-byte
// sniff would (correctly!) detect nulls — but then mis-classify the
// file as binary, returning only a 256-byte preview and hiding the
// payload from the audit. classifyAsBinary now treats files with a
// known TEXT-script extension AND a UTF-16 BOM as text, decoding
// occurs in fetchFile.
const BINARY_EXT_RE = /\.(?:exe|dll|so|dylib|msi|deploy|pfx|p12|p7s|p7b|cer|crt|der|pyd|wasm|class|jar|war|ear|nupkg|whl|egg|zip|tar|gz|bz2|xz|7z|rar|cab|iso|dmg|pkg|appx|msix|ipa|apk|aab|jse|vbe|scr|cpl|com|ico|cur|ani|ttf|otf|woff|woff2|eot|jpg|jpeg|png|gif|bmp|webp|tiff|psd|mp3|mp4|mov|avi|wmv|flv|mkv|ogg|opus|wav|flac|pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|sqlite|db|mdb|bin)$/i;

// Text-script extensions that the audit MUST be able to read in full.
// When a file has one of these extensions AND a UTF-16 BOM, treat it
// as text (decode UTF-16) instead of falling into the binary branch.
const TEXT_SCRIPT_EXT_RE = /\.(?:ps1|psm1|psd1|bat|cmd|wsf|hta|vbs|svg|js|mjs|cjs|ts|tsx|jsx|py|rb|sh|bash|zsh|fish|pl|php|go|rs|java|kt|swift|c|h|cpp|cc|hpp|cs|fs|fsx|m|mm|sql|yaml|yml|json|xml|html|htm|css|scss|sass|less|md|txt|toml|ini|conf|env)$/i;

// UTF-16 BOM detection. UTF-16LE = FF FE; UTF-16BE = FE FF.
function detectUtf16Bom(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 2) return null;
    if (buf[0] === 0xFF && buf[1] === 0xFE) return "utf-16le";
    if (buf[0] === 0xFE && buf[1] === 0xFF) return "utf-16be";
    return null;
}

export function classifyAsBinary(buf, path) {
    if (!Buffer.isBuffer(buf)) {
        throw new Error("classifyAsBinary requires a Buffer");
    }
    // v4-r2 round-2: a UTF-16-encoded text script has nulls by design
    // but is text from the audit's perspective. If the path matches a
    // known text-script extension AND the buffer starts with a UTF-16
    // BOM, treat as text (the caller — fetchFile — will decode it).
    const utf16 = detectUtf16Bom(buf);
    if (utf16 && TEXT_SCRIPT_EXT_RE.test(String(path || ""))) {
        return false;
    }
    return buf.includes(0) || BINARY_EXT_RE.test(String(path || ""));
}

// Exported so fetchFile (and tests) can decide which decoder to use.
export { detectUtf16Bom };

export function fetchFile(owner, repo, sha, path, {
    maxBytes = DEFAULT_MAX_FILE_BYTES,
    maxTextBytes = DEFAULT_TEXT_INLINE_BYTES,
    previewBytes = DEFAULT_PREVIEW_BYTES,
    binaryPreviewBytes = BINARY_PREVIEW_BYTES,
} = {}) {
    ensureValidOwnerRepo(owner, repo);
    ensureValidSha(sha);
    ensureValidPath(path);

    // Use the contents API which returns base64-encoded content for any file type.
    const raw = runGh(["api", `repos/${owner}/${repo}/contents/${path}?ref=${sha}`, "-H", "Accept: application/vnd.github+json"]);
    const parsed = JSON.parse(raw);
    if (parsed?.type !== "file") {
        throw new Error(`expected file at ${path}, got ${parsed?.type || "unknown"}`);
    }

    // v4-r2 round-6 (C-R6-3 high): GitHub's Contents API returns
    // `encoding: "none"` and empty content for files between 1 MB and
    // 100 MB (the API's hard limit for the contents endpoint). The
    // round-3 code threw on this, blinding the audit to any file in
    // that size range. Fall back to the blobs endpoint, which always
    // returns base64 for blobs ≤100 MB. The contents response gives
    // us the blob SHA in `parsed.sha`.
    let buf;
    if (parsed?.encoding === "none") {
        const blobSha = parsed?.sha;
        if (typeof blobSha !== "string" || !/^[a-f0-9]{40}$/i.test(blobSha)) {
            throw new Error(`large file ${path} returned encoding=none but no usable blob sha`);
        }
        // If the file is larger than our absolute ceiling, return
        // metadata-only — don't even fetch via blobs, since blobs
        // would deliver the full bytes and bloat the response.
        const apiSize = typeof parsed?.size === "number" ? parsed.size : 0;
        if (apiSize > maxBytes) {
            return {
                ok: true,
                path,
                sizeBytes: apiSize,
                blobSha,
                contentTooLarge: true,
                note: `text/binary file exceeds ${maxBytes} bytes (size from contents API: ${apiSize}); metadata-only response. To inspect content, request a smaller file or accept a partial preview via a different tool.`,
            };
        }
        const blobRaw = runGh(["api", `repos/${owner}/${repo}/git/blobs/${blobSha}`, "-H", "Accept: application/vnd.github+json"]);
        const blobParsed = JSON.parse(blobRaw);
        if (blobParsed?.encoding !== "base64") {
            throw new Error(`blobs endpoint returned unexpected encoding ${blobParsed?.encoding} for ${path}`);
        }
        const cleanB64Blob = String(blobParsed.content || "").replace(/\s/g, "");
        buf = Buffer.from(cleanB64Blob, "base64");
    } else if (parsed?.encoding === "base64") {
        const cleanB64 = String(parsed.content || "").replace(/\s/g, "");
        buf = Buffer.from(cleanB64, "base64");
    } else {
        throw new Error(`unexpected encoding ${parsed?.encoding} for ${path}`);
    }

    const sizeBytes = buf.length;
    const sha256 = createHash("sha256").update(buf).digest("hex");

    // v4.2 hardening: binary detection runs FIRST and scans the WHOLE buffer
    // (not just first 8KB). A polyglot file with clean ASCII in its first
    // 8KB followed by binary payload would have been mis-classified as text
    // and the attacker would get up to maxTextBytes of binary payload back
    // as a UTF-8 string in the response (a runtime-spill vector). Scanning
    // the whole buffer for null bytes catches that. Cost: O(N) memory scan
    // on every fetch — fine for a single file at our 5MB ceiling.
    //
    // Also detect binary by file extension (defense-in-depth against
    // null-byte-free binary formats like JSE/VBE encoded scripts, custom
    // packers, etc.). The extension list is conservative — anything that
    // smells like an executable/library/cert/installer/archive.
    const isBinary = classifyAsBinary(buf, path);

    if (isBinary) {
        return {
            ok: true,
            path,
            sizeBytes,
            sha256,
            encoding: "binary",
            contentReturned: false,
            previewBase64: buf.subarray(0, binaryPreviewBytes).toString("base64"),
            note: `binary content not returned (v4.1 hardening — bytes-on-disk minimization). previewBase64 is the first ${binaryPreviewBytes} bytes for magic-byte / file-type inspection only. Surface sizeBytes + sha256 in the report; do not request the full content.`,
        };
    }

    // v4-r2 round-2 hardening (gpt-5.5 R2 F4 high): if classifyAsBinary
    // returned text but the buffer is actually UTF-16-encoded, decode
    // with the right codec. Without this the agent gets garbled bytes
    // (every other char a null) and can't read the script.
    const utf16 = detectUtf16Bom(buf);
    if (utf16) {
        // TextDecoder handles UTF-16 in all modern Node versions.
        const decoder = new TextDecoder(utf16);
        const decoded = decoder.decode(buf);
        // Hard ceiling check still applies (in chars, conservatively).
        if (sizeBytes > maxBytes) {
            return {
                ok: true,
                path,
                sizeBytes,
                sha256,
                contentTooLarge: true,
                previewBase64: buf.subarray(0, previewBytes).toString("base64"),
                note: `text file exceeds ${maxBytes} bytes; only sha256 + ${previewBytes}-byte preview returned`,
            };
        }
        // Truncate by char count if over inline cap (UTF-16 is 2 bytes
        // per BMP char, so maxTextBytes/2 is the rough character cap).
        const charCap = Math.floor(maxTextBytes / 2);
        if (decoded.length > charCap) {
            return {
                ok: true,
                path,
                sizeBytes,
                sha256,
                encoding: utf16,
                contentReturned: true,
                textTruncated: true,
                text: decoded.substring(0, charCap),
                note: `text content (${utf16}) truncated to ${charCap} chars; full sizeBytes is ${sizeBytes}.`,
            };
        }
        return {
            ok: true,
            path,
            sizeBytes,
            sha256,
            encoding: utf16,
            contentReturned: true,
            text: decoded,
        };
    }

    // Hard ceiling for TEXT files (binaries already returned above).
    if (sizeBytes > maxBytes) {
        return {
            ok: true,
            path,
            sizeBytes,
            sha256,
            contentTooLarge: true,
            previewBase64: buf.subarray(0, previewBytes).toString("base64"),
            note: `text file exceeds ${maxBytes} bytes; only sha256 + ${previewBytes}-byte preview returned`,
        };
    }

    // Text path: if file is over the inline cap, truncate. Source files
    // are almost always under 256KB; this only kicks in for vendored
    // .min.js, generated JSON, etc.
    if (sizeBytes > maxTextBytes) {
        return {
            ok: true,
            path,
            sizeBytes,
            sha256,
            encoding: "utf-8",
            contentReturned: true,
            textTruncated: true,
            text: buf.subarray(0, maxTextBytes).toString("utf-8"),
            note: `text content truncated to ${maxTextBytes} bytes; full sizeBytes is ${sizeBytes}. Hash matches the FULL file. To inspect bytes past the truncation point, request a specific path subrange via a follow-up call (not yet implemented; for now, treat the truncation as a finding worth noting).`,
        };
    }
    return {
        ok: true,
        path,
        sizeBytes,
        sha256,
        encoding: "utf-8",
        contentReturned: true,
        text: buf.toString("utf-8"),
    };
}

export const __internals = {
    OWNER_RE,
    REPO_RE,
    SHA_RE,
    REPO_PATH_RE,
    ensureValidOwnerRepo,
    ensureValidSha,
    ensureValidPath,
    GH_TIMEOUT_MS,
};
