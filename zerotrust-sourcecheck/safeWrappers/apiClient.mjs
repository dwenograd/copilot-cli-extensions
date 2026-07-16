// safeWrappers/apiClient.mjs
//
// Pure helper around `gh api` for API-direct audits. It does not intentionally
// create source files; Copilot CLI/tool-result logging is outside this module.
//
// Why `gh api` and not raw HTTPS:
//   - Re-uses the operator's existing GitHub authentication (5000 req/hr
//     authenticated vs. 60 req/hr unauth).
//   - `gh` is already installed (it's the documented dependency for the
//     wider extension).
//   - Avoids needing to bundle an HTTP client; execFileSync is simpler.
//
// Trust model:
//   - All `gh` invocations go through resolveTrustedProgram so a
//     repo-planted `gh.cmd` cannot shadow-execute.
//   - File contents are returned through the tool result. This module performs
//     no source-file write, but host/runtime output retention is out of scope.
//   - There is a per-fetch byte cap (configurable). Above the cap, the
//     response stays bounded and mandatory coverage remains incomplete.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

import {
    GIT_TREE_MODES,
    classifyGitTreeEntry,
    computeGitBlobSha1,
    parseGitLfsPointer,
    parseGitSymlinkTarget,
    verifyGitBlobSha1,
} from "../analysis/objectInventory.mjs";
import { resolveTrustedProgram } from "./programResolver.mjs";

// Per-fetch caps:
//   - DEFAULT_MAX_FILE_BYTES (5MB): hard ceiling for mandatory completion.
//     Over-ceiling responses stay bounded and remain coverage gaps.
//   - DEFAULT_TEXT_INLINE_BYTES (256KB): max text content returned inline.
//     Larger TEXT files get truncated to this size with a `truncated: true`
//     marker. Most source files are well under 256KB.
//   - BINARY_PREVIEW_BYTES (256): magic-byte preview for binaries. Just
//     enough to confirm file type (PE "MZ", ELF "\x7fELF", ZIP "PK\x03\x04",
//     etc.) without returning the full binary.
//
// Binary content is never returned in full (no `base64`
// field). The agent gets size + sha256 + magic-byte preview only. This
// closes the spill-via-runtime-temp-file attack: a 552KB malware .exe
// previously would have returned ~750KB of base64 in the JSON response,
// which the Copilot CLI runtime spills to %LOCALAPPDATA%\Temp\copilot-
// tool-output-*.txt, where Defender then sees it. With this security,
// the response for that .exe is ~400 bytes — way under any spill threshold.
export const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
export const DEFAULT_TEXT_INLINE_BYTES = 256 * 1024;   // 256 KB
export const DEFAULT_PREVIEW_BYTES = 4096;             // first 4 KB of >maxBytes files
export const BINARY_PREVIEW_BYTES = 256;               // magic-byte preview for binaries
const GH_TIMEOUT_MS = 60_000;

const OWNER_RE = /^[A-Za-z0-9._-]{1,100}$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
// Path inside repo: forward-slash-separated, no controls or backslashes.
// Individual path segments are URL-encoded before calling the Contents API.
const REPO_PATH_RE = /^[^\u0000-\u001f\u007f\\]+$/u;

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
    if (typeof path !== "string" || path.length < 1 || path.length > 1024
        || !REPO_PATH_RE.test(path)) {
        throw new Error(`invalid repo path: ${JSON.stringify(path)}`);
    }
    if (path.startsWith("/") || path.endsWith("/") || path.includes("//")
        || path.split("/").some((segment) => segment === "." || segment === "..")) {
        throw new Error(`repo path has traversal / leading-trailing slash / double slash: ${JSON.stringify(path)}`);
    }
}

function encodeRepoPath(path) {
    ensureValidPath(path);
    return path.split("/").map(encodeURIComponent).join("/");
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
        const stderr = err.stderr ? String(err.stderr): "";
        throw new Error(`gh ${args[0]} failed: ${err.message}${stderr ? `\nstderr: ${stderr.slice(-500)}`: ""}`);
    }
    return stdout;
}

function requestApiJson(apiPath, requestJson) {
    if (typeof requestJson === "function") return requestJson(apiPath);
    return JSON.parse(runGh(["api", apiPath]));
}

function ensureValidRef(ref) {
    if (typeof ref !== "string" || !/^[A-Za-z0-9._/\-]{1,255}$/.test(ref)) {
        throw new Error(`invalid ref: ${JSON.stringify(ref)}`);
    }
    if (ref.startsWith("/") || ref.endsWith("/") || ref.includes("//")
        || ref.split("/").some((segment) => segment === "." || segment === "..")) {
        throw new Error(`invalid ref path: ${JSON.stringify(ref)}`);
    }
}

function refPath(ref) {
    ensureValidRef(ref);
    return ref.split("/").map(encodeURIComponent).join("/");
}

export function getCommitIdentity(owner, repo, sha, { requestJson } = {}) {
    ensureValidOwnerRepo(owner, repo);
    ensureValidSha(sha);
    const parsed = requestApiJson(`repos/${owner}/${repo}/git/commits/${sha}`, requestJson);
    const commitSha = parsed?.sha;
    const rootTreeSha = parsed?.tree?.sha;
    if (!SHA_RE.test(commitSha || "") || commitSha.toLowerCase() !== sha.toLowerCase()) {
        throw new Error(`commit identity mismatch: requested ${sha}, API returned ${JSON.stringify(commitSha)}`);
    }
    if (!SHA_RE.test(rootTreeSha || "")) {
        throw new Error(`commit ${sha} response did not include a valid tree.sha`);
    }
    return { commitSha: commitSha.toLowerCase(), rootTreeSha: rootTreeSha.toLowerCase() };
}

function resolveTagReference(owner, repo, tagName, { requestJson, maxPeelDepth = 8 } = {}) {
    ensureValidOwnerRepo(owner, repo);
    ensureValidRef(tagName);
    const expectedRef = `refs/tags/${tagName}`;
    const refInfo = requestApiJson(
        `repos/${owner}/${repo}/git/refs/tags/${refPath(tagName)}`,
        requestJson,
    );
    if (refInfo?.ref !== expectedRef) {
        throw new Error(`tag ref mismatch: requested ${expectedRef}, API returned ${JSON.stringify(refInfo?.ref)}`);
    }

    const tagRefSha = refInfo?.object?.sha;
    let objectSha = tagRefSha;
    let objectType = refInfo?.object?.type;
    if (!SHA_RE.test(objectSha || "")) {
        throw new Error(`tag ${tagName} response did not include a valid object.sha`);
    }

    const seen = new Set();
    let peelDepth = 0;
    let tagObjectSha = null;
    while (objectType === "tag") {
        if (peelDepth >= maxPeelDepth) {
            throw new Error(`annotated tag ${tagName} exceeds peel-depth limit ${maxPeelDepth}`);
        }
        const normalized = objectSha.toLowerCase();
        if (seen.has(normalized)) throw new Error(`annotated tag ${tagName} contains a peel cycle`);
        seen.add(normalized);
        if (!tagObjectSha) tagObjectSha = normalized;

        const tagObject = requestApiJson(
            `repos/${owner}/${repo}/git/tags/${normalized}`,
            requestJson,
        );
        objectSha = tagObject?.object?.sha;
        objectType = tagObject?.object?.type;
        if (!SHA_RE.test(objectSha || "")) {
            throw new Error(`annotated tag object ${normalized} did not include a valid target sha`);
        }
        peelDepth += 1;
    }
    if (objectType !== "commit") {
        throw new Error(`tag ${tagName} resolves to ${JSON.stringify(objectType)}, not a commit`);
    }

    return {
        tagName,
        tagRefSha: tagRefSha.toLowerCase(),
        tagObjectSha,
        annotated: peelDepth > 0,
        peelDepth,
        commitSha: objectSha.toLowerCase(),
    };
}

export function resolveReleaseIdentity(owner, repo, {
    requestedTag = null,
    requestJson,
} = {}) {
    ensureValidOwnerRepo(owner, repo);
    if (requestedTag !== null) ensureValidRef(requestedTag);

    const releaseEndpoint = requestedTag
        ? `repos/${owner}/${repo}/releases/tags/${refPath(requestedTag)}`: `repos/${owner}/${repo}/releases/latest`;
    const release = requestApiJson(releaseEndpoint, requestJson);
    const releaseId = release?.id;
    if ((!Number.isSafeInteger(releaseId) || releaseId <= 0)
        && !(typeof releaseId === "string" && /^[1-9][0-9]{0,19}$/.test(releaseId))) {
        throw new Error(`release response did not include a valid positive id`);
    }
    const tagName = release?.tag_name;
    ensureValidRef(tagName);
    if (requestedTag !== null && tagName !== requestedTag) {
        throw new Error(`release tag mismatch: requested ${JSON.stringify(requestedTag)}, API returned ${JSON.stringify(tagName)}`);
    }

    const tag = resolveTagReference(owner, repo, tagName, { requestJson });
    const commit = getCommitIdentity(owner, repo, tag.commitSha, { requestJson });
    let targetCommitish = null;
    if (typeof release?.target_commitish === "string") {
        try {
            ensureValidRef(release.target_commitish);
            targetCommitish = release.target_commitish;
        } catch {
            targetCommitish = null;
        }
    }
    return {
        releaseId: String(releaseId),
        tagName,
        targetCommitish,
        sourceCommitSha: commit.commitSha,
        rootTreeSha: commit.rootTreeSha,
        tagRefSha: tag.tagRefSha,
        tagObjectSha: tag.tagObjectSha,
        annotatedTag: tag.annotated,
        tagPeelDepth: tag.peelDepth,
    };
}

/**
 * Resolve a ref (branch / tag / SHA / HEAD) to a final commit SHA.
 * Annotated tags are peeled until a commit is reached; tag-object SHAs are
 * never accepted as source identities.
 */
export function resolveRefToSha(owner, repo, ref, refType, { requestJson } = {}) {
    ensureValidOwnerRepo(owner, repo);
    if (refType === "commit" || (typeof ref === "string" && SHA_RE.test(ref))) {
        ensureValidSha(ref);
        return ref.toLowerCase();
    }

    const refToResolve = ref || "HEAD";
    ensureValidRef(refToResolve);

    if (refToResolve === "HEAD") {
        const repoMeta = requestApiJson(`repos/${owner}/${repo}`, requestJson);
        const defaultBranch = repoMeta?.default_branch;
        ensureValidRef(defaultBranch);
        const branchInfo = requestApiJson(
            `repos/${owner}/${repo}/branches/${refPath(defaultBranch)}`,
            requestJson,
        );
        const sha = branchInfo?.commit?.sha;
        if (!SHA_RE.test(sha || "")) {
            throw new Error(`could not resolve HEAD for ${owner}/${repo} (default branch ${defaultBranch})`);
        }
        return sha.toLowerCase();
    }

    if (refType === "pr_head") {
        const match = refToResolve.match(/^refs\/pull\/(\d+)\/head$/);
        if (!match) throw new Error(`pr_head ref must be refs/pull/<n>/head, got ${JSON.stringify(refToResolve)}`);
        const parsed = requestApiJson(`repos/${owner}/${repo}/pulls/${match[1]}`, requestJson);
        const sha = parsed?.head?.sha;
        if (!SHA_RE.test(sha || "")) throw new Error(`PR API response missing head.sha`);
        return sha.toLowerCase();
    }

    if (refType === "release_tag") {
        return resolveTagReference(owner, repo, refToResolve, { requestJson }).commitSha;
    }

    let branchError;
    try {
        const parsed = requestApiJson(
            `repos/${owner}/${repo}/git/refs/heads/${refPath(refToResolve)}`,
            requestJson,
        );
        const expectedRef = `refs/heads/${refToResolve}`;
        if (parsed?.ref !== expectedRef) {
            throw new Error(`branch ref mismatch: requested ${expectedRef}, API returned ${JSON.stringify(parsed?.ref)}`);
        }
        if (parsed?.object?.type !== "commit" || !SHA_RE.test(parsed?.object?.sha || "")) {
            throw new Error(`branch ${refToResolve} did not resolve to a commit`);
        }
        return parsed.object.sha.toLowerCase();
    } catch (err) {
        branchError = err;
    }

    try {
        return resolveTagReference(owner, repo, refToResolve, { requestJson }).commitSha;
    } catch (tagError) {
        throw new Error(`could not resolve ref ${JSON.stringify(refToResolve)} for ${owner}/${repo}: branch=${branchError.message}; tag=${tagError.message}`);
    }
}

/**
 * List one tree object. The response SHA must exactly match the requested
 * discovered tree SHA; callers use this to reject arbitrary-tree substitution.
 */
export const DEFAULT_MAX_ENTRIES = 5000;
export const DEFAULT_MAX_DISCOVERED_SUBTREES = 10_000;

export function listTreeBySha(owner, repo, treeSha, {
    recursive = true,
    maxEntries = DEFAULT_MAX_ENTRIES,
    maxDiscoveredSubtrees = DEFAULT_MAX_DISCOVERED_SUBTREES,
    requestJson,
} = {}) {
    ensureValidOwnerRepo(owner, repo);
    ensureValidSha(treeSha);
    const apiPath = `repos/${owner}/${repo}/git/trees/${treeSha}${recursive ? "?recursive=1": ""}`;
    const parsed = requestApiJson(apiPath, requestJson);
    if (!SHA_RE.test(parsed?.sha || "") || parsed.sha.toLowerCase() !== treeSha.toLowerCase()) {
        throw new Error(`tree identity mismatch: requested ${treeSha}, API returned ${JSON.stringify(parsed?.sha)}`);
    }
    const allEntries = Array.isArray(parsed?.tree) ? parsed.tree: [];
    const normalizedEntries = allEntries.map((entry) => {
        if (typeof entry?.path !== "string" || entry.path.length < 1 || entry.path.length > 1024
            || /[\u0000-\u001f\u007f\\]/u.test(entry.path)
            || entry.path.startsWith("/") || entry.path.endsWith("/") || entry.path.includes("//")
            || entry.path.split("/").some((segment) => segment === "." || segment === "..")) {
            throw new Error(`tree response contained an invalid path`);
        }
        if (!["blob", "tree", "commit"].includes(entry?.type) || !SHA_RE.test(entry?.sha || "")) {
            throw new Error(`tree response contained an invalid entry for ${JSON.stringify(entry?.path)}`);
        }
        const objectClassification = classifyGitTreeEntry({
            type: entry.type,
            mode: entry.mode,
        });
        return {
            path: entry.path,
            type: entry.type,
            mode: objectClassification.mode,
            modeInferred: objectClassification.modeInferred,
            objectKind: objectClassification.objectKind,
            executable: objectClassification.executable,
            size: Number.isSafeInteger(entry.size) && entry.size >= 0 ? entry.size: 0,
            sha: entry.sha.toLowerCase(),
        };
    });

    const discovered = normalizedEntries.filter((entry) => entry.type === "tree");
    return {
        treeSha: treeSha.toLowerCase(),
        recursive: !!recursive,
        truncated: !!parsed?.truncated,
        entriesTruncated: normalizedEntries.length > maxEntries,
        totalEntryCount: normalizedEntries.length,
        entries: normalizedEntries.slice(0, maxEntries),
        discoveredSubtrees: discovered.slice(0, maxDiscoveredSubtrees),
        discoveryTruncated: discovered.length > maxDiscoveredSubtrees,
    };
}

/**
 * Fetch a single file's contents at the given SHA. See header for return shapes.
 *
 * Classification is based on the fetched bytes, never the filename suffix.
 * Known binary extensions remain available as an ordering hint only.
 */

// This suffix list is deliberately non-authoritative. It may prioritize likely
// binaries for fetch order, but it must never suppress byte acquisition or
// force binary classification: plain text named payload.exe/payload.png is
// source text and must receive the deterministic text scan.
const BINARY_EXT_RE = /\.(?:exe|dll|so|dylib|msi|deploy|pfx|p12|p7s|p7b|cer|crt|der|pyd|wasm|class|jar|war|ear|nupkg|whl|egg|zip|tar|gz|bz2|xz|7z|rar|cab|iso|dmg|pkg|appx|msix|ipa|apk|aab|jse|vbe|scr|cpl|com|ico|cur|ani|ttf|otf|woff|woff2|eot|jpg|jpeg|png|gif|bmp|webp|tiff|psd|mp3|mp4|mov|avi|wmv|flv|mkv|ogg|opus|wav|flac|pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|sqlite|db|mdb|bin)$/i;

export function isKnownBinaryPath(path) {
    return BINARY_EXT_RE.test(String(path || ""));
}

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
    return classifyActualBytes(buf, path).kind === "binary";
}

function classifyActualBytes(buf, path) {
    const utf16 = detectUtf16Bom(buf);
    if (utf16) {
        try {
            new TextDecoder(utf16, { fatal: true }).decode(buf);
            return { kind: "text", reason: `${utf16}_bom` };
        } catch {
            return { kind: "unknown", reason: `invalid_${utf16}` };
        }
    }

    if (hasBinaryMagic(buf)) {
        return { kind: "binary", reason: "binary_magic" };
    }

    try {
        new TextDecoder("utf-8", { fatal: true }).decode(buf);
        return {
            kind: "text",
            reason: isKnownBinaryPath(path)
                ? "valid_text_bytes_despite_binary_suffix": "valid_utf8",
        };
    } catch {
        // Invalid UTF-8 alone is not evidence of binary content. A script or
        // batch file with one damaged byte must remain unclassified rather
        // than being lossy-decoded or accepted as a verified binary.
    }

    let nullBytes = 0;
    let strongControlBytes = 0;
    for (const byte of buf) {
        if (byte === 0x00) nullBytes += 1;
        if (byte === 0x00
            || (byte >= 0x01 && byte <= 0x08)
            || byte === 0x0B
            || (byte >= 0x0E && byte <= 0x1A)
            || (byte >= 0x1C && byte <= 0x1F)
            || byte === 0x7F) {
            strongControlBytes += 1;
        }
    }

    const minimumStrongEvidence = Math.max(4, Math.ceil(buf.length * 0.10));
    if ((nullBytes >= 2 && nullBytes >= Math.ceil(buf.length * 0.02))
        || strongControlBytes >= minimumStrongEvidence) {
        return { kind: "binary", reason: "strong_binary_byte_evidence" };
    }

    return {
        kind: "unknown",
        reason: "invalid_utf8_without_structural_binary_evidence",
    };
}

const BINARY_MAGICS = Object.freeze([
    Buffer.from([0x7F, 0x45, 0x4C, 0x46]),             // ELF
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), // PNG
    Buffer.from([0xFF, 0xD8, 0xFF]),                   // JPEG
    Buffer.from("GIF87a", "ascii"),
    Buffer.from("GIF89a", "ascii"),
    Buffer.from("%PDF-", "ascii"),
    Buffer.from([0x50, 0x4B, 0x03, 0x04]),             // ZIP
    Buffer.from([0x50, 0x4B, 0x05, 0x06]),
    Buffer.from([0x50, 0x4B, 0x07, 0x08]),
    Buffer.from([0x1F, 0x8B]),                         // gzip
    Buffer.from("BZh", "ascii"),
    Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), // 7z
    Buffer.from("Rar!\x1A\x07", "binary"),
    Buffer.from("MSCF", "ascii"),                      // CAB
    Buffer.from([0x00, 0x61, 0x73, 0x6D]),             // WebAssembly
    Buffer.from("SQLite format 3\x00", "binary"),
    Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]), // OLE
    Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]),             // Java class / Mach-O
    Buffer.from([0xFE, 0xED, 0xFA, 0xCE]),             // Mach-O
    Buffer.from([0xFE, 0xED, 0xFA, 0xCF]),
    Buffer.from([0xCE, 0xFA, 0xED, 0xFE]),
    Buffer.from([0xCF, 0xFA, 0xED, 0xFE]),
]);

function hasBinaryMagic(buf) {
    // A two-byte "MZ" prefix alone is not sufficient: executable-looking
    // script text can begin with those ASCII bytes. Require the PE signature
    // at the DOS header's bounded e_lfanew offset.
    if (buf.length >= 64 && buf[0] === 0x4D && buf[1] === 0x5A) {
        const peOffset = buf.readUInt32LE(0x3C);
        if (peOffset >= 64
            && peOffset <= buf.length - 4
            && buf.subarray(peOffset, peOffset + 4).equals(Buffer.from([0x50, 0x45, 0x00, 0x00]))) {
            return true;
        }
    }
    if (BINARY_MAGICS.some((magic) =>
        buf.length >= magic.length && buf.subarray(0, magic.length).equals(magic))) {
        return true;
    }
    if (buf.length >= 12 && buf.subarray(0, 4).toString("ascii") === "RIFF") {
        const subtype = buf.subarray(8, 12).toString("ascii");
        return ["WAVE", "AVI ", "WEBP"].includes(subtype);
    }
    return false;
}

const FETCH_ANALYSIS_BYTES = Symbol("zerotrust.fetch-analysis-bytes");

function attachFetchAnalysisBytes(result, buffer) {
    Object.defineProperty(result, FETCH_ANALYSIS_BYTES, {
        value: Buffer.from(buffer),
        enumerable: false,
        configurable: true,
        writable: false,
    });
    return result;
}

export function takeFetchAnalysisBytes(result) {
    const buffer = result?.[FETCH_ANALYSIS_BYTES] || null;
    if (buffer) delete result[FETCH_ANALYSIS_BYTES];
    return buffer;
}

function buildFetchResultFromBuffer(path, buf, {
    blobSha = null,
    gitMode = null,
    verifyGitBlobSha = false,
    maxBytes = DEFAULT_MAX_FILE_BYTES,
    maxTextBytes = DEFAULT_TEXT_INLINE_BYTES,
    previewBytes = DEFAULT_PREVIEW_BYTES,
    binaryPreviewBytes = BINARY_PREVIEW_BYTES,
} = {}) {
    if (!Buffer.isBuffer(buf)) throw new Error("buildFetchResultFromBuffer requires a Buffer");
    const gitClassification = gitMode === null
        ? null: classifyGitTreeEntry({ type: "blob", mode: gitMode });
    const sizeBytes = buf.length;
    const sha256 = createHash("sha256").update(buf).digest("hex");
    const gitBlobSha1 = computeGitBlobSha1(buf);
    const normalizedBlobSha = typeof blobSha === "string"
        ? blobSha.toLowerCase(): null;
    if (verifyGitBlobSha) {
        verifyGitBlobSha1(buf, normalizedBlobSha, path);
    }
    const classification = classifyActualBytes(buf, path);
    const symlinkTarget = gitMode === GIT_TREE_MODES.SYMLINK
        ? parseGitSymlinkTarget(buf): null;
    const lfsPointer = parseGitLfsPointer(buf);
    const common = {
        ok: true,
        path,
        sizeBytes,
        sha256,
        ...(normalizedBlobSha ? { blobSha: normalizedBlobSha }: {}),
        gitBlobSha1,
        gitBlobSha1Verified: normalizedBlobSha !== null
            && gitBlobSha1 === normalizedBlobSha,
        gitMode: gitClassification?.mode || null,
        gitObjectKind: gitClassification?.objectKind || null,
        executable: gitClassification?.executable === true,
        symlinkTarget,
        lfsPointer,
        classification: classification.kind,
        classificationComplete: classification.kind !== "unknown",
        classificationReason: classification.reason,
        classificationBytesInspected: sizeBytes,
        likelyBinaryByExtension: isKnownBinaryPath(path),
    };

    if (sizeBytes > maxBytes) {
        const cap = classification.kind === "binary" ? binaryPreviewBytes: previewBytes;
        const preview = buf.subarray(0, cap);
        return attachFetchAnalysisBytes({
            ...common,
            ...(classification.kind === "binary" ? { encoding: "binary" }: {}),
            contentTooLarge: true,
            contentReturned: false,
            previewBase64: preview.toString("base64"),
            previewByteCount: preview.length,
            note: `${classification.kind} file exceeds ${maxBytes} bytes; bounded metadata/preview returned and mandatory acquisition remains incomplete.`,
        }, buf);
    }

    if (classification.kind === "binary") {
        const preview = buf.subarray(0, binaryPreviewBytes);
        return attachFetchAnalysisBytes({
            ...common,
            encoding: "binary",
            contentReturned: false,
            previewBase64: preview.toString("base64"),
            previewByteCount: preview.length,
            note: `binary content not returned (bytes-on-disk minimization). previewBase64 is the first ${preview.length} bytes for magic-byte / file-type inspection only.`,
        }, buf);
    }

    if (classification.kind === "unknown") {
        const preview = buf.subarray(0, previewBytes);
        return attachFetchAnalysisBytes({
            ...common,
            contentReturned: false,
            previewBase64: preview.toString("base64"),
            previewByteCount: preview.length,
            note: "bytes are neither valid supported text nor structurally verified binary; bounded preview returned without lossy decoding, and mandatory acquisition remains incomplete.",
        }, buf);
    }

    const utf16 = detectUtf16Bom(buf);
    if (utf16) {
        const decoded = new TextDecoder(utf16).decode(buf);
        const charCap = Math.floor(maxTextBytes / 2);
        if (decoded.length > charCap) {
            return attachFetchAnalysisBytes({
                ...common,
                encoding: utf16,
                contentReturned: true,
                textTruncated: true,
                text: decoded.substring(0, charCap),
                note: `text content (${utf16}) truncated to ${charCap} chars; full sizeBytes is ${sizeBytes}.`,
            }, buf);
        }
        return attachFetchAnalysisBytes({
            ...common,
            encoding: utf16,
            contentReturned: true,
            text: decoded,
        }, buf);
    }

    if (sizeBytes > maxTextBytes) {
        return attachFetchAnalysisBytes({
            ...common,
            encoding: "utf-8",
            contentReturned: true,
            textTruncated: true,
            text: new TextDecoder("utf-8").decode(buf.subarray(0, maxTextBytes)),
            note: `text content truncated to ${maxTextBytes} bytes; full sizeBytes is ${sizeBytes}. Hash matches the full file.`,
        }, buf);
    }
    return attachFetchAnalysisBytes({
        ...common,
        encoding: "utf-8",
        contentReturned: true,
        text: new TextDecoder("utf-8").decode(buf),
    }, buf);
}

// Exported so fetchFile (and tests) can decide which decoder to use.
export { detectUtf16Bom };

export function fetchFile(owner, repo, sha, path, {
    expectedBlobSha = null,
    expectedSize = null,
    gitMode = null,
    maxBytes = DEFAULT_MAX_FILE_BYTES,
    maxTextBytes = DEFAULT_TEXT_INLINE_BYTES,
    previewBytes = DEFAULT_PREVIEW_BYTES,
    binaryPreviewBytes = BINARY_PREVIEW_BYTES,
} = {}) {
    ensureValidOwnerRepo(owner, repo);
    ensureValidSha(sha);
    const encodedPath = encodeRepoPath(path);
    if (expectedBlobSha !== null) ensureValidSha(expectedBlobSha);
    if (expectedSize !== null
        && (!Number.isSafeInteger(expectedSize) || expectedSize < 0)) {
        throw new Error(`invalid expected blob size for ${path}`);
    }
    if (gitMode !== null) classifyGitTreeEntry({ type: "blob", mode: gitMode });

    if (expectedBlobSha !== null && expectedSize !== null && expectedSize > maxBytes) {
        const gitClassification = gitMode === null
            ? null: classifyGitTreeEntry({ type: "blob", mode: gitMode });
        return {
            ok: true,
            path,
            sizeBytes: expectedSize,
            blobSha: expectedBlobSha.toLowerCase(),
            gitBlobSha1: null,
            gitBlobSha1Verified: false,
            gitMode: gitClassification?.mode || null,
            gitObjectKind: gitClassification?.objectKind || null,
            executable: gitClassification?.executable === true,
            symlinkTarget: null,
            lfsPointer: null,
            classification: "unknown",
            classificationComplete: false,
            classificationBytesInspected: 0,
            likelyBinaryByExtension: isKnownBinaryPath(path),
            contentTooLarge: true,
            contentReturned: false,
            note: `file exceeds ${maxBytes} bytes (size from pinned Git tree: ${expectedSize}); bytes were not fetched, Git blob identity was not recomputed, and mandatory acquisition cannot complete.`,
        };
    }

    if (expectedBlobSha !== null) {
        const raw = runGh([
            "api",
            `repos/${owner}/${repo}/git/blobs/${expectedBlobSha}`,
            "-H",
            "Accept: application/vnd.github+json",
        ]);
        const parsed = JSON.parse(raw);
        if (String(parsed?.sha || "").toLowerCase() !== expectedBlobSha.toLowerCase()) {
            throw new Error(
                `blob identity mismatch for ${path}: requested ${expectedBlobSha}, API returned ${JSON.stringify(parsed?.sha)}`,
            );
        }
        if (parsed?.encoding !== "base64") {
            throw new Error(
                `blobs endpoint returned unexpected encoding ${parsed?.encoding} for ${path}`,
            );
        }
        const buf = Buffer.from(String(parsed.content || "").replace(/\s/gu, ""), "base64");
        if (Number.isSafeInteger(parsed?.size) && parsed.size >= 0
            && parsed.size !== buf.length) {
            throw new Error(
                `blob size mismatch for ${path}: blobs API=${parsed.size}, decoded=${buf.length}`,
            );
        }
        if (expectedSize !== null && expectedSize !== buf.length) {
            throw new Error(
                `blob size mismatch for ${path}: pinned tree=${expectedSize}, decoded=${buf.length}`,
            );
        }
        return buildFetchResultFromBuffer(path, buf, {
            blobSha: expectedBlobSha,
            gitMode,
            verifyGitBlobSha: true,
            maxBytes,
            maxTextBytes,
            previewBytes,
            binaryPreviewBytes,
        });
    }

    // Use the contents API which returns base64-encoded content for any file type.
    const raw = runGh(["api", `repos/${owner}/${repo}/contents/${encodedPath}?ref=${sha}`, "-H", "Accept: application/vnd.github+json"]);
    const parsed = JSON.parse(raw);
    if (parsed?.type !== "file") {
        throw new Error(`expected file at ${path}, got ${parsed?.type || "unknown"}`);
    }
    const blobSha = parsed?.sha;
    if (typeof blobSha !== "string" || !SHA_RE.test(blobSha)) {
        throw new Error(`file ${path} response did not include a valid blob sha`);
    }

    // GitHub's Contents API returns
    // `encoding: "none"` and empty content for files between 1 MB and
    // 100 MB (the API's hard limit for the contents endpoint). The
    // Throwing on this would blind the audit to any file in
    // that size range. Fall back to the blobs endpoint, which always
    // returns base64 for blobs ≤100 MB. The contents response gives
    // us the blob SHA in `parsed.sha`.
    let buf;
    if (parsed?.encoding === "none") {
        // If the file is larger than our absolute ceiling, return
        // metadata-only and classification-incomplete — don't fetch via
        // blobs, since blobs would deliver the full bytes and bloat the response.
        const apiSize = typeof parsed?.size === "number" ? parsed.size: 0;
        if (apiSize > maxBytes) {
            return {
                ok: true,
                path,
                sizeBytes: apiSize,
                blobSha: blobSha.toLowerCase(),
                gitBlobSha1: null,
                gitBlobSha1Verified: false,
                gitMode: null,
                gitObjectKind: null,
                executable: false,
                symlinkTarget: null,
                lfsPointer: null,
                classification: "unknown",
                classificationComplete: false,
                classificationBytesInspected: 0,
                likelyBinaryByExtension: isKnownBinaryPath(path),
                contentTooLarge: true,
                contentReturned: false,
                note: `file exceeds ${maxBytes} bytes (size from contents API: ${apiSize}); bytes were not fetched, classification is incomplete, and mandatory acquisition cannot complete.`,
            };
        }
        const blobRaw = runGh(["api", `repos/${owner}/${repo}/git/blobs/${blobSha}`, "-H", "Accept: application/vnd.github+json"]);
        const blobParsed = JSON.parse(blobRaw);
        if (String(blobParsed?.sha || "").toLowerCase() !== blobSha.toLowerCase()) {
            throw new Error(`blobs endpoint identity mismatch for ${path}`);
        }
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

    if (Number.isSafeInteger(parsed?.size) && parsed.size >= 0 && parsed.size !== buf.length) {
        throw new Error(`file size mismatch for ${path}: contents API=${parsed.size}, decoded=${buf.length}`);
    }
    return buildFetchResultFromBuffer(path, buf, {
        blobSha,
        verifyGitBlobSha: true,
        maxBytes,
        maxTextBytes,
        previewBytes,
        binaryPreviewBytes,
    });
}

export const __internals = {
    OWNER_RE,
    REPO_RE,
    SHA_RE,
    REPO_PATH_RE,
    ensureValidOwnerRepo,
    ensureValidSha,
    ensureValidPath,
    encodeRepoPath,
    ensureValidRef,
    BINARY_EXT_RE,
    isKnownBinaryPath,
    classifyActualBytes,
    buildFetchResultFromBuffer,
    takeFetchAnalysisBytes,
    computeGitBlobSha1,
    verifyGitBlobSha1,
    parseGitSymlinkTarget,
    parseGitLfsPointer,
    resolveTagReference,
    requestApiJson,
    GH_TIMEOUT_MS,
};
