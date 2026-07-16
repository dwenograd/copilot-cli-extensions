// localPathValidator.mjs — pure validation for local-path targets.
//
// Mirrors the shape of urlParser.mjs but for filesystem paths instead
// of GitHub URLs. No I/O beyond fs.statSync / fs.lstatSync — fully
// unit-testable in isolation.
//
// Threat model: local_path is operator-supplied. We need to:
// - Reject anything that isn't an absolute path on this machine
// - Reject UNC paths and the \\?\ prefix (different containment semantics)
// - Reject paths containing .. segments (defense against
//   C:\foo\..\..\..\Windows\System32 style escape)
// - Reject paths that look like credential stores (anything under
//   ~/.ssh, .aws, .docker, .kube, .gnupg, .password-store, Windows
//   Credential Manager / Vault)
// - Reject symlinks at the root (refuse to follow operator-supplied
//   symlinks at the audit root)
// - Verify the path actually exists and is a directory
//
// Returns either:
//   { ok: true, resolved: <canonical absolute path>, slug: <fs-safe slug> }
//   { ok: false, error: <reason> }

import nodePath from "node:path";
import { lstatSync, statSync } from "node:fs";

const MAX_LEN = 2048;

// Credential-store path patterns. Mirrors and EXTENDS the list in
// _shared/schemas.mjs (which validates free-text schema fields).
// Kept local because:
//   1. This is a filesystem-path-shape check, not a free-text-content check;
//      the semantics differ (substring vs full path).
//   2. Windows-specific credential paths are added here that aren't in the
//      shared list (Credential Manager, Vault, etc.).
// If you add to either list, consider whether the other needs the same entry.
const CREDENTIAL_PATH_PATTERNS = [
    // POSIX-style credential paths (operator may symlink-mount via WSL etc.)
    { label: "~/.ssh", pattern: /~[/\\]\.ssh(?:[/\\]|$)/i },
    { label: ".ssh/", pattern: /[/\\]\.ssh(?:[/\\]|$)/i },
    { label: "id_rsa", pattern: /[/\\]id_rsa/i },
    { label: "id_ed25519", pattern: /[/\\]id_ed25519/i },
    { label: "id_ecdsa", pattern: /[/\\]id_ecdsa/i },
    { label: "id_dsa", pattern: /[/\\]id_dsa/i },
    { label: "~/.aws", pattern: /~[/\\]\.aws(?:[/\\]|$)/i },
    { label: ".aws/", pattern: /[/\\]\.aws(?:[/\\]|$)/i },
    { label: "~/.docker", pattern: /~[/\\]\.docker(?:[/\\]|$)/i },
    { label: ".docker/", pattern: /[/\\]\.docker(?:[/\\]|$)/i },
    { label: "~/.kube", pattern: /~[/\\]\.kube(?:[/\\]|$)/i },
    { label: ".kube/", pattern: /[/\\]\.kube(?:[/\\]|$)/i },
    { label: "~/.gnupg", pattern: /~[/\\]\.gnupg(?:[/\\]|$)/i },
    { label: ".gnupg/", pattern: /[/\\]\.gnupg(?:[/\\]|$)/i },
    { label: "~/.password-store", pattern: /~[/\\]\.password-store(?:[/\\]|$)/i },
    { label: ".password-store/", pattern: /[/\\]\.password-store(?:[/\\]|$)/i },
    { label: ".npmrc", pattern: /[/\\]\.npmrc(?:[/\\]|$)/i },
    { label: "kubeconfig", pattern: /[/\\]kubeconfig(?:[/\\]|$)/i },
    // Windows-specific
    { label: "Microsoft\\Credentials", pattern: /[/\\]Microsoft[/\\]Credentials(?:[/\\]|$)/i },
    { label: "Microsoft\\Vault", pattern: /[/\\]Microsoft[/\\]Vault(?:[/\\]|$)/i },
    { label: "Microsoft\\Protect", pattern: /[/\\]Microsoft[/\\]Protect(?:[/\\]|$)/i },
];

export function pathLooksLikeCredentialStore(path) {
    return CREDENTIAL_PATH_PATTERNS.find(({ pattern }) => pattern.test(path));
}

function hasParentSegment(p) {
    // After resolve(), .. segments shouldn't remain — but we also check the
    // input shape pre-resolve to catch tricks like Forward/back\../.. that
    // might survive some normalizers.
    return p.split(/[\\/]+/).some((seg) => seg === "..");
}

/**
 * Compute a filesystem-safe slug from the path's basename. Used in the
 * report directory name. Never empty (falls back to "root").
 *
 *   "/home/you/projects/my-project"      -> "my-project"
 *   "C:\\Users\\you\\Some Weird Name!"   -> "some-weird-name-"
 *   "/"                                   -> "root"  (basename empty)
 *   "/home/you/projects/foo.bar.baz"     -> "foo.bar.baz"
 */
export function slugForPath(resolved) {
    const base = nodePath.basename(resolved) || "root";
    let slug = base.toLowerCase()
        // Allow [a-z0-9._-]; anything else becomes a hyphen.
        .replace(/[^a-z0-9._-]+/g, "-")
        // Collapse consecutive hyphens.
        .replace(/-{2,}/g, "-")
        // Trim leading/trailing hyphens or dots (hidden-file friendliness).
        .replace(/^[-.]+|[-.]+$/g, "");
    if (!slug) slug = "root";
    if (slug.length > 60) slug = slug.slice(0, 60).replace(/-+$/, "") || "root";
    return slug;
}

/**
 * Validate an operator-supplied local path.
 *
 * @param {unknown} input  the local_path argument
 * @returns {{ ok: true, resolved: string, slug: string } | { ok: false, error: string }}
 */
export function validateLocalPath(input) {
    if (typeof input !== "string" || input.length === 0) {
        return { ok: false, error: "local_path must be a non-empty string" };
    }
    if (input.length > MAX_LEN) {
        return { ok: false, error: `local_path too long (>${MAX_LEN} chars)` };
    }

    // Reject UNC paths (\\server\share\...) and the \\?\ long-path prefix.
    // UNC paths have totally different containment semantics — symlinks
    // resolved across the SMB share could escape in ways we can't reason
    // about. \\?\ disables path normalization which defeats our `..` check.
    if (/^\\\\/.test(input) || /^\\\\\?\\/.test(input)) {
        return { ok: false, error: "local_path: UNC and \\\\?\\ paths are not supported" };
    }

    if (!nodePath.isAbsolute(input)) {
        return { ok: false, error: "local_path must be an absolute path" };
    }

    // Pre-resolve `..` check — if the input contains .. segments, reject
    // before resolve() silently collapses them. Operator pasting a path
    // with .. is suspicious and we'd rather make it explicit.
    if (hasParentSegment(input)) {
        return { ok: false, error: "local_path must not contain '..' segments" };
    }

    let resolved;
    try {
        resolved = nodePath.resolve(input);
    } catch (err) {
        return { ok: false, error: `local_path resolution failed: ${err.message}` };
    }

    // Post-resolve check — should be a no-op since pre-resolve check passed,
    // but defense-in-depth: if resolve somehow produced a path with .., reject.
    if (hasParentSegment(resolved)) {
        return { ok: false, error: "local_path resolves to a path containing '..'" };
    }

    const credMatch = pathLooksLikeCredentialStore(resolved);
    if (credMatch) {
        return {
            ok: false,
            error: `local_path: blocked credential-store path (matched: ${credMatch.label}). ` +
                   "If you genuinely need to audit credential storage, copy the relevant " +
                   "files to a non-credential-store path first.",
        };
    }

    // Existence + type checks via fs. Use lstat first to detect a root-level
    // symlink before stat (which would follow it).
    let lstats;
    try {
        lstats = lstatSync(resolved);
    } catch (err) {
        if (err && err.code === "ENOENT") {
            return { ok: false, error: `local_path does not exist: ${resolved}` };
        }
        return { ok: false, error: `local_path lstat failed: ${err.message}` };
    }

    if (lstats.isSymbolicLink()) {
        return {
            ok: false,
            error: `local_path: root is a symbolic link. Pass the canonical absolute path ` +
                   `of the symlink target instead (we refuse to follow operator-supplied ` +
                   `root symlinks to keep the audit scope unambiguous).`,
        };
    }

    let stats;
    try {
        stats = statSync(resolved);
    } catch (err) {
        return { ok: false, error: `local_path stat failed: ${err.message}` };
    }

    if (!stats.isDirectory()) {
        return { ok: false, error: `local_path must be a directory (got ${stats.isFile() ? "file": "non-directory"})` };
    }

    const slug = slugForPath(resolved);

    return { ok: true, resolved, slug };
}

// Exported for unit tests; not part of the public surface.
export const __internals = {
    CREDENTIAL_PATH_PATTERNS,
    hasParentSegment,
    MAX_LEN,
};
