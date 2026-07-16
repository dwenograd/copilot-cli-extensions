import { test } from "node:test";
import assert from "node:assert/strict";

import {
    listTreeBySha,
    resolveReleaseIdentity,
} from "../safeWrappers/apiClient.mjs";
import { safeListTreeHandler } from "../safeWrappers/safeListTreeHandler.mjs";
import {
    activateAudit,
    deactivateAudit,
    getTrustedAuditContext,
} from "../enforcement.mjs";
import { buildQuarantinePath, buildReportPath, parseGithubUrl } from "../urlParser.mjs";
import { DEFAULT_BUILD_ROOT } from "../safeWrappers/defaults.mjs";
import { runHandler } from "../handler.mjs";

const COMMIT = "1".repeat(40);
const ROOT = "2".repeat(40);
const TAG_OBJECT = "3".repeat(40);
const TAG_REF = "4".repeat(40);
const SRC_TREE = "5".repeat(40);
const DOCS_TREE = "6".repeat(40);
const BLOB_A = "7".repeat(40);
const BLOB_B = "8".repeat(40);
const MALICIOUS_TREE = "9".repeat(40);
const BUILD_ROOT = "C:\\test\\zerotrust-sourcecheck";
const CLONE_PATH = `${BUILD_ROOT}\\octocat-demo-${"0".repeat(40)}`;

function requestMap(entries) {
    const calls = [];
    const requestJson = (path) => {
        calls.push(path);
        const value = entries[path];
        if (value instanceof Error) throw value;
        if (value === undefined) throw new Error(`unexpected API path: ${path}`);
        return structuredClone(value);
    };
    return { calls, requestJson };
}

function treeResult(treeSha, recursive, {
    entries = [],
    discoveredSubtrees = entries.filter((entry) => entry.type === "tree"),
    truncated = false,
    entriesTruncated = false,
    discoveryTruncated = false,
} = {}) {
    return {
        treeSha,
        recursive,
        truncated,
        entriesTruncated,
        totalEntryCount: entries.length,
        entries,
        discoveredSubtrees,
        discoveryTruncated,
    };
}

function releaseIdentity(overrides = {}) {
    return {
        releaseId: "12345",
        tagName: "baseline.2.3",
        targetCommitish: "main",
        sourceCommitSha: COMMIT,
        rootTreeSha: ROOT,
        tagRefSha: TAG_REF,
        tagObjectSha: null,
        annotatedTag: false,
        tagPeelDepth: 0,
        ...overrides,
    };
}

function activateUrlAudit(sessionId, overrides = {}) {
    activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "demo",
        ref: "main",
        refType: "branch_or_tag",
        urlKind: "tree",
        ...overrides,
    });
}

test("release URLs distinguish tagged and latest selectors", () => {
    const tagged = parseGithubUrl("https://github.com/octocat/demo/releases/tag/baseline.2.3");
    assert.equal(tagged.ok, true);
    assert.equal(tagged.parsed.releaseSelector, "tag");

    const latest = parseGithubUrl("https://github.com/octocat/demo/releases");
    assert.equal(latest.ok, true);
    assert.equal(latest.parsed.releaseSelector, "latest");

    const unsupported = parseGithubUrl("https://github.com/octocat/demo/releases/latest");
    assert.equal(unsupported.ok, false);
});

test("release packet uses bound release id and the real subtree API", () => {
    const result = runHandler({
        url: "https://github.com/octocat/demo/releases",
        mode: "verify_release",
    });
    assert.equal(result.resultType, "success");
    assert.match(result.textResultForLlm, /subtree_path: "<path from unresolvedSubtrees>"/);
    assert.match(result.textResultForLlm, /zerotrust_safe_list_release_assets/);
    assert.match(result.textResultForLlm, /zerotrust_safe_fetch_release_asset/);
    assert.match(result.textResultForLlm, /never calls `\/releases\/latest`/i);
    assert.match(result.textResultForLlm, /boundContext\.reportPath/);
});

test("release URL identity cannot be replaced by ref override", () => {
    const latest = runHandler({
        url: "https://github.com/octocat/demo/releases",
        mode: "verify_release",
        ref: "baseline.2.3",
    });
    assert.equal(latest.resultType, "failure");
    assert.match(latest.textResultForLlm, /ref override is not valid/i);

    const tagged = runHandler({
        url: "https://github.com/octocat/demo/releases/tag/baseline.2.3",
        mode: "verify_release",
        ref: "release-test",
    });
    assert.equal(tagged.resultType, "failure");
    assert.match(tagged.textResultForLlm, /cannot change.*release identity/i);
});

test("latest release resolves its actual lightweight tag and final commit", () => {
    const { calls, requestJson } = requestMap({
        "repos/octocat/demo/releases/latest": {
            id: 12345,
            tag_name: "baseline.2.3",
            target_commitish: "main",
        },
        "repos/octocat/demo/git/refs/tags/baseline.2.3": {
            ref: "refs/tags/baseline.2.3",
            object: { type: "commit", sha: COMMIT },
        },
        [`repos/octocat/demo/git/commits/${COMMIT}`]: {
            sha: COMMIT,
            tree: { sha: ROOT },
        },
    });

    const identity = resolveReleaseIdentity("octocat", "demo", { requestJson });
    assert.deepEqual(identity, releaseIdentity({ tagRefSha: COMMIT }));
    assert.deepEqual(calls, [
        "repos/octocat/demo/releases/latest",
        "repos/octocat/demo/git/refs/tags/baseline.2.3",
        `repos/octocat/demo/git/commits/${COMMIT}`,
    ]);
});

test("tagged release peels annotated tags before accepting source commit", () => {
    const { requestJson } = requestMap({
        "repos/octocat/demo/releases/tags/baseline.2.3": {
            id: 12345,
            tag_name: "baseline.2.3",
            target_commitish: "main",
        },
        "repos/octocat/demo/git/refs/tags/baseline.2.3": {
            ref: "refs/tags/baseline.2.3",
            object: { type: "tag", sha: TAG_OBJECT },
        },
        [`repos/octocat/demo/git/tags/${TAG_OBJECT}`]: {
            object: { type: "commit", sha: COMMIT },
        },
        [`repos/octocat/demo/git/commits/${COMMIT}`]: {
            sha: COMMIT,
            tree: { sha: ROOT },
        },
    });

    const identity = resolveReleaseIdentity("octocat", "demo", {
        requestedTag: "baseline.2.3",
        requestJson,
    });
    assert.equal(identity.sourceCommitSha, COMMIT);
    assert.equal(identity.tagRefSha, TAG_OBJECT);
    assert.equal(identity.tagObjectSha, TAG_OBJECT);
    assert.equal(identity.annotatedTag, true);
    assert.equal(identity.tagPeelDepth, 1);
});

test("release and tree identity mismatches are rejected", () => {
    const releaseMock = requestMap({
        "repos/octocat/demo/releases/tags/baseline.2.3": {
            id: 12345,
            tag_name: "release-test",
        },
    });
    assert.throws(() => resolveReleaseIdentity("octocat", "demo", {
            requestedTag: "baseline.2.3",
            requestJson: releaseMock.requestJson,
        }),
        /release tag mismatch/i,
    );

    const treeMock = requestMap({
        [`repos/octocat/demo/git/trees/${ROOT}?recursive=1`]: {
            sha: MALICIOUS_TREE,
            truncated: false,
            tree: [],
        },
    });
    assert.throws(() => listTreeBySha("octocat", "demo", ROOT, {
            requestJson: treeMock.requestJson,
        }),
        /tree identity mismatch/i,
    );
});

test("bare release enumeration binds release, source, state, and artifact paths", async () => {
    const sessionId = `release-bind-${Math.random().toString(36).slice(2)}`;
    activateUrlAudit(sessionId, {
        mode: "verify_release",
        ref: null,
        refType: null,
        urlKind: "release",
        releaseSelector: "latest",
    });
    const client = {
        resolveReleaseIdentity:() => releaseIdentity(),
        resolveRefToSha:() => {
            throw new Error("release flow must not resolve HEAD");
        },
        getCommitIdentity:() => {
            throw new Error("release identity already includes commit/tree");
        },
        listTreeBySha: (_owner, _repo, sha, { recursive }) =>
            treeResult(sha, recursive, {
                entries: [{ path: "README.md", type: "blob", size: 10, sha: BLOB_A }],
            }),
    };
    try {
        const result = await safeListTreeHandler(
            { owner: "octocat", repo: "demo" },
            { sessionId, apiClient: client },
        );
        assert.equal(result.resultType, "success");
        const parsed = JSON.parse(result.textResultForLlm);
        assert.equal(parsed.sha, COMMIT);
        assert.equal(parsed.rootTreeSha, ROOT);
        assert.equal(parsed.releaseIdentity.releaseId, "12345");
        assert.equal(parsed.releaseIdentity.tagName, "baseline.2.3");
        assert.equal(parsed.boundContext.reportPath, buildReportPath(BUILD_ROOT, "octocat", "demo", COMMIT));
        assert.equal(parsed.boundContext.quarantinePath, buildQuarantinePath(BUILD_ROOT, "octocat", "demo", COMMIT));
        assert.equal(parsed.coverageComplete, true);

        const ctx = getTrustedAuditContext({
            sessionId,
            args: {},
            defaultBuildRoot: DEFAULT_BUILD_ROOT,
        });
        assert.equal(ctx.resolvedSha, COMMIT);
        assert.equal(ctx.releaseIdentity.releaseId, "12345");
        assert.equal(ctx.releaseIdentity.tagName, "baseline.2.3");
        assert.equal(ctx.rootTreeSha, ROOT);
        assert.equal(ctx.expectedReportPath, buildReportPath(BUILD_ROOT, "octocat", "demo", COMMIT));
    } finally {
        deactivateAudit(sessionId);
    }
});

test("subtree traversal validates discovery, merges duplicates, and completes coverage", async () => {
    const sessionId = `subtree-${Math.random().toString(36).slice(2)}`;
    activateUrlAudit(sessionId);
    let treeCalls = 0;
    const client = {
        resolveRefToSha:() => COMMIT,
        getCommitIdentity:() => ({ commitSha: COMMIT, rootTreeSha: ROOT }),
        resolveReleaseIdentity:() => {
            throw new Error("not a release");
        },
        listTreeBySha: (_owner, _repo, sha, { recursive }) => {
            treeCalls += 1;
            if (sha === ROOT && recursive) {
                return treeResult(ROOT, true, { truncated: true });
            }
            if (sha === ROOT && !recursive) {
                const entries = [
                    { path: "README.md", type: "blob", size: 10, sha: BLOB_A },
                    { path: "src", type: "tree", size: 0, sha: SRC_TREE },
                    { path: "docs", type: "tree", size: 0, sha: DOCS_TREE },
                ];
                return treeResult(ROOT, false, { entries });
            }
            if (sha === SRC_TREE && recursive) {
                return treeResult(SRC_TREE, true, {
                    entries: [
                        { path: "index.js", type: "blob", size: 20, sha: BLOB_B },
                        { path: "index.js", type: "blob", size: 20, sha: BLOB_B },
                    ],
                });
            }
            if (sha === DOCS_TREE && recursive) {
                return treeResult(DOCS_TREE, true, {
                    entries: [{ path: "guide.md", type: "blob", size: 30, sha: BLOB_A }],
                });
            }
            throw new Error(`unexpected tree call ${sha} recursive=${recursive}`);
        },
    };
    try {
        const rootResult = JSON.parse((await safeListTreeHandler(
            { owner: "octocat", repo: "demo" },
            { sessionId, apiClient: client },
        )).textResultForLlm);
        assert.equal(rootResult.coverageComplete, false);
        assert.deepEqual(
            rootResult.unresolvedSubtrees.map((item) => item.path),
            ["docs", "src"],
        );

        const callsBeforeReject = treeCalls;
        const rejected = await safeListTreeHandler(
            { owner: "octocat", repo: "demo", tree_sha: MALICIOUS_TREE },
            { sessionId, apiClient: client },
        );
        assert.equal(rejected.resultType, "failure");
        assert.match(rejected.textResultForLlm, /not discovered from the pinned commit tree/i);
        assert.equal(treeCalls, callsBeforeReject);

        const srcResult = JSON.parse((await safeListTreeHandler(
            { owner: "octocat", repo: "demo", subtree_path: "src" },
            { sessionId, apiClient: client },
        )).textResultForLlm);
        assert.equal(srcResult.coverageComplete, false);
        assert.equal(srcResult.duplicateEntryCount, 1);
        assert.deepEqual(srcResult.entries.map((entry) => entry.path), [
            "src/index.js",
            "src/index.js",
        ]);

        const docsResult = JSON.parse((await safeListTreeHandler(
            { owner: "octocat", repo: "demo", tree_sha: DOCS_TREE },
            { sessionId, apiClient: client },
        )).textResultForLlm);
        assert.equal(docsResult.coverageComplete, true);
        assert.equal(docsResult.unresolvedSubtreeCount, 0);
        assert.equal(docsResult.aggregateEntryCount, 5);
        assert.equal(
            docsResult.aggregateEntries.filter((entry) => entry.path === "src/index.js").length,
            1,
        );
    } finally {
        deactivateAudit(sessionId);
    }
});

test("flat entry-cap truncation exposes blockers and never claims complete coverage", async () => {
    const sessionId = `subtree-flat-${Math.random().toString(36).slice(2)}`;
    activateUrlAudit(sessionId);
    const client = {
        resolveRefToSha:() => COMMIT,
        getCommitIdentity:() => ({ commitSha: COMMIT, rootTreeSha: ROOT }),
        resolveReleaseIdentity:() => {
            throw new Error("not a release");
        },
        listTreeBySha: (_owner, _repo, sha, { recursive }) => treeResult(sha, recursive, {
            entries: [{ path: "only-visible.txt", type: "blob", size: 1, sha: BLOB_A }],
            entriesTruncated: true,
        }),
    };
    try {
        const result = await safeListTreeHandler(
            { owner: "octocat", repo: "demo" },
            { sessionId, apiClient: client },
        );
        assert.equal(result.resultType, "success");
        const parsed = JSON.parse(result.textResultForLlm);
        assert.equal(parsed.coverageComplete, false);
        assert.equal(parsed.unresolvedSubtreeCount, 0);
        assert.ok(parsed.coverageBlockers.length > 0);
        assert.match(parsed.coverageBlockers[0].reason, /direct entries.*undisclosed/i);
    } finally {
        deactivateAudit(sessionId);
    }
});
