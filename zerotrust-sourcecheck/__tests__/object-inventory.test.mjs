import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
    GIT_TREE_MODES,
    EVASIVE_BLOCKERS,
    buildGitObjectInventory,
    buildLocalObjectInventory,
    classifyGitTreeEntry,
    computeGitBlobSha1,
    createInitialAssuranceStageState,
    createEvasiveObjectInventoryRecord,
    parseGitLfsPointer,
    parseGitSymlinkTarget,
} from "../analysis/index.mjs";
import {
    __internals as apiInternals,
    listTreeBySha,
} from "../safeWrappers/apiClient.mjs";
import { safeFetchFileHandler } from "../safeWrappers/safeFetchHandler.mjs";
import { safeListTreeHandler } from "../safeWrappers/safeListTreeHandler.mjs";
import {
    createCoverageState,
    recordEnumeratedEntries,
    recordFetchResult,
} from "../safeWrappers/coverageAccounting.mjs";
import {
    activateAudit,
    deactivateAudit,
    getAnalysisStageState,
    getAssuranceSnapshot,
    getAssuranceState,
} from "../enforcement.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const COMMIT = "1".repeat(40);
const ROOT = "2".repeat(40);
const SOURCE_NAMESPACE = `github.com/example/repo@${COMMIT}`;

function blobEntry(path, mode, bytes) {
    return {
        path,
        type: "blob",
        mode,
        sha: computeGitBlobSha1(bytes),
        size: bytes.length,
    };
}

function fetched(entry, bytes) {
    return apiInternals.buildFetchResultFromBuffer(entry.path, bytes, {
        blobSha: entry.sha,
        gitMode: entry.mode,
        verifyGitBlobSha: true,
    });
}

function stageState(sourceNamespace = SOURCE_NAMESPACE) {
    return createInitialAssuranceStageState({
        auditId: AUDIT_ID,
        sourceNamespace,
    });
}

test("Git tree modes are preserved and classify executable, symlink, gitlink, and tree", () => {
    assert.deepEqual(
        classifyGitTreeEntry({ type: "blob", mode: "100755" }),
        {
            type: "blob",
            mode: "100755",
            modeInferred: false,
            objectKind: "executable-blob",
            executable: true,
            classificationRequired: true,
        },
    );
    assert.equal(
        classifyGitTreeEntry({ type: "blob", mode: "120000" }).objectKind,
        "symlink",
    );
    assert.equal(
        classifyGitTreeEntry({ type: "commit", mode: "160000" }).objectKind,
        "gitlink",
    );
    assert.equal(
        classifyGitTreeEntry({ type: "tree", mode: "040000" }).objectKind,
        "tree",
    );
    assert.throws(() => classifyGitTreeEntry({ type: "blob", mode: "160000" }),
        /mode\/type mismatch/,
    );
});

test("API tree normalization retains exact Git modes", () => {
    const result = listTreeBySha("example", "repo", ROOT, {
        requestJson:() => ({
            sha: ROOT,
            truncated: false,
            tree: [
                {
                    path: "run.sh",
                    type: "blob",
                    mode: "100755",
                    sha: "3".repeat(40),
                    size: 7,
                },
                {
                    path: "link",
                    type: "blob",
                    mode: "120000",
                    sha: "4".repeat(40),
                    size: 6,
                },
                {
                    path: "vendor",
                    type: "commit",
                    mode: "160000",
                    sha: "5".repeat(40),
                },
            ],
        }),
    });
    assert.deepEqual(result.entries.map((entry) => entry.mode), [
        "100755",
        "120000",
        "160000",
    ]);
    assert.deepEqual(result.entries.map((entry) => entry.objectKind), [
        "executable-blob",
        "symlink",
        "gitlink",
    ]);
});

test("fetched bytes are bound to the recomputed Git blob SHA-1", () => {
    const bytes = Buffer.from("console.log('ok');\n", "utf8");
    const expected = createHash("sha1")
        .update(`blob ${bytes.length}\0`, "utf8")
        .update(bytes)
        .digest("hex");
    assert.equal(computeGitBlobSha1(bytes), expected);
    const result = apiInternals.buildFetchResultFromBuffer("index.mjs", bytes, {
        blobSha: expected,
        gitMode: "100644",
        verifyGitBlobSha: true,
    });
    assert.equal(result.gitBlobSha1Verified, true);
    assert.throws(() => apiInternals.buildFetchResultFromBuffer("index.mjs", bytes, {
            blobSha: "f".repeat(40),
            gitMode: "100644",
            verifyGitBlobSha: true,
        }),
        /Git blob identity mismatch/,
    );
});

test("symlink and Git LFS pointer blobs are parsed from bytes without following", () => {
    const symlink = parseGitSymlinkTarget(Buffer.from("../shared/config.json", "utf8"));
    assert.equal(symlink.valid, true);
    assert.equal(symlink.kind, "relative");
    assert.equal(symlink.target, "../shared/config.json");

    const pointerBytes = Buffer.from(
        `version https://git-lfs.github.com/spec/v1\n`
        + `oid sha256:${"a".repeat(64)}\n`
        + "size 12345\n",
        "utf8",
    );
    assert.deepEqual(parseGitLfsPointer(pointerBytes), {
        detected: true,
        valid: true,
        oidSha256: "a".repeat(64),
        size: 12345,
    });
});

test("Git inventory records parent identity, special modes, gitlinks, and unresolved LFS objects", () => {
    const executableBytes = Buffer.from("#!/bin/sh\necho ok\n", "utf8");
    const symlinkBytes = Buffer.from("../README.md", "utf8");
    const lfsBytes = Buffer.from(
        `version https://git-lfs.github.com/spec/v1\n`
        + `oid sha256:${"a".repeat(64)}\n`
        + "size 9001\n",
        "utf8",
    );
    const entries = [
        {
            path: "bin",
            type: "tree",
            mode: GIT_TREE_MODES.TREE,
            sha: "3".repeat(40),
            size: 0,
        },
        blobEntry("bin/run.sh", GIT_TREE_MODES.EXECUTABLE_BLOB, executableBytes),
        blobEntry("latest", GIT_TREE_MODES.SYMLINK, symlinkBytes),
        blobEntry("model.bin", GIT_TREE_MODES.BLOB, lfsBytes),
        {
            path: "vendor/module",
            type: "commit",
            mode: GIT_TREE_MODES.GITLINK,
            sha: "4".repeat(40),
            size: 0,
        },
        {
            path: "vendor",
            type: "tree",
            mode: GIT_TREE_MODES.TREE,
            sha: "5".repeat(40),
            size: 0,
        },
    ];
    const acquisition = createCoverageState(COMMIT, ROOT);
    recordEnumeratedEntries(acquisition, entries);
    for (const [entry, bytes] of [
        [entries[1], executableBytes],
        [entries[2], symlinkBytes],
        [entries[3], lfsBytes],
    ]) {
        recordFetchResult(acquisition, {
            path: entry.path,
            scope: "mandatory",
            result: fetched(entry, bytes),
        });
    }
    const built = buildGitObjectInventory({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        stageState: stageState(),
        commitSha: COMMIT,
        rootTreeSha: ROOT,
        treeState: {
            commitSha: COMMIT,
            rootTreeSha: ROOT,
            entries,
            unresolvedSubtrees: [],
            coverageBlockers: [],
            stateTrackingTruncated: false,
            discoveryTruncated: false,
        },
        acquisitionState: acquisition,
    });
    const byPath = new Map(
        built.snapshot.objectInventory.map((record) => [record.path, record]),
    );
    assert.equal(byPath.get("bin/run.sh").objectKind, "executable-blob");
    assert.equal(byPath.get("bin/run.sh").gitMode, "100755");
    assert.equal(
        byPath.get("bin/run.sh").parentObjectId,
        byPath.get("bin").objectId,
    );
    assert.equal(byPath.get("latest").objectKind, "symlink");
    assert.equal(byPath.get("latest").symlinkTarget.kind, "relative");
    assert.equal(byPath.get("vendor/module").objectKind, "gitlink");
    assert.ok(
        byPath.get("vendor/module").blockerCodes.includes(
            EVASIVE_BLOCKERS.GITLINK_UNRESOLVED,
        ),
    );
    assert.equal(byPath.get("model.bin").lfsPointer.size, 9001);
    assert.ok(byPath.has("model.bin#git-lfs-object"));
    assert.ok(
        built.summary.blockerCodes.includes(EVASIVE_BLOCKERS.LFS_PAYLOAD_UNRESOLVED),
    );
    assert.equal(built.summary.complete, false);
});

test("ordinary verified Git blobs can complete the inventory stage input", () => {
    const bytes = Buffer.from("export const ready = true;\n", "utf8");
    const entry = blobEntry("src/index.mjs", GIT_TREE_MODES.BLOB, bytes);
    const tree = {
        path: "src",
        type: "tree",
        mode: GIT_TREE_MODES.TREE,
        sha: "3".repeat(40),
        size: 0,
    };
    const acquisition = createCoverageState(COMMIT, ROOT);
    recordEnumeratedEntries(acquisition, [tree, entry]);
    recordFetchResult(acquisition, {
        path: entry.path,
        scope: "mandatory",
        result: fetched(entry, bytes),
    });
    const built = buildGitObjectInventory({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        stageState: stageState(),
        commitSha: COMMIT,
        rootTreeSha: ROOT,
        treeState: {
            commitSha: COMMIT,
            rootTreeSha: ROOT,
            entries: [tree, entry],
            unresolvedSubtrees: [],
            coverageBlockers: [],
            stateTrackingTruncated: false,
            discoveryTruncated: false,
        },
        acquisitionState: acquisition,
    });
    assert.equal(built.summary.complete, true);
    assert.equal(built.snapshot.objectInventory.length, 2);
    assert.ok(
        built.snapshot.objectInventory.every((record) =>
            record.auditId === AUDIT_ID
            && record.sourceNamespace === SOURCE_NAMESPACE),
    );
});

test("local inventory represents skipped reparse points as explicit blockers", () => {
    const sourceNamespace = `local-audit:${AUDIT_ID}`;
    const contentSha256 = createHash("sha256")
        .update("const x = 1;\n")
        .digest("hex");
    const built = buildLocalObjectInventory({
        auditId: AUDIT_ID,
        sourceNamespace,
        stageState: stageState(sourceNamespace),
        sourceRoot: "C:\\source",
        enumeration: {
            directoryEntries: [{ path: "src", size: 0 }],
            files: [{ path: "src/index.mjs", size: 13 }],
            reparsePoints: [{ path: "linked-deps", size: 0 }],
            trackingTruncated: false,
        },
        indexState: {
            files: [{
                path: "src/index.mjs",
                size: 13,
                status: "indexed-text",
                classification: "text",
                contentSha256,
            }],
        },
    });
    const reparse = built.snapshot.objectInventory.find((record) =>
        record.path === "linked-deps");
    assert.equal(reparse.objectKind, "reparse-point");
    assert.equal(reparse.status, "blocked");
    assert.deepEqual(reparse.blockerCodes, [EVASIVE_BLOCKERS.REPARSE_POINT_SKIPPED]);
    assert.equal(built.summary.complete, false);
});

test("local inventory records Git LFS pointer metadata and its unresolved payload", () => {
    const sourceNamespace = `local-audit:${AUDIT_ID}`;
    const contentSha256 = "b".repeat(64);
    const built = buildLocalObjectInventory({
        auditId: AUDIT_ID,
        sourceNamespace,
        stageState: stageState(sourceNamespace),
        sourceRoot: "C:\\source",
        enumeration: {
            directoryEntries: [],
            files: [{ path: "model.bin", size: 128 }],
            reparsePoints: [],
            trackingTruncated: false,
        },
        indexState: {
            files: [{
                path: "model.bin",
                size: 128,
                status: "indexed-text",
                classification: "text",
                contentSha256,
            }],
        },
        observations: {
            "model.bin": {
                lfsPointer: {
                    detected: true,
                    valid: true,
                    oidSha256: "c".repeat(64),
                    size: 4096,
                },
            },
        },
    });
    const pointer = built.snapshot.objectInventory.find((record) =>
        record.path === "model.bin");
    assert.deepEqual(pointer.lfsPointer, {
        oidSha256: "c".repeat(64),
        size: 4096,
    });
    assert.ok(
        built.snapshot.objectInventory.some((record) =>
            record.path === "model.bin#git-lfs-object"
            && record.blockerCodes.includes(EVASIVE_BLOCKERS.LFS_PAYLOAD_UNRESOLVED)),
    );
});

test("strict assurance records reject a Git mode/type mismatch", () => {
    assert.throws(() => createEvasiveObjectInventoryRecord({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            path: "bad",
            parentObjectId: null,
            objectKind: "gitlink",
            byteLength: 0,
            status: "blocked",
            blockerCodes: [EVASIVE_BLOCKERS.GITLINK_UNRESOLVED],
            contentSha256: null,
            upstreamSha: "3".repeat(40),
            gitObjectType: "blob",
            gitMode: "160000",
            parentUpstreamSha: ROOT,
            executable: false,
            symlinkTarget: null,
            lfsPointer: null,
        }),
        /does not match the Git tree mode/,
    );
});

test("API wrappers persist assurance inventory automatically", async () => {
    const sessionId = `assurance-object-inventory-${Math.random().toString(36).slice(2)}`;
    const bytes = Buffer.from("export const value = 1;\n", "utf8");
    const entry = blobEntry("index.mjs", GIT_TREE_MODES.BLOB, bytes);
    const buildRoot = "C:\\test\\zerotrust-sourcecheck";
    const auditId = activateAudit({
        sessionId,
        buildPath: buildRoot,
        mode: "audit_source",
        expectedClonePath: `${buildRoot}\\example-repo`,
        owner: "example",
        repo: "repo",
        ref: "main",
        refType: "branch_or_tag",
        urlKind: "tree",
    });
    try {
        const listed = await safeListTreeHandler(
            { owner: "example", repo: "repo" },
            {
                sessionId,
                apiClient: {
                    resolveRefToSha:() => COMMIT,
                    getCommitIdentity:() => ({
                        commitSha: COMMIT,
                        rootTreeSha: ROOT,
                    }),
                    resolveReleaseIdentity:() => {
                        throw new Error("not a release");
                    },
                    listTreeBySha:() => ({
                        treeSha: ROOT,
                        recursive: true,
                        truncated: false,
                        entriesTruncated: false,
                        totalEntryCount: 1,
                        entries: [entry],
                        discoveredSubtrees: [],
                        discoveryTruncated: false,
                    }),
                },
            },
        );
        const listedResult = JSON.parse(listed.textResultForLlm);
        assert.equal(listedResult.assuranceObjectInventory.stage, "acquired");
        assert.equal(
            getAssuranceState(sessionId, { auditId }).sourceNamespace,
            SOURCE_NAMESPACE,
        );

        const fetchedResult = await safeFetchFileHandler(
            {
                owner: "example",
                repo: "repo",
                sha: COMMIT,
                path: entry.path,
                coverage_scope: "mandatory",
            },
            {
                sessionId,
                fetchFile:() => fetched(entry, bytes),
            },
        );
        const fetchedPayload = JSON.parse(fetchedResult.textResultForLlm);
        assert.equal(fetchedPayload.assuranceObjectInventory.stage, "inventoried");
        assert.equal(fetchedPayload.assuranceObjectInventory.complete, true);
        assert.equal(fetchedPayload.assuranceDerivedAnalysis.stage, "decoded");
        assert.equal(fetchedPayload.assuranceDerivedAnalysis.artifactCount > 0, true);
        const assuranceSnapshot = getAssuranceSnapshot(
            sessionId,
            { auditId: listedResult.analysisIndex.auditId },
        );
        assert.equal(assuranceSnapshot.objectInventory.length, 1);
        assert.equal(assuranceSnapshot.stageState.current, "decoded");
        assert.equal(assuranceSnapshot.derivedArtifacts.length > 0, true);
        assert.equal(JSON.stringify(assuranceSnapshot).includes("export const value"), false);
        assert.equal(getAnalysisStageState(sessionId).schemaVersion, 5);
    } finally {
        deactivateAudit(sessionId);
    }
});
