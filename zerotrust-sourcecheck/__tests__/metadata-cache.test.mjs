import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import {
    existsSync,
    mkdtempSync,
    readFileSync,
    rmSync,
    symlinkSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";

import {
    CACHE_LIMITS,
    CACHE_SCHEMA_REVISION,
    buildCachePaths,
    buildCachePayload,
    computeCachedPluginFactId,
    parseCacheEnvelope,
    serializeCacheEnvelope,
    validateCachePayload,
} from "../analysis/cache.mjs";
import { extractFactsFromText } from "../analysis/extractFacts.mjs";
import {
    createAnalysisIndexState,
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import {
    __internals as enforcementInternals,
    activateAudit,
    deactivateAudit,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
    recordResolvedSha,
} from "../enforcement.mjs";
import {
    cacheCleanupHandler,
    cacheListHandler,
    cacheLoadHandler,
    cacheStoreHandler,
} from "../safeWrappers/cacheWrapper.mjs";
import { closeAuditHandler } from "../safeWrappers/lifecycleWrapper.mjs";
import { resolveCacheRoot } from "../safeWrappers/defaults.mjs";
import {
    __internals as stateInternals,
    getCacheBinding,
} from "../safeWrappers/state.mjs";

const scratchRoots = [];
const OWNER = "octocat";
const REPO = "cache-demo";
const SHA_ONE = "1".repeat(40);
const SHA_TWO = "2".repeat(40);
const BLOB_ONE = "a".repeat(40);
const BLOB_TWO = "b".repeat(40);
const CONTENT_SHA = "c".repeat(64);

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

function makeScratch(prefix = ".zt-cache-") {
    const root = mkdtempSync(nodePath.join(process.cwd(), prefix));
    scratchRoots.push(root);
    return root;
}

function buildIndexState({
    auditId = "11111111-1111-4111-8111-111111111111",
    blobSha = BLOB_ONE,
    contentSha256 = CONTENT_SHA,
    indexed = true,
} = {}) {
    const source = [
        "export function collect() {",
        "  const password = 'super-secret-value';",
        "  return process.env.API_TOKEN;",
        "}",
    ].join("\n");
    const extraction = extractFactsFromText({
        path: "src/index.mjs",
        text: source,
    });
    const state = createAnalysisIndexState({
        auditId,
        sourceKind: "api-direct",
    });
    recordIndexEnumeration(state, {
        entries: [{
            path: "src/index.mjs",
            size: Buffer.byteLength(source),
            blobSha,
        }],
        complete: true,
    });
    if (indexed) {
        recordIndexedFile(state, {
            path: "src/index.mjs",
            size: Buffer.byteLength(source),
            classification: "text",
            classificationComplete: true,
            contentSha256,
            blobSha,
            facts: extraction.facts,
            lineCount: extraction.lineCount,
            invisibleUnicodeScanComplete: true,
        });
    }
    return { state, source, facts: extraction.facts };
}

function activateIndexedAudit({
    sessionId,
    buildRoot,
    sourceSha,
    blobSha = BLOB_ONE,
    indexed = true,
} = {}) {
    const auditId = activateAudit({
        sessionId,
        buildPath: buildRoot,
        mode: "audit_source",
        expectedClonePath: nodePath.join(buildRoot, "unused"),
        owner: OWNER,
        repo: REPO,
    });
    assert.equal(recordResolvedSha(sessionId, sourceSha), true);
    const built = buildIndexState({ auditId, blobSha, indexed });
    mutateAnalysisIndexState(sessionId, (state) => {
        recordIndexEnumeration(state, {
            entries: state.files.length > 0
                ? []: [{
                    path: "src/index.mjs",
                    size: built.state.files[0].size,
                    blobSha,
                }],
            complete: true,
        });
        if (indexed) {
            const file = built.state.files[0];
            recordIndexedFile(state, {
                path: file.path,
                size: file.size,
                classification: file.classification,
                classificationComplete: true,
                contentSha256: file.contentSha256,
                blobSha: file.blobSha,
                facts: built.facts,
                lineCount: file.lineCount,
                invisibleUnicodeScanComplete: true,
            });
        }
    });
    maybeAdvanceAnalysisPrepared(sessionId);
    return { auditId, ...built };
}

afterEach(() => {
    enforcementInternals.activeAudits.clear();
    stateInternals.cacheBindings.clear();
    while (scratchRoots.length > 0) {
        rmSync(scratchRoots.pop(), { recursive: true, force: true });
    }
});

test("cache schema is canonical, integrity-checked, and rejects snippet-bearing fields", () => {
    const { state, source } = buildIndexState();
    const payload = buildCachePayload({
        sourceIdentity: {
            kind: "github",
            owner: OWNER,
            repo: REPO,
            sourceSha: SHA_ONE,
        },
        indexState: state,
        stageState: {
            current: "prepared",
            history: ["acquired", "prepared"],
        },
    });
    const serialized = serializeCacheEnvelope(payload);
    assert.equal(parseCacheEnvelope(serialized).payload.sourceKey, payload.sourceKey);
    assert.doesNotMatch(serialized, /super-secret-value/);
    assert.doesNotMatch(serialized, new RegExp(source.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
    assert.doesNotMatch(serialized, /sourceText|excerptText|prompt|modelOutput|verdict/);

    assert.throws(() => validateCachePayload({ ...payload, verdict: "low" }),
        /unknown or non-cacheable field/,
    );
    assert.throws(() => validateCachePayload({
            ...payload,
            pluginRecords: [{
                pluginId: "activation-events",
                pluginVersion: "1.0.0",
                sourceBlobs: [{
                    path: "src/index.mjs",
                    blobSha: BLOB_ONE,
                    contentSha256: CONTENT_SHA,
                }],
                facts: [],
                nodes: [],
                edges: [],
                findings: [],
                validationDecisions: [],
                summary: "const password = 'copied snippet'",
            }],
        }),
        /unknown or non-cacheable field/,
    );

    const tampered = serialized.replace(`"integritySha256":"`, `"integritySha256":"0`);
    assert.throws(() => parseCacheEnvelope(tampered), /integrity|invalid format/);
    assert.throws(() => parseCacheEnvelope(`${serialized.trim()}  \n`), /canonical JSON/);
    assert.throws(() => parseCacheEnvelope("x".repeat(CACHE_LIMITS.fileBytes + 1)),
        /exceeds/,
    );
    assert.equal(typeof payload.storedAt, "string");
    assert.equal(new Date(payload.storedAt).toISOString(), payload.storedAt);
    assert.throws(() => validateCachePayload({
            ...payload,
            storedAt: new Date(payload.storedAt),
        }),
        /must be a string/,
    );

    const postFinalization = buildCachePayload({
        sourceIdentity: {
            kind: "github",
            owner: OWNER,
            repo: REPO,
            sourceSha: SHA_ONE,
        },
        indexState: state,
        stageState: {
            current: "finalized",
            history: ["acquired", "prepared", "scanned", "traced", "validated", "finalized"],
        },
    });
    assert.equal(postFinalization.stage.current, "validated");
    assert.doesNotMatch(serializeCacheEnvelope(postFinalization), /"finalized"|verdict|reportBody/);
    assert.throws(() => validateCachePayload({
            ...payload,
            stage: {
                current: "finalized",
                history: ["acquired", "prepared", "scanned", "traced", "validated", "finalized"],
            },
        }),
        /must be one of/,
    );
});

test("cache paths are revisioned, contained, and collision-resistant", () => {
    const buildRoot = nodePath.resolve(makeScratch());
    const cacheRoot = resolveCacheRoot(buildRoot);
    const first = buildCachePaths(cacheRoot, {
        kind: "github",
        owner: "a-b",
        repo: "c",
        sourceSha: SHA_ONE,
    });
    const second = buildCachePaths(cacheRoot, {
        kind: "github",
        owner: "a",
        repo: "b-c",
        sourceSha: SHA_ONE,
    });
    assert.notEqual(first.namespaceKey, second.namespaceKey);
    assert.notEqual(first.sourceKey, second.sourceKey);
    assert.match(
        first.filePath,
        new RegExp(`_cache[\\\\/]schema-${CACHE_SCHEMA_REVISION}[\\\\/]format-[a-f0-9]{64}`),
    );
    assert.equal(nodePath.relative(buildRoot, first.filePath).startsWith(".."), false);
    assert.throws(() => resolveCacheRoot("relative-cache-root"), /absolute/);
});

test("active-bound store/load persists only normalized metadata and close preserves disk cache", async () => {
    const buildRoot = makeScratch();
    const sessionId = "cache-store-load";
    const { auditId } = activateIndexedAudit({
        sessionId,
        buildRoot,
        sourceSha: SHA_ONE,
    });

    const storedResult = await cacheStoreHandler(
        { audit_id: auditId },
        { sessionId },
    );
    assert.equal(storedResult.resultType, "success");
    const stored = parse(storedResult);
    assert.equal(stored.stored, true);
    assert.equal(stored.fileCount, 1);

    const binding = getCacheBinding(sessionId, { auditId });
    assert.ok(binding);
    assert.equal(existsSync(binding.cachePath), true);
    const raw = readFileSync(binding.cachePath, "utf8");
    assert.doesNotMatch(raw, /super-secret-value|sourceText|excerptText|prompt|verdict/);
    assert.doesNotMatch(raw, new RegExp(auditId));
    assert.equal(raw, serializeCacheEnvelope(parseCacheEnvelope(raw).payload));

    const listed = parse(await cacheListHandler(
        { audit_id: auditId },
        { sessionId },
    ));
    assert.equal(listed.available, true);
    assert.equal(listed.entries.length, 1);

    const loaded = parse(await cacheLoadHandler(
        {
            audit_id: auditId,
            plugin_versions: listed.entries[0].pluginRecords.map((plugin) => ({
                plugin_id: plugin.pluginId,
                plugin_version: plugin.pluginVersion,
            })),
        },
        { sessionId },
    ));
    assert.equal(loaded.hit, true);
    assert.equal(loaded.exactSourceHit, true);
    assert.equal(loaded.files.length, 1);
    assert.equal(loaded.stage.current, "prepared");
    assert.ok(loaded.pluginRecords.every((record) =>
        record.facts.every((fact) => /^zpcf-[a-f0-9]{64}$/u.test(fact.id))));

    const closed = parse(await closeAuditHandler({}, { sessionId }));
    assert.equal(closed.closed, true);
    assert.equal(closed.cacheBindingCleared, true);
    assert.equal(closed.diskCachePreserved, true);
    assert.equal(getCacheBinding(sessionId), null);
    assert.equal(existsSync(binding.cachePath), true);
});

test("prior source SHA reuse requires unchanged blob and exact plugin version", async () => {
    const buildRoot = makeScratch();
    const first = activateIndexedAudit({
        sessionId: "cache-prior-one",
        buildRoot,
        sourceSha: SHA_ONE,
    });
    const cachedPluginFact = {
        kind: "activation-surface",
        name: "cache-test-activation",
        value: "on-install",
        producer: "cache-test-plugin",
        sourceIdentity: {
            type: "git-blob",
            namespace: `${OWNER}/${REPO}`,
            path: "src/index.mjs",
            contentSha256: CONTENT_SHA,
            blobSha: BLOB_ONE,
        },
        evidence: [{
            path: "src/index.mjs",
            startLine: 1,
            endLine: 1,
            blobSha: BLOB_ONE,
            excerptHash: first.facts[0].excerptHash,
            producer: "cache-test-plugin",
            coverageScope: "mandatory",
        }],
        tags: ["cache-test"],
    };
    cachedPluginFact.id = computeCachedPluginFactId(cachedPluginFact);
    const pluginRecord = {
        pluginId: "cache-test-plugin",
        pluginVersion: "1.2.3",
        sourceBlobs: [{
            path: "src/index.mjs",
            blobSha: BLOB_ONE,
            contentSha256: CONTENT_SHA,
        }],
        facts: [cachedPluginFact],
        nodes: [],
        edges: [],
        findings: [],
        validationDecisions: [],
    };
    assert.equal(
        (await cacheStoreHandler(
            {
                audit_id: first.auditId,
                plugin_records: [pluginRecord],
            },
            { sessionId: "cache-prior-one" },
        )).resultType,
        "success",
    );
    deactivateAudit("cache-prior-one");

    const unchanged = activateIndexedAudit({
        sessionId: "cache-prior-two",
        buildRoot,
        sourceSha: SHA_TWO,
        blobSha: BLOB_ONE,
        indexed: false,
    });
    const reused = parse(await cacheLoadHandler(
        {
            audit_id: unchanged.auditId,
            plugin_versions: [{
                plugin_id: "cache-test-plugin",
                plugin_version: "1.2.3",
            }],
        },
        { sessionId: "cache-prior-two" },
    ));
    assert.equal(reused.hit, true);
    assert.equal(reused.exactSourceHit, false);
    assert.equal(reused.reusedPriorSource, true);
    assert.equal(reused.files.length, 1);
    assert.equal(reused.pluginRecords.length, 1);
    assert.equal(reused.stage, null);
    assert.deepEqual(reused.coverage, []);

    const mismatchedPlugin = parse(await cacheLoadHandler(
        {
            audit_id: unchanged.auditId,
            plugin_versions: [{
                plugin_id: "cache-test-plugin",
                plugin_version: "2.0.0",
            }],
        },
        { sessionId: "cache-prior-two" },
    ));
    assert.equal(mismatchedPlugin.files.length, 1);
    assert.equal(mismatchedPlugin.pluginRecords.length, 0);
    deactivateAudit("cache-prior-two");

    const changed = activateIndexedAudit({
        sessionId: "cache-prior-three",
        buildRoot,
        sourceSha: SHA_TWO,
        blobSha: BLOB_TWO,
        indexed: false,
    });
    const miss = parse(await cacheLoadHandler(
        {
            audit_id: changed.auditId,
            plugin_versions: [{
                plugin_id: "cache-test-plugin",
                plugin_version: "1.2.3",
            }],
        },
        { sessionId: "cache-prior-three" },
    ));
    assert.equal(miss.hit, false);
    assert.deepEqual(miss.files, []);
    assert.deepEqual(miss.pluginRecords, []);
});

test("corrupt cache is discarded and cache absence remains a normal result", async () => {
    const buildRoot = makeScratch();
    const sessionId = "cache-corrupt";
    const { auditId } = activateIndexedAudit({
        sessionId,
        buildRoot,
        sourceSha: SHA_ONE,
    });
    assert.equal(
        (await cacheStoreHandler({ audit_id: auditId }, { sessionId })).resultType,
        "success",
    );
    const binding = getCacheBinding(sessionId, { auditId });
    writeFileSync(binding.cachePath, Buffer.from([0xff, 0xfe, 0x7b, 0x7d]));

    const loaded = parse(await cacheLoadHandler(
        { audit_id: auditId },
        { sessionId },
    ));
    assert.equal(loaded.ok, true);
    assert.equal(loaded.hit, false);
    assert.equal(loaded.discardedCorrupt.length, 1);
    assert.equal(loaded.discardedCorrupt[0].removed, true);
    assert.match(loaded.discardedCorrupt[0].reason, /UTF-8/);
    assert.equal(existsSync(binding.cachePath), false);

    const empty = parse(await cacheListHandler(
        { audit_id: auditId },
        { sessionId },
    ));
    assert.equal(empty.ok, true);
    assert.equal(empty.available, false);
    assert.deepEqual(empty.entries, []);
});

test("cache cleanup is source-bound and cache reads never follow symlinks", async (t) => {
    const buildRoot = makeScratch();
    const sessionId = "cache-cleanup";
    const { auditId } = activateIndexedAudit({
        sessionId,
        buildRoot,
        sourceSha: SHA_ONE,
    });
    assert.equal(
        (await cacheStoreHandler({ audit_id: auditId }, { sessionId })).resultType,
        "success",
    );
    const binding = getCacheBinding(sessionId, { auditId });
    const outside = nodePath.join(buildRoot, "outside.json");
    writeFileSync(outside, "{\"private\":\"must-not-be-read\"}\n");
    rmSync(binding.cachePath);
    let linked = false;
    try {
        symlinkSync(outside, binding.cachePath, "file");
        linked = true;
    } catch (error) {
        if (!["EPERM", "EACCES", "UNKNOWN"].includes(error?.code)) throw error;
        t.diagnostic(`file symlink creation unavailable: ${error.code}`);
    }
    if (linked) {
        const refused = await cacheLoadHandler(
            { audit_id: auditId },
            { sessionId },
        );
        assert.equal(refused.resultType, "failure");
        assert.equal(readFileSync(outside, "utf8"), "{\"private\":\"must-not-be-read\"}\n");
        rmSync(binding.cachePath);
    }

    assert.equal(
        (await cacheStoreHandler({ audit_id: auditId }, { sessionId })).resultType,
        "success",
    );
    const cleaned = parse(await cacheCleanupHandler(
        { audit_id: auditId, scope: "current_source" },
        { sessionId },
    ));
    assert.equal(cleaned.cleaned, true);
    assert.equal(cleaned.removed.length, 1);
    assert.equal(existsSync(binding.cachePath), false);
    assert.equal(existsSync(outside), true);
});

test("extension registers all active-bound cache tools and bounded schemas", () => {
    const extensionSource = readFileSync(
        new URL("../extension.mjs", import.meta.url),
        "utf8",
    );
    for (const name of [
        "zerotrust_cache_list",
        "zerotrust_cache_load",
        "zerotrust_cache_store",
        "zerotrust_cache_cleanup",
    ]) {
        assert.match(extensionSource, new RegExp(`name:\\s*"${name}"`));
    }
    assert.match(extensionSource, /additionalProperties:\s*false/);
    assert.match(extensionSource, /source text, snippets, prompts, credentials/i);
});
