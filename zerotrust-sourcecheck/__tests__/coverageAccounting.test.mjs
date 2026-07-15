import { test } from "node:test";
import assert from "node:assert/strict";

import {
    buildCoverageSnapshot,
    createCoverageState,
    FETCH_OUTCOMES,
    isRequiredBlobPath,
    recordEnumeratedEntries,
    recordFetchFailure,
    recordFetchResult,
    scanInvisibleUnicode,
} from "../safeWrappers/coverageAccounting.mjs";
import { __internals as apiInternals } from "../safeWrappers/apiClient.mjs";
import { safeListTreeHandler } from "../safeWrappers/safeListTreeHandler.mjs";
import { safeFetchFileHandler } from "../safeWrappers/safeFetchHandler.mjs";
import { recordOutcomeHandler } from "../safeWrappers/outcomeWrapper.mjs";
import {
    __internals as reportInternals,
    finalizeReportHandler,
} from "../safeWrappers/reportWrapper.mjs";
import { clearRecordedOutcome } from "../safeWrappers/state.mjs";
import {
    activateAudit,
    deactivateAudit,
    getAcquisitionCoverageState,
} from "../enforcement.mjs";
import { buildInstructionPacket } from "../packet.mjs";
import { buildQuarantinePath, buildReportPath } from "../urlParser.mjs";

const COMMIT = "a".repeat(40);
const ROOT = "b".repeat(40);
const BLOB_A = "c".repeat(40);
const BLOB_B = "d".repeat(40);
const BUILD_ROOT = "C:\\test\\zerotrust-sourcecheck";
const CLONE_PATH = `${BUILD_ROOT}\\octocat-demo-aaaaaaa`;

function blob(path, sha = BLOB_A, size = 10) {
    return { path, type: "blob", sha, size };
}

function fetchedText(path, text, blobSha = BLOB_A, options = {}) {
    return apiInternals.buildFetchResultFromBuffer(
        path,
        Buffer.from(text, "utf-8"),
        { blobSha, ...options },
    );
}

function fetchedBinary(path, bytes, blobSha = BLOB_A, options = {}) {
    return apiInternals.buildFetchResultFromBuffer(
        path,
        Buffer.from(bytes),
        { blobSha, ...options },
    );
}

function syntheticPe() {
    const bytes = Buffer.alloc(132);
    bytes[0] = 0x4D;
    bytes[1] = 0x5A;
    bytes.writeUInt32LE(128, 0x3C);
    bytes.set([0x50, 0x45, 0x00, 0x00], 128);
    return bytes;
}

function completeTreeState(entries = []) {
    return {
        commitSha: COMMIT,
        rootTreeSha: ROOT,
        entries,
        duplicateEntryCount: 0,
        unresolvedSubtrees: [],
        coverageBlockers: [],
        stateTrackingTruncated: false,
        discoveryTruncated: false,
    };
}

function treeResult(entries = []) {
    return {
        treeSha: ROOT,
        recursive: true,
        truncated: false,
        entriesTruncated: false,
        totalEntryCount: entries.length,
        entries,
        discoveredSubtrees: entries.filter((entry) => entry.type === "tree"),
        discoveryTruncated: false,
    };
}

function activateUrlAudit(sessionId, mode = "audit_source") {
    return activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode,
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "demo",
        ref: "main",
        refType: "branch_or_tag",
        urlKind: "tree",
    });
}

async function enumerate(sessionId, entries) {
    const client = {
        resolveRefToSha: () => COMMIT,
        getCommitIdentity: () => ({ commitSha: COMMIT, rootTreeSha: ROOT }),
        resolveReleaseIdentity: () => {
            throw new Error("not a release");
        },
        listTreeBySha: () => treeResult(entries),
    };
    return safeListTreeHandler(
        { owner: "octocat", repo: "demo" },
        { sessionId, apiClient: client },
    );
}

function parseResult(result) {
    return JSON.parse(result.textResultForLlm);
}

test("enumerated paths and blob SHAs are unique without duplicate inflation", () => {
    const state = createCoverageState(COMMIT, ROOT);
    recordEnumeratedEntries(state, [
        blob("src/a.js", BLOB_A),
        blob("src/b.js", BLOB_A),
    ]);
    recordEnumeratedEntries(state, [blob("src/a.js", BLOB_A)]);

    const snapshot = buildCoverageSnapshot(state, completeTreeState());
    assert.equal(snapshot.enumeration.uniqueFiles, 2);
    assert.equal(snapshot.enumeration.uniqueBlobShas, 1);
    assert.equal(snapshot.enumeration.duplicateEntries, 1);
});

test("invisible-Unicode scan detects Variation Selectors Supplement", () => {
    const hidden = String.fromCodePoint(0xE0100, 0xE01EF);
    assert.deepEqual(scanInvisibleUnicode(hidden), {
        complete: true,
        matchCount: 2,
    });
});

test("full, truncated, binary, oversized, and failed fetches are accounted separately", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [
        blob("full.js"),
        blob("truncated.js"),
        blob("payload.exe"),
        blob("oversized.js"),
        blob("failed.js"),
    ];
    recordEnumeratedEntries(state, entries);
    const hidden = String.fromCodePoint(0xE0001);

    const full = recordFetchResult(state, {
        path: "full.js",
        scope: "mandatory",
        result: fetchedText("full.js", `const x = 1;${hidden}`),
    });
    recordFetchResult(state, {
        path: "truncated.js",
        scope: "mandatory",
        result: fetchedText("truncated.js", "partial text", BLOB_A, { maxTextBytes: 4 }),
    });
    recordFetchResult(state, {
        path: "payload.exe",
        scope: "council_sample",
        result: fetchedBinary("payload.exe", syntheticPe()),
    });
    recordFetchResult(state, {
        path: "oversized.js",
        scope: "mandatory",
        result: fetchedText("oversized.js", "too large", BLOB_A, { maxBytes: 2 }),
    });
    recordFetchFailure(state, {
        path: "failed.js",
        scope: "mandatory",
        error: new Error("network refused"),
    });

    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(full.outcome, FETCH_OUTCOMES.FULL_TEXT);
    assert.equal(full.invisibleUnicodeScan.complete, true);
    assert.equal(full.invisibleUnicodeScan.matchCount, 1);
    assert.equal(snapshot.acquisition.observedOutcomes.fullTextFiles, 1);
    assert.equal(snapshot.acquisition.observedOutcomes.truncatedTextFiles, 1);
    assert.equal(snapshot.acquisition.observedOutcomes.binaryMetadataOnlyFiles, 1);
    assert.equal(snapshot.acquisition.observedOutcomes.oversizedMetadataOnlyFiles, 1);
    assert.equal(snapshot.acquisition.observedOutcomes.failureFiles, 1);
    assert.equal(snapshot.acquisition.fetchFailureAttempts, 1);
    assert.equal(snapshot.deterministicMandatory.invisibleUnicodeMatchCount, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, false);
});

test("duplicate fetches upgrade outcomes without double-counting unique files", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [blob("src/index.js")];
    recordEnumeratedEntries(state, entries);
    const completeText = "complete text";
    recordFetchResult(state, {
        path: "src/index.js",
        scope: "mandatory",
        result: fetchedText("src/index.js", completeText, BLOB_A, { maxTextBytes: 4 }),
    });
    recordFetchResult(state, {
        path: "src/index.js",
        scope: "mandatory",
        result: fetchedText("src/index.js", completeText),
    });

    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.acquisition.uniqueFetchedFiles, 1);
    assert.equal(snapshot.acquisition.fetchAttempts, 2);
    assert.equal(snapshot.acquisition.duplicateFetchCalls, 1);
    assert.equal(snapshot.acquisition.observedOutcomes.truncatedTextFiles, 1);
    assert.equal(snapshot.acquisition.observedOutcomes.fullTextFiles, 1);
    assert.equal(snapshot.acquisition.bestOutcomes.fullTextFiles, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, true);
});

test("council sampling never satisfies deterministic mandatory coverage", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [blob("src/index.js")];
    recordEnumeratedEntries(state, entries);
    const result = fetchedText("src/index.js", "complete");
    recordFetchResult(state, {
        path: "src/index.js",
        scope: "council_sample",
        result,
    });
    let snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.councilSampling.uniqueSampledFiles, 1);
    assert.equal(snapshot.deterministicMandatory.councilSampleOnlyBlobs, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, false);

    recordFetchResult(state, {
        path: "src/index.js",
        scope: "mandatory",
        result,
    });
    snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.requiredAcquisitionComplete, true);
});

test("unresolved subtrees keep required acquisition incomplete", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const treeState = completeTreeState([]);
    treeState.unresolvedSubtrees = [{ path: "src", sha: BLOB_B }];
    const snapshot = buildCoverageSnapshot(state, treeState);
    assert.equal(snapshot.requiredAcquisitionComplete, false);
    assert.equal(snapshot.enumeration.unresolvedSubtrees, 1);
    assert.ok(snapshot.blockers.some((blocker) => blocker.kind === "unresolved_subtrees"));
});

test("genuine binary blobs require mandatory byte classification and bounded inspection", () => {
    const binaryState = createCoverageState(COMMIT, ROOT);
    const binaryEntries = [blob("image.png"), blob("tool.exe", BLOB_B)];
    recordEnumeratedEntries(binaryState, binaryEntries);
    recordFetchResult(binaryState, {
        path: "image.png",
        scope: "mandatory",
        result: fetchedBinary(
            "image.png",
            [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00],
        ),
    });
    recordFetchResult(binaryState, {
        path: "tool.exe",
        scope: "mandatory",
        result: fetchedBinary("tool.exe", syntheticPe(), BLOB_B),
    });
    const binaryRecord = binaryState.fetchRecords.find((record) =>
        record.path === "tool.exe");
    assert.ok(binaryRecord.scopes.mandatory.best.previewByteCount <= 256);
    assert.equal(binaryRecord.scopes.mandatory.best.contentReturned, false);
    const binarySnapshot = buildCoverageSnapshot(
        binaryState,
        completeTreeState(binaryEntries),
    );
    assert.equal(binarySnapshot.deterministicMandatory.requiredBlobClassifications, 2);
    assert.equal(binarySnapshot.deterministicMandatory.classifiedBinaryBlobs, 2);
    assert.equal(binarySnapshot.acquisition.observedOutcomes.binaryMetadataOnlyFiles, 2);
    assert.equal(binarySnapshot.requiredAcquisitionComplete, true);
});

test("plain ASCII scripts under .png and .exe are fetched as text and scanned", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [blob("payload.png"), blob("runner.exe", BLOB_B)];
    recordEnumeratedEntries(state, entries);
    const hidden = String.fromCodePoint(0xE0001);
    const pngText = fetchedText("payload.png", `console.log('png');${hidden}`);
    const exeText = fetchedText("runner.exe", "Write-Output 'exe'", BLOB_B);
    assert.equal(pngText.classification, "text");
    assert.equal(pngText.likelyBinaryByExtension, true);
    assert.equal(exeText.classification, "text");
    assert.equal(exeText.likelyBinaryByExtension, true);

    recordFetchResult(state, {
        path: "payload.png",
        scope: "mandatory",
        result: pngText,
    });

    recordFetchResult(state, {
        path: "runner.exe",
        scope: "mandatory",
        result: exeText,
    });

    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.deterministicMandatory.fullyFetchedAndScannedTextBlobs, 2);
    assert.equal(snapshot.deterministicMandatory.invisibleUnicodeMatchCount, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, true);
});

test("invalid UTF-8 script bytes remain unknown and cannot satisfy coverage", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [blob("runner.bat")];
    recordEnumeratedEntries(state, entries);
    const payload = Buffer.concat([
        Buffer.from("MZ@echo off\r\nrem damaged byte:"),
        Buffer.from([0xFF]),
        Buffer.from("\r\n" + "A".repeat(80) + "\r\npowershell -encodedCommand hidden"),
    ]);
    const result = apiInternals.buildFetchResultFromBuffer(
        "runner.bat",
        payload,
        { blobSha: BLOB_A, previewBytes: 24 },
    );
    assert.equal(result.classification, "unknown");
    assert.equal(result.classificationComplete, false);
    assert.equal(result.contentReturned, false);
    assert.equal("text" in result, false);
    assert.equal(Buffer.from(result.previewBase64, "base64").includes(Buffer.from("powershell")), false);
    recordFetchResult(state, { path: "runner.bat", scope: "mandatory", result });
    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.deterministicMandatory.missingOrIncomplete, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, false);
});

test("trusted PE, PNG, and ZIP signatures are structurally binary", () => {
    const samples = [
        ["tool.exe", syntheticPe()],
        ["image.png", [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
        ["archive.zip", [0x50, 0x4B, 0x03, 0x04, 0x00]],
    ];
    for (const [path, bytes] of samples) {
        const result = fetchedBinary(path, bytes);
        assert.equal(result.classification, "binary");
        assert.equal(result.classificationComplete, true);
    }
});

test("extensionless non-magic binary can be verified by strong byte evidence", () => {
    const bytes = [
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
    ];
    const result = fetchedBinary("payload", bytes);
    assert.equal(result.classification, "binary");
    assert.equal(result.classificationReason, "strong_binary_byte_evidence");
});

test("valid UTF-8 and BOM-marked UTF-16 remain text", () => {
    const validUtf8Controls = fetchedBinary("controls", [0x00, 0x01, 0x02, 0x41]);
    assert.equal(validUtf8Controls.classification, "text");
    assert.equal(validUtf8Controls.encoding, "utf-8");

    const utf16le = fetchedBinary("script.ps1", [
        0xFF, 0xFE, 0x57, 0x00, 0x72, 0x00, 0x69, 0x00, 0x74, 0x00, 0x65, 0x00,
    ]);
    const utf16be = fetchedBinary("script.cmd", [
        0xFE, 0xFF, 0x00, 0x65, 0x00, 0x63, 0x00, 0x68, 0x00, 0x6F,
    ]);
    assert.equal(utf16le.classification, "text");
    assert.equal(utf16le.encoding, "utf-16le");
    assert.match(utf16le.text, /Write/);
    assert.equal(utf16be.classification, "text");
    assert.equal(utf16be.encoding, "utf-16be");
    assert.match(utf16be.text, /echo/);
});

test("extensionless binary is classified from bytes and can satisfy coverage", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [blob("payload")];
    recordEnumeratedEntries(state, entries);
    const result = fetchedBinary("payload", [0x7F, 0x45, 0x4C, 0x46, 0x00, 0x01]);
    assert.equal(result.classification, "binary");
    assert.equal(result.likelyBinaryByExtension, false);
    recordFetchResult(state, { path: "payload", scope: "mandatory", result });
    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.deterministicMandatory.classifiedBinaryBlobs, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, true);
});

test("oversized binary remains an explicit mandatory acquisition gap", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [blob("large.bin")];
    recordEnumeratedEntries(state, entries);
    const result = fetchedBinary(
        "large.bin",
        syntheticPe(),
        BLOB_A,
        { maxBytes: 4 },
    );
    assert.equal(result.contentTooLarge, true);
    recordFetchResult(state, { path: "large.bin", scope: "mandatory", result });
    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.acquisition.observedOutcomes.oversizedMetadataOnlyFiles, 1);
    assert.equal(snapshot.deterministicMandatory.missingOrIncomplete, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, false);
});

test("unfetchable binary-looking blob remains an explicit gap", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = [blob("missing.exe")];
    recordEnumeratedEntries(state, entries);
    recordFetchFailure(state, {
        path: "missing.exe",
        scope: "mandatory",
        error: new Error("synthetic refusal"),
    });
    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.acquisition.fetchFailureAttempts, 1);
    assert.equal(snapshot.deterministicMandatory.missingOrIncomplete, 1);
    assert.equal(snapshot.requiredAcquisitionComplete, false);
});

test("zero-file repositories can complete mandatory acquisition", () => {
    const emptyState = createCoverageState(COMMIT, ROOT);
    const emptySnapshot = buildCoverageSnapshot(emptyState, completeTreeState([]));
    assert.equal(emptySnapshot.enumeration.uniqueFiles, 0);
    assert.equal(emptySnapshot.requiredAcquisitionComplete, true);
});

test("every blob path requires classification regardless of suffix", () => {
    assert.equal(isRequiredBlobPath("src/main.js"), true);
    assert.equal(isRequiredBlobPath("Makefile"), true);
    assert.equal(isRequiredBlobPath(".env"), true);
    assert.equal(isRequiredBlobPath("tool.EXE"), true);
    assert.equal(isRequiredBlobPath(`tool.exe${String.fromCodePoint(0x2060)}`), true);
    assert.equal(scanInvisibleUnicode("plain").matchCount, 0);
});

test("bounded snapshots cap required-blob gap details", () => {
    const state = createCoverageState(COMMIT, ROOT);
    const entries = Array.from({ length: 55 }, (_, index) =>
        blob(`src/file-${String(index).padStart(2, "0")}.js`, index % 2 ? BLOB_A : BLOB_B));
    recordEnumeratedEntries(state, entries);
    const snapshot = buildCoverageSnapshot(state, completeTreeState(entries));
    assert.equal(snapshot.deterministicMandatory.missingOrIncomplete, 55);
    assert.equal(snapshot.details.missingOrIncomplete.length, 50);
    assert.equal(snapshot.details.notFetched.length, 50);
    assert.equal(snapshot.bounded.missingOrIncompleteTruncated, true);
    assert.equal(snapshot.bounded.notFetchedTruncated, true);
});

test("list and fetch handlers expose required classification and running coverage", async () => {
    const sessionId = `coverage-handler-${Math.random().toString(36).slice(2)}`;
    activateUrlAudit(sessionId);
    try {
        const listed = await enumerate(sessionId, [blob("src/index.js")]);
        assert.equal(listed.resultType, "success");
        const listBody = parseResult(listed);
        assert.equal(listBody.entries[0].classificationRequired, true);
        assert.equal(listBody.entries[0].likelyBinaryByExtension, false);
        assert.equal(listBody.acquisitionCoverage.requiredAcquisitionComplete, false);

        const fetched = await safeFetchFileHandler(
            {
                owner: "octocat",
                repo: "demo",
                sha: COMMIT,
                path: "src/index.js",
                coverage_scope: "mandatory",
            },
            {
                sessionId,
                apiClient: {
                    fetchFile: () => fetchedText("src/index.js", "const x = 1;"),
                },
            },
        );
        assert.equal(fetched.resultType, "success");
        const fetchBody = parseResult(fetched);
        assert.equal(fetchBody.coverageScope, "mandatory");
        assert.equal(fetchBody.invisibleUnicodeScan.complete, true);
        assert.equal(fetchBody.acquisitionCoverage.requiredAcquisitionComplete, true);

        const duplicate = await safeFetchFileHandler(
            {
                owner: "octocat",
                repo: "demo",
                sha: COMMIT,
                path: "src/index.js",
                coverage_scope: "mandatory",
            },
            {
                sessionId,
                apiClient: {
                    fetchFile: () => fetchedText("src/index.js", "const x = 1;"),
                },
            },
        );
        const duplicateBody = parseResult(duplicate);
        assert.equal(duplicateBody.acquisitionCoverage.acquisition.uniqueFetchedFiles, 1);
        assert.equal(duplicateBody.acquisitionCoverage.acquisition.duplicateFetchCalls, 1);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("fetch handler records failures and rejects invalid coverage scope", async () => {
    const sessionId = `coverage-failure-${Math.random().toString(36).slice(2)}`;
    activateUrlAudit(sessionId);
    try {
        await enumerate(sessionId, [blob("src/index.js")]);
        const invalid = await safeFetchFileHandler(
            {
                owner: "octocat",
                repo: "demo",
                sha: COMMIT,
                path: "src/index.js",
                coverage_scope: "other",
            },
            { sessionId },
        );
        assert.equal(invalid.resultType, "failure");
        assert.match(invalid.textResultForLlm, /coverage_scope/);

        const failed = await safeFetchFileHandler(
            {
                owner: "octocat",
                repo: "demo",
                sha: COMMIT,
                path: "src/index.js",
                coverage_scope: "mandatory",
            },
            {
                sessionId,
                apiClient: {
                    fetchFile: () => {
                        throw new Error("synthetic fetch failure");
                    },
                },
            },
        );
        assert.equal(failed.resultType, "failure");
        const body = parseResult(failed);
        assert.equal(body.acquisitionCoverage.acquisition.fetchFailureAttempts, 1);
        assert.equal(body.acquisitionCoverage.requiredAcquisitionComplete, false);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("active audit coverage is isolated by session and reset on reactivation", async () => {
    const sessionA = `coverage-session-a-${Math.random().toString(36).slice(2)}`;
    const sessionB = `coverage-session-b-${Math.random().toString(36).slice(2)}`;
    activateUrlAudit(sessionA);
    activateUrlAudit(sessionB);
    try {
        await enumerate(sessionA, [blob("a.js")]);
        await enumerate(sessionB, [blob("b.js"), blob("c.js", BLOB_B)]);
        assert.equal(getAcquisitionCoverageState(sessionA).enumeratedFiles.length, 1);
        assert.equal(getAcquisitionCoverageState(sessionB).enumeratedFiles.length, 2);

        activateUrlAudit(sessionA);
        assert.equal(getAcquisitionCoverageState(sessionA), null);
        assert.equal(getAcquisitionCoverageState(sessionB).enumeratedFiles.length, 2);
    } finally {
        deactivateAudit(sessionA);
        deactivateAudit(sessionB);
    }
});

test("no-red-flags outcome is blocked until mandatory acquisition completes", async () => {
    const sessionId = `coverage-outcome-${Math.random().toString(36).slice(2)}`;
    const auditId = activateUrlAudit(sessionId, "audit_source_council");
    try {
        await enumerate(sessionId, [blob("payload.exe")]);
        const blocked = await recordOutcomeHandler(
            {
                audit_id: auditId,
                verdict: "no red flags found",
                critical_count: 0,
                high_count: 0,
                complete: true,
            },
            { sessionId },
        );
        assert.equal(blocked.resultType, "failure");
        assert.match(blocked.textResultForLlm, /mandatory acquisition coverage/i);

        await safeFetchFileHandler(
            {
                owner: "octocat",
                repo: "demo",
                sha: COMMIT,
                path: "payload.exe",
                coverage_scope: "mandatory",
            },
            {
                sessionId,
                apiClient: {
                    fetchFile: () => fetchedText(
                        "payload.exe",
                        "console.log('text under exe');",
                    ),
                },
            },
        );
        const accepted = await recordOutcomeHandler(
            {
                audit_id: auditId,
                verdict: "no red flags found",
                critical_count: 0,
                high_count: 0,
                complete: true,
            },
            { sessionId },
        );
        assert.equal(accepted.resultType, "success");
        assert.equal(
            parseResult(accepted).acquisitionCoverage.requiredAcquisitionComplete,
            true,
        );
    } finally {
        clearRecordedOutcome(sessionId);
        deactivateAudit(sessionId);
    }
});

test("report finalizer recognizes normalized verdict lines and blocks incomplete no-red reports", async () => {
    const sessionId = `coverage-report-${Math.random().toString(36).slice(2)}`;
    activateUrlAudit(sessionId);
    try {
        await enumerate(sessionId, [blob("src/index.js")]);
        const verdictLines = [
            "- **Verdict:** no red flags found",
            "**Verdict**: no red flags found",
            "_Verdict_: no red flags found",
            "### Verdict:   no red flags found.",
        ];
        for (const verdictLine of verdictLines) {
            assert.equal(
                reportInternals.extractDeclaredVerdict(verdictLine),
                "no red flags found",
            );
            const result = await finalizeReportHandler(
                {
                    owner: "octocat",
                    repo: "demo",
                    resolved_sha: COMMIT,
                    markdown_body: [
                        "# report",
                        "",
                        verdictLine,
                    ].join("\n"),
                },
                { sessionId },
            );
            assert.equal(result.resultType, "failure");
            const body = parseResult(result);
            assert.match(body.error, /mandatory acquisition coverage/i);
            assert.equal(body.acquisitionCoverage.requiredAcquisitionComplete, false);
        }
        assert.equal(
            reportInternals.extractDeclaredVerdict([
                "Verdict: incomplete",
                "Verdict: no red flags found",
            ].join("\n")),
            "no red flags found",
        );
        assert.equal(
            reportInternals.extractDeclaredVerdict(
                "The report mentions the verdict: no red flags found.",
            ),
            null,
        );
    } finally {
        deactivateAudit(sessionId);
    }
});

test("API-direct packet requires whole-tree mandatory acquisition and quantitative reporting", () => {
    const packet = buildInstructionPacket({
        mode: "audit_source",
        parsed: {
            owner: "octocat",
            repo: "demo",
            ref: "main",
            refType: "branch_or_tag",
            kind: "tree",
            canonicalUrl: "https://github.com/octocat/demo/tree/main",
        },
        refOverride: null,
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "coverage-packet",
        scrubNote: null,
        privateRepoAck: true,
        buildExecAck: false,
        unsafeAck: false,
        buildRoot: BUILD_ROOT,
        expectedClonePath: CLONE_PATH,
        expectedReportPath: buildReportPath(BUILD_ROOT, "octocat", "demo", "0".repeat(40)),
        expectedQuarantinePath: buildQuarantinePath(BUILD_ROOT, "octocat", "demo", "0".repeat(40)),
        placeholderSha: true,
        councilManifest: null,
        councilJudgeModel: null,
        councilSubJudgeModel: null,
        maxPremiumCalls: null,
    });

    assert.match(packet, /classificationRequired === true/);
    assert.match(packet, /plain-text payloads named/i);
    assert.match(packet, /filename suffixes do not establish content type/i);
    assert.match(packet, /coverage_scope: "mandatory"/);
    assert.match(packet, /council samples are advisory/i);
    assert.match(packet, /requiredAcquisitionComplete === true/);
    assert.match(packet, /## Acquisition coverage \(API-direct/);
    assert.match(packet, /Mandatory blobs classified\+inspected \/ required/);
    assert.doesNotMatch(packet, /Don't fetch every file/);
});
