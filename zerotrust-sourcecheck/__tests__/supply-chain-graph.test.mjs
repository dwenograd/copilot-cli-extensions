import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

import {
    DEPENDENCY_BLOCKERS,
    analyzeSupplyChain,
    applySupplyChainGraphToAssuranceSnapshot,
    buildSupplyChainGraph,
    createInitialAssuranceStageState,
    createAssuranceAnalysisSnapshot,
    createEvasiveObjectInventoryRecord,
    parseDependencyManifests,
    validateSupplyChainGraph,
    verifyDeclaredIntegrity,
} from "../analysis/index.mjs";
import {
    __internals as supplyChainInternals,
} from "../analysis/supplyChainGraph.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE = "github.com/example/repo@" + "a".repeat(40);

function sha256(buffer) {
    return createHash("sha256").update(buffer).digest("hex");
}

function sri(buffer, algorithm = "sha512") {
    return `${algorithm}-${createHash(algorithm).update(buffer).digest("base64")}`;
}

function tarOctal(value, length) {
    return `${value.toString(8).padStart(length - 1, "0")}\0`;
}

function makeTar(entries) {
    const blocks = [];
    for (const [path, content] of entries) {
        const bytes = Buffer.from(content);
        const header = Buffer.alloc(512);
        header.write(path, 0, 100, "ascii");
        header.write(tarOctal(0o644, 8), 100, 8, "ascii");
        header.write(tarOctal(0, 8), 108, 8, "ascii");
        header.write(tarOctal(0, 8), 116, 8, "ascii");
        header.write(tarOctal(bytes.length, 12), 124, 12, "ascii");
        header.write(tarOctal(0, 12), 136, 12, "ascii");
        header.fill(0x20, 148, 156);
        header[156] = 0x30;
        header.write("ustar\0", 257, 6, "ascii");
        header.write("00", 263, 2, "ascii");
        let checksum = 0;
        for (const byte of header) checksum += byte;
        header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
        blocks.push(header, bytes);
        const padding = (512 - (bytes.length % 512)) % 512;
        if (padding) blocks.push(Buffer.alloc(padding));
    }
    blocks.push(Buffer.alloc(1024));
    return Buffer.concat(blocks);
}

function npmInventory(artifact, {
    includeChild = false,
    integrity = sri(artifact),
} = {}) {
    const packages = {
        "": { dependencies: { demo: "1.0.0" } },
        "node_modules/demo": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
            integrity,
            dependencies: includeChild ? { child: "2.0.0" }: {},
        },
    };
    if (includeChild) {
        packages["node_modules/child"] = {
            version: "2.0.0",
            resolved: "https://registry.npmjs.org/child/-/child-2.0.0.tgz",
            integrity,
        };
    }
    const text = JSON.stringify({ lockfileVersion: 3, packages });
    return {
        text,
        set: parseDependencyManifests({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            manifests: [{ path: "package-lock.json", text }],
        }),
    };
}

test("supply-chain unique sorting accepts Sets and caps generic iterables", () => {
    assert.deepEqual(
        supplyChainInternals.uniqueSorted(new Set(["zeta", "alpha", "zeta"]), 2),
        ["alpha", "zeta"],
    );
    let visited = 0;
    const iterable = {
        *[Symbol.iterator]() {
            for (const value of ["zeta", "alpha", "beta"]) {
                visited += 1;
                yield value;
            }
        },
    };
    assert.deepEqual(supplyChainInternals.uniqueSorted(iterable, 2), ["alpha", "zeta"]);
    assert.equal(visited, 2);
    assert.throws(() => supplyChainInternals.uniqueSorted("source text", 2), TypeError);
    assert.throws(() => supplyChainInternals.uniqueSorted({ alpha: true }, 2), TypeError);
});

test("declared integrity is checked before package content analysis", async () => {
    const artifact = gzipSync(makeTar([
        ["package/package.json", JSON.stringify({
            name: "demo",
            version: "1.0.0",
            scripts: { install: "node install.js", prepare: "node prepare.js" },
        })],
        ["package/index.js", "require('node:child_process').exec('echo test');"],
    ]));
    const { set } = npmInventory(artifact);
    const graph = await analyzeSupplyChain({
        inventorySet: set,
        fetchBuffer: async () => Buffer.from(artifact),
    });
    const packageNode = graph.nodes.find((node) => node.nodeKind === "package");
    const artifactNode = graph.nodes.find((node) => node.nodeKind === "artifact");

    assert.equal(packageNode.status, "analyzed");
    assert.deepEqual(packageNode.lifecycleHooks, ["npm:install", "npm:prepare"]);
    assert.ok(packageNode.analysis.factCount > 0);
    assert.equal(artifactNode.status, "analyzed");
    assert.equal(graph.counts.packagesAnalyzed, 1);
    assert.equal(graph.blockerCodes.includes(DEPENDENCY_BLOCKERS.HASH_MISMATCH), false);
});

test("hash mismatch blocks analysis and produces no artifact node", async () => {
    const artifact = gzipSync(makeTar([["package/index.js", "console.log('ok')"]]));
    const { set } = npmInventory(artifact, { integrity: "sha512-YWJj" });
    const graph = await analyzeSupplyChain({
        inventorySet: set,
        fetchBuffer: async () => Buffer.from(artifact),
    });
    assert.ok(graph.blockerCodes.includes(DEPENDENCY_BLOCKERS.HASH_MISMATCH));
    assert.equal(graph.nodes.some((node) => node.nodeKind === "artifact"), false);
    assert.equal(graph.counts.packagesAnalyzed, 0);
});

test("exact transitive traversal remains bounded by recursion depth", async () => {
    const artifact = gzipSync(makeTar([["package/index.js", "export const ok = true;"]]));
    const { set } = npmInventory(artifact, { includeChild: true });
    const graph = await analyzeSupplyChain({
        inventorySet: set,
        limits: { maxDepth: 0 },
        fetchBuffer: async () => Buffer.from(artifact),
    });
    assert.ok(graph.blockerCodes.includes(DEPENDENCY_BLOCKERS.RECURSION_CAP));
    assert.equal(graph.counts.packagesAnalyzed, 1);
    assert.equal(graph.counts.deepestLevel, 1);
});

test("package, artifact, and provenance graph identities are canonical", () => {
    const artifact = Buffer.from("artifact");
    const { set } = npmInventory(artifact);
    const graph = buildSupplyChainGraph({ inventorySet: set });
    assert.deepEqual(validateSupplyChainGraph(graph), graph);
    assert.ok(graph.nodes.some((node) => node.nodeKind === "package"));
    assert.ok(graph.nodes.some((node) => node.nodeKind === "provenance"));
    assert.ok(graph.edges.some((edge) => edge.kind === "declared-in"));
    assert.throws(() => validateSupplyChainGraph({
            ...graph,
            counts: { ...graph.counts, packages: graph.counts.packages + 1 },
        }),
        /component hashes/u,
    );
});

test("supply-chain graphs add dependency-graph artifacts to exact assurance manifests", () => {
    const artifact = Buffer.from("artifact");
    const { text, set } = npmInventory(artifact);
    const graph = buildSupplyChainGraph({ inventorySet: set });
    const object = createEvasiveObjectInventoryRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path: "package-lock.json",
        parentObjectId: null,
        objectKind: "manifest",
        byteLength: Buffer.byteLength(text),
        status: "inventoried",
        blockerCodes: [],
        contentSha256: sha256(Buffer.from(text)),
        upstreamSha: null,
    });
    const snapshot = createAssuranceAnalysisSnapshot({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        stageState: createInitialAssuranceStageState({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
        }),
        status: "incomplete",
        objectInventory: [object],
        derivedArtifacts: [],
        semanticReviewCoverage: [],
        redTeamCoverage: [],
        blockerCodes: [],
        sourceIdentitySha256: "b".repeat(64),
    });
    const integrated = applySupplyChainGraphToAssuranceSnapshot({ snapshot, graph });
    assert.equal(integrated.applied, true);
    assert.equal(integrated.artifacts[0].artifactKind, "dependency-graph");
    assert.equal(integrated.snapshot.derivedArtifacts.length, 1);
});

test("integrity verifier supports the lockfile hash encodings", () => {
    const buffer = Buffer.from("verified");
    assert.equal(verifyDeclaredIntegrity(buffer, [{
        algorithm: "sha256",
        encoding: "hex",
        digest: createHash("sha256").update(buffer).digest("hex"),
    }]).verified, true);
    assert.equal(verifyDeclaredIntegrity(buffer, [{
        algorithm: "sha512",
        encoding: "base64",
        digest: createHash("sha512").update(buffer).digest("base64"),
    }]).verified, true);
});
