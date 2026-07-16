import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { test } from "node:test";

import {
    fetchDependencyHttpsBuffer,
    safeInventoryDependenciesHandler,
    validateDependencyRegistryUrl,
} from "../safeWrappers/dependencyFetchWrapper.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE = "github.com/example/repo@" + "a".repeat(40);

function sha256(text) {
    return createHash("sha256").update(text, "utf8").digest("hex");
}

function parseResult(result) {
    return JSON.parse(result.textResultForLlm);
}

function assuranceWrapperDependencies(path, content) {
    return {
        getContext:() => ({
            ok: true,
            hasActiveAudit: true,
            auditId: AUDIT_ID,
            buildRoot: "C:\\fixture",
        }),
        getIndexState:() => ({
            files: [{
                path,
                size: Buffer.byteLength(content),
                status: "indexed-text",
                classification: "text",
                contentSha256: sha256(content),
            }],
        }),
        getAssuranceState:() => ({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
        }),
        getAssuranceSnapshot:() => null,
        recordAssuranceSnapshot:() => {
            throw new Error("not expected");
        },
        recordAssuranceSupplyChainGraph:() => {},
    };
}

test("dependency inventory wrapper binds lockfile bytes to the active audit index", async () => {
    const content = JSON.stringify({
        lockfileVersion: 3,
        packages: {
            "": { dependencies: { demo: "1.0.0" } },
            "node_modules/demo": {
                version: "1.0.0",
                resolved: "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                integrity: "sha512-YWJj",
            },
        },
    });
    const result = await safeInventoryDependenciesHandler({
        audit_id: AUDIT_ID,
        manifests: [{
            path: "package-lock.json",
            content,
            content_sha256: sha256(content),
        }],
    }, { sessionId: "dependency-wrapper-test" }, assuranceWrapperDependencies(
        "package-lock.json",
        content,
    ));
    const body = parseResult(result);
    assert.equal(result.resultType, "success");
    assert.equal(body.supplyChain.auditId, AUDIT_ID);
    assert.equal(body.fetchedArtifacts, false);
});

test("dependency inventory wrapper refuses unindexed or changed manifest bytes", async () => {
    const content = JSON.stringify({ lockfileVersion: 3, packages: {} });
    const changed = `${content}\n`;
    const result = await safeInventoryDependenciesHandler({
        audit_id: AUDIT_ID,
        manifests: [{
            path: "package-lock.json",
            content: changed,
            content_sha256: sha256(changed),
        }],
    }, { sessionId: "dependency-wrapper-mismatch" }, assuranceWrapperDependencies(
        "package-lock.json",
        content,
    ));
    assert.equal(result.resultType, "failure");
    assert.match(parseResult(result).error, /not bound to exact fully indexed audit bytes/u);
});

test("registry URL validation is HTTPS-only, host/path allowlisted, and filename-bound", () => {
    assert.equal(
        validateDependencyRegistryUrl(
            "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
            { kind: "artifact", expectedFileName: "demo-1.0.0.tgz" },
        ).hostname,
        "registry.npmjs.org",
    );
    assert.throws(() => validateDependencyRegistryUrl(
            "http://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
            { kind: "artifact" },
        ),
        /strict HTTPS registry allowlist/u,
    );
    assert.throws(() => validateDependencyRegistryUrl(
            "https://evil.example/demo-1.0.0.tgz",
            { kind: "artifact" },
        ),
        /strict HTTPS registry allowlist/u,
    );
    assert.throws(() => validateDependencyRegistryUrl(
            "https://registry.npmjs.org/demo/-/other-1.0.0.tgz",
            { kind: "artifact", expectedFileName: "demo-1.0.0.tgz" },
        ),
        /filename does not match/u,
    );
});

test("Node HTTPS fetch enforces response size and rejects off-allowlist redirects", async () => {
    const packageRecord = {
        packageId: "ztdp-" + "a".repeat(64),
        ecosystem: "npm",
        registryHost: "registry.npmjs.org",
    };
    const responseRequest = (statusCode, headers, chunks) =>
        (_url, _options, callback) => {
            const request = new EventEmitter();
            request.setTimeout = () => {};
            request.destroy = (error) => request.emit("error", error);
            request.end = () => {
                const response = Readable.from(chunks);
                response.statusCode = statusCode;
                response.headers = headers;
                callback(response);
            };
            return request;
        };

    await assert.rejects(
        fetchDependencyHttpsBuffer(
            "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
            {
                kind: "artifact",
                packageRecord,
                expectedFileName: "demo-1.0.0.tgz",
                limits: {
                    requestTimeoutMs: 1_000,
                    maxRedirects: 0,
                    maxResponseBytes: 3,
                },
                remainingTotalBytes: 3,
                requestImpl: responseRequest(200, {
                    "content-length": "4",
                    "content-encoding": "identity",
                }, [Buffer.from("four")]),
            },
        ),
        /byte cap/u,
    );

    await assert.rejects(
        fetchDependencyHttpsBuffer(
            "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
            {
                kind: "artifact",
                packageRecord,
                expectedFileName: "demo-1.0.0.tgz",
                limits: {
                    requestTimeoutMs: 1_000,
                    maxRedirects: 2,
                    maxResponseBytes: 1024,
                },
                remainingTotalBytes: 1024,
                requestImpl: responseRequest(302, {
                    location: "https://evil.example/demo-1.0.0.tgz",
                }, []),
            },
        ),
        /strict HTTPS registry allowlist/u,
    );
});

test("extension registers dependency tools in the current assurance lifecycle", () => {
    const extensionSource = readFileSync(
        new URL("../extension.mjs", import.meta.url),
        "utf8",
    );
    assert.match(extensionSource, /name: "zerotrust_inventory_dependencies"/u);
    assert.match(extensionSource, /name: "zerotrust_analyze_dependencies"/u);
    assert.match(extensionSource, /Every activation owns one current assurance lifecycle/u);
});
