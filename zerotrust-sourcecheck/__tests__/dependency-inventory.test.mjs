import assert from "node:assert/strict";
import { test } from "node:test";

import {
    DEPENDENCY_BLOCKERS,
    parseDependencyManifest,
    parseDependencyManifests,
} from "../analysis/index.mjs";
import {
    __internals as dependencyInternals,
} from "../analysis/dependencyInventory.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE = "github.com/example/repo@" + "a".repeat(40);
const HASH = "a".repeat(64);

function parse(path, text) {
    return parseDependencyManifest({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path,
        text,
    });
}

test("dependency inventory unique sorting accepts only bounded collection inputs", () => {
    assert.deepEqual(
        dependencyInternals.uniqueSorted(["zeta", "alpha", "zeta", null], 2),
        ["alpha", "zeta"],
    );
    assert.deepEqual(
        dependencyInternals.uniqueSorted(new Set(["zeta", "alpha", "zeta"]), 2),
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
    assert.deepEqual(dependencyInternals.uniqueSorted(iterable, 2), ["alpha", "zeta"]);
    assert.equal(visited, 2);
    assert.throws(() => dependencyInternals.uniqueSorted("source text", 2), TypeError);
    assert.throws(() => dependencyInternals.uniqueSorted({ alpha: true }, 2), TypeError);
});

test("npm lock inventory captures exact registry, alias, local, hook, and Git forms", () => {
    const lock = JSON.stringify({
        name: "fixture",
        lockfileVersion: 3,
        packages: {
            "": {
                dependencies: {
                    alias: "npm:real-package@1.2.3",
                    local: "file:../local",
                    mutable: "github:owner/repo#main",
                },
            },
            "node_modules/alias": {
                version: "npm:real-package@1.2.3",
                integrity: "sha512-YWJj",
                hasInstallScript: true,
            },
            "node_modules/local": {
                resolved: "file:../local",
                link: true,
            },
            "node_modules/mutable": {
                version: "git+https://github.com/owner/repo.git#main",
            },
        },
    });
    const inventory = parse("package-lock.json", lock);
    const alias = inventory.packages.find((entry) => entry.name === "alias");
    const local = inventory.packages.find((entry) => entry.name === "local");
    const git = inventory.packages.find((entry) => entry.name === "mutable");

    assert.equal(alias.aliasFor, "real-package");
    assert.match(alias.artifactUrl, /real-package.*1\.2\.3\.tgz$/u);
    assert.deepEqual(alias.lifecycleHooks, ["install-script-present"]);
    assert.equal(local.sourceType, "local");
    assert.equal(local.localPath, "node_modules/local");
    assert.equal(git.sourceType, "git");
    assert.equal(git.git.mutable, true);
    assert.ok(git.blockerCodes.includes(DEPENDENCY_BLOCKERS.MUTABLE_REF));
    assert.ok(git.blockerCodes.includes(DEPENDENCY_BLOCKERS.UNSUPPORTED_REGISTRY));
});

test("Cargo.lock inventory binds registry checksums, workspace roots, and Git commits", () => {
    const commit = "b".repeat(40);
    const inventory = parse("Cargo.lock", `
version = 4

[[package]]
name = "workspace-root"
version = "0.1.0"
dependencies = [
 "serde 1.0.203",
 "gitdep 2.0.0 (git+https://github.com/example/gitdep?rev=previous#${commit})",
]

[[package]]
name = "serde"
version = "1.0.203"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "${HASH}"

[[package]]
name = "gitdep"
version = "2.0.0"
source = "git+https://github.com/example/gitdep?rev=previous#${commit}"
`);
    const serde = inventory.packages.find((entry) => entry.name === "serde");
    const git = inventory.packages.find((entry) => entry.name === "gitdep");
    const root = inventory.packages.find((entry) => entry.name === "workspace-root");

    assert.equal(serde.registryHost, "static.crates.io");
    assert.match(serde.artifactUrl, /\.crate$/u);
    assert.equal(serde.integrity[0].algorithm, "sha256");
    assert.equal(root.sourceType, "workspace");
    assert.equal(git.git.commit, commit);
    assert.equal(git.git.mutable, false);
    assert.ok(git.blockerCodes.includes(DEPENDENCY_BLOCKERS.UNSUPPORTED_REGISTRY));
    assert.equal(inventory.edges.length, 2);
});

test("hashed requirements, Poetry, and Pipfile locks preserve exact Python identities", () => {
    const requirements = parse(
        "requirements.txt",
        `demo==1.2.3 --hash=sha256:${HASH}\n`
        + `gitdep @ git+https://github.com/example/gitdep.git@main\n`,
    );
    const demo = requirements.packages.find((entry) => entry.name === "demo");
    assert.equal(demo.version, "1.2.3");
    assert.equal(demo.metadataUrl, "https://pypi.org/pypi/demo/1.2.3/json");
    assert.equal(demo.integrity[0].digest, HASH);

    const poetry = parse("poetry.lock", `
[[package]]
name = "poetry-demo"
version = "4.5.6"
description = ""
optional = false
python-versions = "*"
files = [
    {file = "poetry_demo-4.5.6-py3-none-any.whl", hash = "sha256:${HASH}"},
]
`);
    assert.equal(poetry.packages[0].artifactCandidates[0].file,
        "poetry_demo-4.5.6-py3-none-any.whl");

    const pipfile = parse("Pipfile.lock", JSON.stringify({
        _meta: {},
        default: {
            pipdemo: {
                version: "==7.8.9",
                hashes: [`sha256:${HASH}`],
            },
        },
        develop: {},
    }));
    assert.equal(pipfile.packages[0].version, "7.8.9");
    assert.equal(pipfile.packages[0].registryHost, "pypi.org");
});

test("NuGet lockfiles derive exact nupkg URLs and packages.config stays blocked", () => {
    const contentHash = Buffer.from("nuget-hash").toString("base64");
    const locked = parse("packages.lock.json", JSON.stringify({
        version: 1,
        dependencies: {
            "net8.0": {
                Parent: {
                    type: "Direct",
                    requested: "[1.0.0, )",
                    resolved: "1.0.0",
                    contentHash,
                    dependencies: { Child: "2.0.0" },
                },
                Child: {
                    type: "Transitive",
                    resolved: "2.0.0",
                    contentHash,
                },
            },
        },
    }));
    assert.equal(locked.packages.length, 2);
    assert.equal(locked.edges.length, 1);
    assert.match(
        locked.packages.find((entry) => entry.name === "Parent").artifactUrl,
        /parent\.1\.0\.0\.nupkg$/u,
    );

    const legacy = parse(
        "packages.config",
        `<packages><package id="Legacy" version="3.0.0" /></packages>`,
    );
    assert.ok(legacy.blockerCodes.includes(DEPENDENCY_BLOCKERS.MISSING_INTEGRITY));
});

test("inventory sets remain audit-bound across multiple ecosystems", () => {
    const set = parseDependencyManifests({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        manifests: [
            {
                path: "requirements.txt",
                text: `demo==1.0.0 --hash=sha256:${HASH}\n`,
            },
            {
                path: "packages.config",
                text: `<packages><package id="Legacy" version="3.0.0" /></packages>`,
            },
        ],
    });
    assert.equal(set.inventories.length, 2);
    assert.equal(set.auditId, AUDIT_ID);
    assert.match(set.hashes.inventorySetSha256, /^[a-f0-9]{64}$/u);
});
