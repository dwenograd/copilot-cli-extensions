import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
    SCANNER_SCHEMA_REVISION,
    SEMANTIC_FACT_KINDS,
    createSemanticPluginInput,
    extractFactsFromText,
    scanSourceText,
    selectScanner,
    validateScannerResult,
    validateSemanticPluginInput,
} from "../analysis/index.mjs";
import {
    createAnalysisIndexState,
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import { buildPluginContext } from "../analysis/plugins/index.mjs";
import {
    METAMORPHIC_SCANNER_FIXTURES,
} from "./fixtures/evasiveLanguageScannerFixtures.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";

function sha256(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

function semanticSignature(result) {
    return result.facts.map((fact) => JSON.stringify({
        kind: fact.kind,
        name: fact.name,
        value: fact.value || null,
        target: fact.target || null,
        resolution: fact.resolution || null,
        tags: fact.tags || [],
    })).sort();
}

test("assurance registry selects every required language family with a generic fallback", () => {
    const selections = {
        "src/index.ts": "scanner.javascript-typescript",
        "package.jsonc": "scanner.json-jsonc",
        "setup.py": "scanner.python",
        "scripts/install.ps1": "scanner.powershell-shell",
        "scripts/install.sh": "scanner.powershell-shell",
        "src/Program.cs": "scanner.csharp",
        "Directory.Build.targets": "scanner.msbuild-xml",
        "build.rs": "scanner.rust",
        "Cargo.toml": "scanner.cargo-toml",
        ".github/workflows/build.yml": "scanner.yaml-github-actions",
        "Dockerfile": "scanner.docker-devcontainer",
        ".devcontainer/devcontainer.json": "scanner.docker-devcontainer",
        "CMakeLists.txt": "scanner.cmake-make",
        "Makefile": "scanner.cmake-make",
        "unknown.ztfixture": "scanner.generic",
    };
    for (const [path, scannerId] of Object.entries(selections)) {
        assert.equal(selectScanner(path).id, scannerId, path);
    }
});

test("baseline extraction remains available while assurance ranges hash exact source slices", () => {
    const source = [
        "{",
        '  "scripts": {',
        '    "postinstall": "node first.js",',
        '    "postinstall": "pwsh second.ps1"',
        "  }",
        "}",
    ].join("\n");
    const baseline = extractFactsFromText({ path: "package.jsonc", text: source });
    assert.equal(baseline.lineCount, 6);
    assert.ok(baseline.facts.every((fact) => !Object.hasOwn(fact, "startOffset")));

    const assurance = scanSourceText({ path: "package.jsonc", text: source });
    assert.equal(assurance.schemaVersion, SCANNER_SCHEMA_REVISION);
    const commands = assurance.facts.filter((fact) =>
        fact.kind === "command-construction" && fact.name === "postinstall");
    assert.deepEqual(commands.map((fact) => fact.line), [3, 4]);
    assert.deepEqual(commands.map((fact) => fact.target), ["node", "pwsh"]);
    for (const fact of assurance.facts) {
        assert.equal(
            fact.excerptHash,
            sha256(source.slice(fact.startOffset, fact.endOffset)),
        );
        assert.ok(fact.endOffset > fact.startOffset);
        assert.ok(fact.endLine >= fact.line);
        assert.ok(fact.startColumn >= 1);
        assert.ok(fact.endColumn >= 1);
    }
});

test("bounded literal concatenation, arrays, joins, and lookups resolve command targets", () => {
    for (const fixture of METAMORPHIC_SCANNER_FIXTURES) {
        const result = scanSourceText({
            path: fixture.path,
            text: fixture.source,
        });
        for (const kind of fixture.expectedKinds) {
            assert.ok(
                result.facts.some((fact) => fact.kind === kind),
                `${fixture.name} missing ${kind}`,
            );
        }
        assert.ok(
            result.facts.some((fact) => fact.target === fixture.expectedTarget),
            `${fixture.name} did not resolve ${fixture.expectedTarget}`,
        );
    }
});

test("metamorphic layout and comment changes preserve semantic fact signatures", () => {
    for (const fixture of METAMORPHIC_SCANNER_FIXTURES) {
        const original = scanSourceText({
            path: fixture.path,
            text: fixture.source,
        });
        const variant = scanSourceText({
            path: fixture.path,
            text: fixture.variant,
        });
        assert.deepEqual(
            semanticSignature(variant),
            semanticSignature(original),
            fixture.name,
        );
        assert.notEqual(variant.sourceSha256, original.sourceSha256, fixture.name);
    }
});

test("dynamic targets remain explicit blockers rather than guessed commands or imports", () => {
    const source = [
        "const command = process.env.RUNTIME_COMMAND;",
        "child_process.spawn(command);",
        'const commands = { win: "pwsh" };',
        "const selected = commands[process.env.RUNTIME_PLATFORM];",
        "child_process.spawn(selected);",
        "import(process.env.RUNTIME_MODULE);",
    ].join("\n");
    const result = scanSourceText({ path: "src/runtime.mjs", text: source });
    const unresolved = result.facts.filter((fact) =>
        fact.kind === "unresolved-dynamic-target");
    assert.ok(unresolved.length >= 2);
    assert.ok(unresolved.every((fact) => fact.resolution === "dynamic"));
    assert.ok(unresolved.some((fact) => fact.value === "command-construction"));
    assert.ok(unresolved.some((fact) => fact.value === "dynamic-import"));
    assert.ok(!result.facts.some((fact) => fact.target === "pwsh"));
    assert.ok(result.facts
        .filter((fact) => ["command-construction", "dynamic-import"].includes(fact.kind))
        .some((fact) => !Object.hasOwn(fact, "target")));
});

test("scanner families collectively cover the complete assurance semantic taxonomy", () => {
    const sources = {
        "src/evasive.ts": [
            "import fs from 'node:fs';",
            "window.addEventListener('load', handler);",
            "const moduleName = process.env.RUNTIME_MODULE;",
            "import(moduleName);",
            "Reflect.apply(handler, null, []);",
            "eval(process.env.RUNTIME_CODE);",
            "child_process.exec(process.env.RUNTIME_COMMAND);",
            "fetch('https://example.invalid/payload');",
            "Buffer.from(payload, 'base64');",
            "fs.writeFileSync('generated.js', payload);",
            "if (process.env.ENABLED) child_process.exec('node generated.js');",
            "if (process.platform === 'win32') run;",
            "if (Date.now() > deadline) run;",
        ].join("\n"),
        "scripts/persist.ps1": "Register-ScheduledTask -TaskName Demo",
        "build.targets": [
            "<Project>",
            '  <UsingTask TaskName="Inline" TaskFactory="CodeTaskFactory" AssemblyFile="$(Asm)" />',
            "</Project>",
        ].join("\n"),
    };
    const kinds = new Set(Object.entries(sources).flatMap(([path, text]) =>
        scanSourceText({ path, text }).facts.map((fact) => fact.kind)));
    for (const kind of SEMANTIC_FACT_KINDS) {
        assert.ok(kinds.has(kind), `missing semantic kind ${kind}`);
    }
});

test("scanner limits fail closed and expose structured truncation blockers", () => {
    const source = Array.from(
        { length: 100 },
        (_, index) => `child_process.spawn("tool-${index}");`,
    ).join("\n");
    const result = scanSourceText({
        path: "src/many.js",
        text: source,
        maxFacts: 2,
        maxTokens: 40,
    });
    assert.equal(result.truncated, true);
    assert.equal(result.factCount, 2);
    assert.ok(result.blockers.some((blocker) => blocker.startsWith("bounds/")));
    assert.deepEqual(validateScannerResult(result), result);
});

test("semantic plugin inputs are source-text-free and bound to indexed file identity", () => {
    const path = "src/index.mjs";
    const source = [
        'const command = ["pw", "sh"].join("");',
        "child_process.spawn(command);",
    ].join("\n");
    const contentSha256 = sha256(source);
    const blobSha = "b".repeat(40);
    const extraction = extractFactsFromText({ path, text: source });
    const indexState = createAnalysisIndexState({
        auditId: AUDIT_ID,
        sourceKind: "api-direct",
    });
    recordIndexEnumeration(indexState, {
        entries: [{ path, size: Buffer.byteLength(source), blobSha }],
        complete: true,
    });
    recordIndexedFile(indexState, {
        path,
        size: Buffer.byteLength(source),
        classification: "text",
        classificationComplete: true,
        contentSha256,
        blobSha,
        facts: extraction.facts,
        factsOverflow: extraction.overflow,
        lineCount: extraction.lineCount,
        invisibleUnicodeScanComplete: true,
    });

    const scan = scanSourceText({ path, text: source });
    const semanticInput = createSemanticPluginInput(scan, { blobSha });
    assert.deepEqual(validateSemanticPluginInput(semanticInput), semanticInput);
    const context = buildPluginContext({
        auditId: AUDIT_ID,
        indexState,
        sourceNamespace: "github.com/example/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        semanticInputs: [semanticInput],
    });
    assert.equal(context.semanticCoverage.complete, true);
    assert.equal(context.semanticCoverage.providedFileCount, 1);
    assert.equal(context.semanticFacts.length, scan.factCount);
    assert.ok(context.semanticFacts.every((fact) => fact.file.path === path));
    assert.doesNotMatch(
        JSON.stringify({ semanticInput, context: context.semanticCoverage }),
        /child_process\.spawn|\["pw", "sh"\]/u,
    );

    assert.throws(() => buildPluginContext({
            auditId: AUDIT_ID,
            indexState,
            sourceNamespace:
                "github.com/example/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            semanticInputs: [{
                ...semanticInput,
                contentSha256: "c".repeat(64),
            }],
        }),
        /identity mismatch/u,
    );
});
