import { createHash } from "node:crypto";

import {
    validateIdentifier,
    validatePluginOutput,
} from "../schemas.mjs";
import { FACT_KINDS } from "../extractFacts.mjs";

const DEFINITION_FIELDS = new Set([
    "id",
    "version",
    "supports",
    "detect",
    "run",
]);

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function assertExactFields(value, allowed, label) {
    if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object`);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`${label}.${key} is not allowed`);
    }
}

    function normalizedValue(value, label) {
        if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
        const normalized = value.normalize("NFKC")
            .replace(/[\u0000-\u001f\u007f]+/gu, " ")
            .replace(/\s+/gu, " ")
            .trim();
        if (!normalized || normalized !== value || normalized.length > 256) {
            throw new TypeError(`${label} must be normalized and contain 1-256 characters`);
        }
        return normalized;
    }

    export function computePluginFactId(value) {
        const kind = String(value.kind || "");
        const path = String(value.path || "").replace(/\\/g, "/").replace(/^\.\/+/, "");
        const line = Number(value.line);
        const name = String(value.name || "");
        const factValue = value.value === undefined ? "": normalizedValue(
            value.value,
            "pluginFact.value",
        );
        return createHash("sha256")
            .update(`${kind}\0${path}\0${line}\0${name}\0${factValue}`, "utf8")
            .digest("hex");
    }

    export function validatePluginFact(value, path = "pluginFact") {
        assertExactFields(value, new Set([
            "id",
            "kind",
            "path",
            "line",
            "endLine",
            "excerptHash",
            "name",
            "value",
        ]), path);
        const normalizedPath = String(value.path || "").replace(/\\/g, "/").replace(/^\.\/+/, "");
        if (!normalizedPath || normalizedPath.length > 1024 || normalizedPath.startsWith("/")
            || normalizedPath.endsWith("/") || normalizedPath.includes("//")
            || normalizedPath.split("/").some((segment) => segment === "." || segment === "..")
            || /[\u0000-\u001f\u007f]/u.test(normalizedPath)) {
            throw new TypeError(`${path}.path is invalid`);
        }
        if (!FACT_KINDS.includes(value.kind)) {
            throw new TypeError(`${path}.kind is invalid`);
        }
        const line = Number(value.line);
        const endLine = Number(value.endLine);
        if (!Number.isSafeInteger(line) || line < 1 || line > 10_000_000
            || !Number.isSafeInteger(endLine) || endLine < line || endLine > 10_000_000) {
            throw new TypeError(`${path} line range is invalid`);
        }
        const normalized = {
            id: String(value.id || "").toLowerCase(),
            kind: value.kind,
            path: normalizedPath,
            line,
            endLine,
            excerptHash: String(value.excerptHash || "").toLowerCase(),
            name: validateIdentifier(value.name, `${path}.name`),
        };
        if (Object.hasOwn(value, "value")) {
            normalized.value = normalizedValue(value.value, `${path}.value`);
        }
        if (!/^[a-f0-9]{64}$/u.test(normalized.excerptHash)
            || !/^[a-f0-9]{64}$/u.test(normalized.id)
            || normalized.id !== computePluginFactId(normalized)) {
            throw new TypeError(`${path}.id must be canonically derived from the plugin fact`);
        }
        return Object.freeze(structuredClone(normalized));
}

export function definePlugin(definition) {
    assertExactFields(definition, DEFINITION_FIELDS, "plugin");
    const id = validateIdentifier(definition.id, "plugin.id");
    const version = String(definition.version || "").normalize("NFKC").trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/u.test(version)) {
        throw new TypeError("plugin.version is invalid");
    }
    for (const method of ["supports", "detect", "run"]) {
        if (typeof definition[method] !== "function") {
            throw new TypeError(`plugin.${method} must be a function`);
        }
    }
    return Object.freeze({
        id,
        version,
        supports: definition.supports,
        detect: definition.detect,
        run: definition.run,
    });
}

export function validatePluginExecutionResult(value, plugin) {
    assertExactFields(value, new Set(["output", "facts", "truncated"]), `${plugin.id}.result`);
    if (typeof value.truncated !== "boolean") {
        throw new TypeError(`${plugin.id}.result.truncated must be boolean`);
    }
    const output = validatePluginOutput(value.output, `${plugin.id}.output`);
    if (!Array.isArray(value.facts) || value.facts.length > 512) {
        throw new TypeError(`${plugin.id}.result.facts must contain at most 512 entries`);
    }
    const facts = value.facts.map((fact, index) =>
        validatePluginFact(fact, `${plugin.id}.facts[${index}]`));
    if (new Set(facts.map((fact) => fact.id)).size !== facts.length) {
        throw new TypeError(`${plugin.id}.result.facts contains duplicate IDs`);
    }
    if (output.pluginId !== plugin.id || output.pluginVersion !== plugin.version) {
        throw new TypeError(`${plugin.id} output identity does not match its registration`);
    }
    if (output.producer !== plugin.id) {
        throw new TypeError(`${plugin.id} output producer must equal pluginId`);
    }
    if (output.findings.length !== 0
        || output.validationDecisions.length !== 0
        || output.metadataDocuments.length !== 0) {
        throw new TypeError(
            `${plugin.id} activation plugins may emit only graph seeds and warnings`,
        );
    }
    for (const fact of facts) {
        if (!fact.path) throw new TypeError(`${plugin.id} fact path is required`);
    }
    const evidenceKeys = new Set(facts.map((fact) =>
        `${fact.path}\0${fact.line}\0${fact.endLine}\0${fact.excerptHash}`));
    for (const entry of [...output.nodes, ...output.edges]) {
        for (const evidence of entry.evidence) {
            const key = `${evidence.path}\0${evidence.startLine}\0${evidence.endLine}\0${evidence.excerptHash}`;
            if (!evidenceKeys.has(key)) {
                throw new TypeError(`${plugin.id} graph evidence has no emitted plugin fact`);
            }
        }
    }
    return Object.freeze({ output, facts, truncated: value.truncated });
}

export const __internals = Object.freeze({
    isPlainObject,
    assertExactFields,
    normalizedValue,
});
