import { createHash } from "node:crypto";
import nodePath from "node:path";

import {
    renderMarker,
    validateFixtureText,
} from "./fixtureSyntax.mjs";

export const METAMORPHIC_TRANSFORMS = Object.freeze([
    "rename",
    "whitespace-comments",
    "file-relocation",
    "string-split",
]);

function stableRename(prefix, value) {
    const digest = createHash("sha256")
        .update(`${prefix}\0${value}`, "utf8")
        .digest("hex")
        .slice(0, 16);
    return `${prefix}-${digest}`;
}

function normalizedDocuments(documents) {
    if (!Array.isArray(documents) || documents.length === 0) {
        throw new TypeError("metamorphic transforms require fixture documents");
    }
    return documents.map((document) => {
        if (!document || typeof document.path !== "string"
            || typeof document.text !== "string") {
            throw new TypeError("fixture documents require path and text");
        }
        return {
            path: document.path.replace(/\\/gu, "/"),
            markers: validateFixtureText(document.text, document.path)
                .map((marker) => ({
                    kind: marker.kind,
                    args: [...marker.args],
                    splitArguments: new Set(),
                })),
        };
    });
}

function renameIdentifiers(documents) {
    const nodeIds = new Map();
    for (const document of documents) {
        for (const marker of document.markers) {
            if (marker.kind === "node") {
                nodeIds.set(marker.args[0], stableRename("node", marker.args[0]));
            }
        }
    }
    for (const document of documents) {
        for (const marker of document.markers) {
            if (marker.kind === "node") marker.args[0] = nodeIds.get(marker.args[0]);
            if (marker.kind === "edge") {
                marker.args[0] = stableRename("edge", marker.args[0]);
                marker.args[2] = nodeIds.get(marker.args[2]) || marker.args[2];
                marker.args[3] = nodeIds.get(marker.args[3]) || marker.args[3];
            }
            if (marker.kind === "finding") {
                marker.args[0] = stableRename("finding", marker.args[0]);
            }
        }
    }
}

function addWhitespaceComments(documents) {
    for (const [index, document] of documents.entries()) {
        document.markers.unshift({
            kind: "comment",
            args: [`metamorphic-comment-${index + 1}`],
            splitArguments: new Set(),
        });
    }
}

function relocateFiles(documents) {
    for (const [index, document] of documents.entries()) {
        document.path = [
            "relocated",
            String(index + 1).padStart(3, "0"),
            nodePath.posix.basename(document.path),
        ].join("/");
    }
}

function splitStrings(documents) {
    for (const document of documents) {
        for (const marker of document.markers) {
            for (const [index, value] of marker.args.entries()) {
                if (value.length >= 6) marker.splitArguments.add(index);
            }
        }
    }
}

function renderDocuments(documents, { spaced }) {
    return documents.map((document, documentIndex) => {
        const lines = [];
        for (const [markerIndex, marker] of document.markers.entries()) {
            if (spaced && markerIndex > 0) lines.push("");
            lines.push(renderMarker(marker.kind, marker.args, {
                splitArguments: marker.splitArguments,
                spaced,
                indent: spaced && (documentIndex + markerIndex) % 2 === 0 ? "  ": "",
            }));
        }
        return Object.freeze({
            path: document.path,
            text: `${lines.join("\n")}\n`,
        });
    });
}

export function applyMetamorphicTransforms(documents, transforms = []) {
    const requested = [...new Set(transforms)];
    for (const transform of requested) {
        if (!METAMORPHIC_TRANSFORMS.includes(transform)) {
            throw new TypeError(`unknown metamorphic transform: ${transform}`);
        }
    }
    const normalized = normalizedDocuments(documents);
    if (requested.includes("rename")) renameIdentifiers(normalized);
    if (requested.includes("whitespace-comments")) addWhitespaceComments(normalized);
    if (requested.includes("file-relocation")) relocateFiles(normalized);
    if (requested.includes("string-split")) splitStrings(normalized);
    return Object.freeze(renderDocuments(
        normalized,
        { spaced: requested.includes("whitespace-comments") },
    ));
}

export const __internals = Object.freeze({
    stableRename,
    normalizedDocuments,
    renameIdentifiers,
    addWhitespaceComments,
    relocateFiles,
    splitStrings,
    renderDocuments,
});
