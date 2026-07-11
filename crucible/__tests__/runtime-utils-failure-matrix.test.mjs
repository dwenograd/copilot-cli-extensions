import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { atomicWriteJson } from "../runtime/utils.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-utils-${label}-`));
    roots.push(root);
    return root;
}

function atomicTemps(root) {
    return fs.readdirSync(root).filter((name) => name.endsWith(".tmp"));
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 10,
            retryDelay: 25,
        });
    }
});

describe("H7 atomic status-write failure matrix", () => {
    it.each([
        "after-open",
        "after-write",
        "before-file-fsync",
        "after-file-fsync",
        "before-rename",
    ])("removes the current-owned temporary after a pre-publication failure at %s", (point) => {
        const root = makeRoot(point);
        const target = path.join(root, "status.json");
        const inject = (event) => {
            if (event.point === point) {
                throw new Error(`injected ${point}`);
            }
        };

        expect(() => atomicWriteJson(target, { revision: 1 }, {
            token: "fixed-retry-token",
            faultInjector: inject,
        })).toThrow(`injected ${point}`);
        expect(fs.existsSync(target)).toBe(false);
        expect(atomicTemps(root)).toEqual([]);

        atomicWriteJson(target, { revision: 2 }, {
            token: "fixed-retry-token",
        });
        expect(JSON.parse(fs.readFileSync(target, "utf8"))).toEqual({ revision: 2 });
        expect(atomicTemps(root)).toEqual([]);
    });

    it.each([
        "after-rename",
        "before-directory-fsync",
    ])("leaves one complete recoverable publication and no temporary at %s", (point) => {
        const root = makeRoot(point);
        const target = path.join(root, "status.json");

        expect(() => atomicWriteJson(target, { revision: 7 }, {
            token: "published-token",
            faultInjector(event) {
                if (event.point === point) {
                    throw new Error(`injected ${point}`);
                }
            },
        })).toThrow(`injected ${point}`);

        expect(JSON.parse(fs.readFileSync(target, "utf8"))).toEqual({ revision: 7 });
        expect(atomicTemps(root)).toEqual([]);
    });
});
