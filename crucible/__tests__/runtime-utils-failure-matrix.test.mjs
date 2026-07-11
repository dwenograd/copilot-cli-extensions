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
    const failures = [];
    for (const root of roots.splice(0)) {
        try {
            fs.rmSync(root, {
                recursive: true,
                force: true,
                maxRetries: 10,
                retryDelay: 25,
            });
        } catch (error) {
            failures.push(error);
        }
        if (fs.existsSync(root)) {
            failures.push(new Error(`runtime utils root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "runtime utils test cleanup failed");
    }
});

describe("H7 atomic status-write failure matrix", () => {
    it.each([
        ["after-open", false],
        ["after-file-fsync", false],
        ["after-rename", true],
    ])("leaves an atomic recoverable state at representative point %s", (
        point,
        published,
    ) => {
        const root = makeRoot(point);
        const target = path.join(root, "status.json");

        expect(() => atomicWriteJson(target, { revision: 1 }, {
            token: "representative-token",
            faultInjector(event) {
                if (event.point === point) {
                    throw new Error(`injected ${point}`);
                }
            },
        })).toThrow(`injected ${point}`);

        if (published) {
            expect(JSON.parse(fs.readFileSync(target, "utf8"))).toEqual({ revision: 1 });
        } else {
            expect(fs.existsSync(target)).toBe(false);
            atomicWriteJson(target, { revision: 2 }, {
                token: "representative-token",
            });
            expect(JSON.parse(fs.readFileSync(target, "utf8"))).toEqual({ revision: 2 });
        }
        expect(atomicTemps(root)).toEqual([]);
    });
});
