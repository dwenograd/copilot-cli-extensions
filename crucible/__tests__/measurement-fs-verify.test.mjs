// crucible/__tests__/measurement-fs-verify.test.mjs
//
// Verifies the local-regular-file gate that every trusted file must pass
// (allowlist, harness executable, dependencies) before any measurement.

import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";

import {
    FILE_HASH_ALGORITHM,
    MEASUREMENT_ERROR_CODES,
    STREAM_HASH_ALGORITHM,
    normalizeExpectedHash,
    sha256Bytes,
    sha256File,
    verifyAndHashFile,
    verifyLocalRegularFile,
} from "../measurement/index.mjs";

import {
    HERE,
    canCreateDirJunction,
    canCreateFileSymlink,
    makeTempRoot,
    rmTempRoot,
} from "./measurement-fixtures.mjs";

const roots = [];
function tmp(label) {
    const r = makeTempRoot(`fsv-${label}`);
    roots.push(r);
    return r;
}
afterAll(() => { roots.forEach(rmTempRoot); });

function writeSample(root, name = "sample.bin", body = "hello world") {
    const p = path.join(root, name);
    fs.writeFileSync(p, body);
    return p;
}

describe("verifyLocalRegularFile", () => {
    it("accepts an absolute local regular file and returns the resolved path", () => {
        const root = tmp("accept");
        const p = writeSample(root);
        const resolved = verifyLocalRegularFile(p, { label: "sample" });
        expect(resolved.toLowerCase()).toBe(path.resolve(p).toLowerCase());
    });

    it("rejects a relative path", () => {
        const err = expectThrow(() => verifyLocalRegularFile("relative\\path.txt", { label: "x" }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT);
    });

    it("rejects UNC and network paths", () => {
        for (const p of [
            "\\\\server\\share\\thing.exe",
            "//fileserver/share/thing.exe",
            "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\thing.exe",
            "\\\\.\\CrucibleSyntheticDevice",
        ]) {
            const err = expectThrow(() => verifyLocalRegularFile(p, { label: "x" }));
            expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_NOT_LOCAL);
        }
    });

    it("reports FILE_NOT_FOUND for a missing file", () => {
        const root = tmp("missing");
        const err = expectThrow(() => verifyLocalRegularFile(path.join(root, "nope.exe"), { label: "x" }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_NOT_FOUND);
    });

    it("rejects a directory (not a regular file)", () => {
        const root = tmp("dir");
        const err = expectThrow(() => verifyLocalRegularFile(root, { label: "x" }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR);
    });

    it("rejects a file symlink where the platform allows creating one", () => {
        if (!canCreateFileSymlink()) {
            // Best-effort: symlink creation requires SeCreateSymbolicLinkPrivilege
            // (admin or Developer Mode) on Windows. Skip so CI without those
            // privileges still exercises the rest of the boundary.
            return;
        }
        const root = tmp("symlink");
        const target = writeSample(root, "target.bin", "target-bytes");
        const link = path.join(root, "link.bin");
        fs.symlinkSync(target, link, "file");
        const err = expectThrow(() => verifyLocalRegularFile(link, { label: "linked" }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_SYMLINK);
    });

    it("rejects a Windows directory junction as a reparse point / non-regular", () => {
        if (!canCreateDirJunction()) return;
        const root = tmp("junction");
        const target = path.join(root, "target");
        fs.mkdirSync(target);
        const j = path.join(root, "j");
        fs.symlinkSync(target, j, "junction");
        // Junction points at a directory; either "symlink" or "not regular"
        // may fire depending on Node's lstat classification. Both are
        // acceptable rejections for our purposes.
        const err = expectThrow(() => verifyLocalRegularFile(j, { label: "j" }));
        expect([
            MEASUREMENT_ERROR_CODES.FILE_SYMLINK,
            MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR,
        ]).toContain(err.code);
    });

    it("catches path shadowing via an ancestor directory junction (realpath differs)", () => {
        if (!canCreateDirJunction()) return;
        const root = tmp("shadow");
        const real = path.join(root, "real");
        fs.mkdirSync(real);
        const target = path.join(real, "exe.bin");
        fs.writeFileSync(target, "real-bytes");
        const shadow = path.join(root, "shadow");
        fs.symlinkSync(real, shadow, "junction");
        // The shadow path resolves to `real` via the junction. Our verifier
        // rejects because realpath differs from the input (reparse point).
        const shadowed = path.join(shadow, "exe.bin");
        const err = expectThrow(() => verifyLocalRegularFile(shadowed, { label: "shadowed" }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_REPARSE_POINT);
    });
});

describe("sha256File / verifyAndHashFile", () => {
    it("matches independent SHA-256 golden vectors for files and bytes", () => {
        const root = tmp("hash");
        const empty = writeSample(root, "empty.bin", "");
        const abc = writeSample(root, "abc.bin", "abc");
        const emptyHex =
            "e3b0c44298fc1c149afbf4c8996fb924"
            + "27ae41e4649b934ca495991b7852b855";
        const abcHex =
            "ba7816bf8f01cfea414140de5dae2223"
            + "b00361a396177a9cb410ff61f20015ad";

        expect(sha256File(empty)).toBe(`${FILE_HASH_ALGORITHM}:${emptyHex}`);
        expect(sha256File(abc)).toBe(`${FILE_HASH_ALGORITHM}:${abcHex}`);
        expect(sha256Bytes(Buffer.alloc(0)))
            .toBe(`${STREAM_HASH_ALGORITHM}:${emptyHex}`);
        expect(sha256Bytes(Buffer.from("abc", "utf8")))
            .toBe(`${STREAM_HASH_ALGORITHM}:${abcHex}`);
    });

    it("verifyAndHashFile accepts a bare-hex expected value", () => {
        const root = tmp("acceptBare");
        const p = writeSample(root, "y.bin", "content-y");
        const tagged = sha256File(p);
        const hex = tagged.split(":").pop();
        const { hash, resolvedPath } = verifyAndHashFile(p, hex, { label: "y" });
        expect(hash).toBe(tagged);
        expect(resolvedPath.toLowerCase()).toBe(path.resolve(p).toLowerCase());
    });

    it("verifyAndHashFile accepts a tagged expected value", () => {
        const root = tmp("acceptTagged");
        const p = writeSample(root, "z.bin", "content-z");
        const tagged = sha256File(p);
        const { hash } = verifyAndHashFile(p, tagged, { label: "z" });
        expect(hash).toBe(tagged);
    });

    it("verifyAndHashFile throws FILE_HASH_MISMATCH when the file changed", () => {
        const root = tmp("mismatch");
        const p = writeSample(root, "m.bin", "before");
        const stale = sha256File(p);
        fs.writeFileSync(p, "after"); // mutate on disk after we captured the hash
        const err = expectThrow(() => verifyAndHashFile(p, stale, { label: "m" }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH);
        expect(err.details.path.toLowerCase()).toBe(path.resolve(p).toLowerCase());
    });

    it("normalizeExpectedHash rejects malformed values", () => {
        expect(() => normalizeExpectedHash("", "x")).toThrow();
        expect(() => normalizeExpectedHash("nothex", "x")).toThrow();
        expect(() => normalizeExpectedHash("abcd", "x")).toThrow(); // too short
    });
});

function expectThrow(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    throw new Error(`expected the operation to throw (in ${HERE})`);
}
