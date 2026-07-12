import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { DOMAIN_VERSION } from "../../domain/index.mjs";
import { buildV3ScienceBaseline } from "./v3-adapter.mjs";

// Phase 0 baseline only. This suite checks deterministic characterization
// output; it is deliberately separate from future v4 science acceptance tests.

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const RUNNER = path.join(
    ROOT,
    "crucible",
    "scripts",
    "run-v3-science-benchmark.mjs",
);
const BASELINE = path.join(HERE, "baseline.v3.json");

describe("characterizes_v3 machine-readable science benchmark", () => {
    it("keeps the committed v3 baseline as immutable fixture data under v4", () => {
        const committed = JSON.parse(fs.readFileSync(BASELINE, "utf8"));

        expect(buildV3ScienceBaseline()).toEqual(committed);
        expect(committed.domainVersion).toBe(3);
        expect(DOMAIN_VERSION).toBe(4);
    });

    it("characterizes_v3_runner_as_deterministic_and_machine_readable", () => {
        const args = [RUNNER, "--check"];
        const first = execFileSync(process.execPath, args, {
            cwd: ROOT,
            encoding: "utf8",
        });
        const second = execFileSync(process.execPath, args, {
            cwd: ROOT,
            encoding: "utf8",
        });

        expect(second).toBe(first);
        const summary = JSON.parse(first);
        expect(summary).toMatchObject({
            runnerVersion: 1,
            suite: "crucible-v3-science-baseline",
            baselineMatch: true,
            caseCount: 10,
            expectedToChangeInV4Count: 9,
            notDesiredBehaviorCount: 9,
        });
        expect(summary.summary.cases).toHaveLength(10);
    });

    it("characterizes_v3_runner_as_read_only_with_strict_arguments", () => {
        const before = fs.readFileSync(BASELINE, "utf8");
        const result = spawnSync(process.execPath, [RUNNER, "--unknown"], {
            cwd: ROOT,
            encoding: "utf8",
        });

        expect(result.status).toBe(2);
        expect(result.stderr).toContain("Usage:");
        expect(fs.readFileSync(BASELINE, "utf8")).toBe(before);
    });
});
