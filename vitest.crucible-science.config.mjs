import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: [
            "crucible/__tests__/science-fixtures/v4-science-gate.test.mjs",
            "crucible/__tests__/science-fixtures/v4-runner-science.release.test.mjs",
        ],
        fileParallelism: false,
        passWithNoTests: false,
        testTimeout: 360_000,
        hookTimeout: 30_000,
    },
});
