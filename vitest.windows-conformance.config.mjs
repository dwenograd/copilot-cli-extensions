import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: [
            "crucible/__tests__/windows-conformance/**/*.conformance.test.mjs",
        ],
        fileParallelism: false,
        pool: "forks",
        poolOptions: {
            forks: {
                singleFork: true,
            },
        },
        sequence: {
            concurrent: false,
            shuffle: false,
        },
        testTimeout: 180_000,
        hookTimeout: 180_000,
    },
});
