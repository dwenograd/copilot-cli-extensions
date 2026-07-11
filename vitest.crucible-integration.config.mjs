import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: [
            "crucible/__tests__/runtime-sdk-cli.integration.test.mjs",
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
        testTimeout: 240_000,
        hookTimeout: 60_000,
    },
});
