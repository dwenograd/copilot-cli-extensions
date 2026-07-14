import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: [
            "crucible/__tests__/**/*.release.test.mjs",
        ],
        passWithNoTests: false,
        testTimeout: 360_000,
        hookTimeout: 180_000,
    },
});
