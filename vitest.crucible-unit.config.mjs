import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: [
            "crucible/__tests__/domain-canonical.test.mjs",
            "crucible/__tests__/domain-enumerands.test.mjs",
            "crucible/__tests__/domain-hypotheses.test.mjs",
            "crucible/__tests__/domain-statistics.test.mjs",
            "crucible/__tests__/domain-archive-strategy.test.mjs",
            "crucible/__tests__/v4-stat-contract.test.mjs",
            "crucible/__tests__/measurement-parser.test.mjs",
            "crucible/__tests__/api-schema.test.mjs",
        ],
        testTimeout: 10_000,
        hookTimeout: 10_000,
    },
});
