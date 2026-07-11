// vitest.config.mjs — workspace test config.
//
// Five of the six extensions (the orchestrators: triple-*, debate,
// duck-council) and the _shared/ module use vitest.
// `zerotrust-sourcecheck/` uses Node's built-in `node:test` runner
// instead (its suite predates the workspace vitest adoption).
// Excluding it from vitest's file walk keeps the "Tests" counts honest
// and avoids confusing "0 tests" entries for files that ARE running
// tests — just through a different runner.
//
// `npm test` (in package.json) runs vitest first, then explicitly
// invokes `node --test "zerotrust-sourcecheck/__tests__/*.test.mjs"`
// so both suites are exercised end-to-end.

import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        exclude: [
            "**/node_modules/**",
            "**/dist/**",
            "**/.{idea,git,cache,output,temp}/**",
            "zerotrust-sourcecheck/**",
            "crucible/__tests__/windows-conformance/**",
            "crucible/__tests__/**/*.integration.test.mjs",
            "crucible/__tests__/**/*.release.test.mjs",
        ],
    },
});
