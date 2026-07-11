// vitest.config.mjs — workspace test config.
//
// Six extensions use vitest: the five orchestrators (triple-*, debate,
// duck-council) plus Crucible. The _shared/ module also uses vitest.
// `zerotrust-sourcecheck/` uses Node's built-in `node:test` runner
// instead (its suite predates the workspace vitest adoption).
// Excluding it avoids duplicate/incorrect discovery under a different runner.
// mcp-autoreload currently has no automated test files.
//
// `npm test` (in package.json) runs vitest first, then explicitly
// invokes `node --test "zerotrust-sourcecheck/__tests__/*.test.mjs"`
// so both test runners are invoked by the workspace command.
// This config does not enable passWithNoTests. Only the snapshot-maintenance
// script `npm run test:update` passes `--passWithNoTests`.

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
