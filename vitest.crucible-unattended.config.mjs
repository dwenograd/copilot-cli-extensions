import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        include: [
            "crucible/__tests__/api-e2e.release.test.mjs",
            "crucible/__tests__/api-lifecycle.test.mjs",
            "crucible/__tests__/api-preflight.test.mjs",
            "crucible/__tests__/persistence-event-log.test.mjs",
            "crucible/__tests__/persistence-recovery-catalog.test.mjs",
            "crucible/__tests__/persistence-segments.release.test.mjs",
            "crucible/__tests__/persistence-working-set.release.test.mjs",
            "crucible/__tests__/persistence-working-set.test.mjs",
            "crucible/__tests__/runtime-control-channel.test.mjs",
            "crucible/__tests__/runtime-discovery.test.mjs",
            "crucible/__tests__/runtime-identity.test.mjs",
            "crucible/__tests__/runtime-recovery-daemon.release.test.mjs",
            "crucible/__tests__/runtime-recovery-daemon.test.mjs",
            "crucible/__tests__/runtime-resource-broker.release.test.mjs",
            "crucible/__tests__/runtime-sdk-retry-policy.test.mjs",
            "crucible/__tests__/runtime-supervisor.test.mjs",
            "crucible/__tests__/runtime-worker-pool-retry.test.mjs",
            "crucible/__tests__/tools-recovery-task.test.mjs",
            "crucible/__tests__/v4-unattended-gate.release.test.mjs",
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
        testTimeout: 360_000,
        hookTimeout: 180_000,
    },
});
