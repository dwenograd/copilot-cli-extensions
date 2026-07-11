import { hashCanonical } from "../domain/index.mjs";
import { PARSER_VERSION } from "../measurement/index.mjs";

export function fakeHarnessIdentity({
    harnessId = "fixture-harness",
    parserVersion = PARSER_VERSION,
    executesCandidateCode = false,
    dependencyHashes = [],
} = {}) {
    const hash = (label, value) => hashCanonical(
        value,
        `sha256:crucible-${label}-v1`,
    );
    const policyIdentity = executesCandidateCode
        ? {
            primitive: "fixture-containment",
            providerId: "fixture-provider",
            providerVersion: "v1",
            policyId: "fixture-policy-v1",
            helperSourceHash: hash("sandbox-helper-source", { harnessId }),
            helperBinaryHash: hash("measurement-file", { harnessId, helper: true }),
            launcherId: "fixture-launcher-v1",
            launcherBinaryHash: hash("measurement-file", {
                harnessId,
                launcher: true,
            }),
            launcherScriptHash: hash("sandbox-launcher-script", {
                harnessId,
            }),
            securityContext: {
                appContainer: true,
                lowIntegrity: true,
                capabilities: [],
                loopbackExemptionRejected: true,
            },
            network: {
                mode: "deny-by-default",
                enforcement: "fixture zero-capability boundary",
            },
            filesystem: {
                stagedHarness: "exact-manifest-read-execute",
                immutableCandidate: "private-staged-copy-read-only",
                outputTemp: "provider-owned",
                aclJournalRestored: true,
                exactLaunchClosure: true,
                hostWriteDenied: true,
            },
            job: {
                killOnJobClose: true,
                descendantsContained: true,
                uiRestrictions: true,
                activeProcessLimit: 8,
                processMemoryBytes: 512 * 1024 * 1024,
                jobMemoryBytes: 768 * 1024 * 1024,
                cpuRatePercent: 50,
                cpuTimeMs: 30_000,
                wallTimeMs: 120_000,
                terminationGraceMs: 5_000,
            },
        }
        : null;
    return {
        version: 1,
        harnessId,
        allowlistVersion: 1,
        allowlistFileHash: hash("measurement-file", { harnessId, allowlist: true }),
        harnessEntryHash: hash("measurement-entry", { harnessId }),
        executableHash: hash("measurement-file", { harnessId, executable: true }),
        dependencyHashes,
        argvTemplateHash: hash("measurement-argv-template", { harnessId }),
        allowedEnvHash: hash("measurement-env-policy", { harnessId }),
        parserVersion,
        parserVersionHash: hash("measurement-parser-version", { parserVersion }),
        parserSourceHash: hash("measurement-parser-source", { parserVersion }),
        executesCandidateCode,
        sandbox: {
            required: executesCandidateCode,
            policyIdentity,
            policyDigest: policyIdentity === null
                ? null
                : hashCanonical(
                    policyIdentity,
                    "sha256:crucible-measurement-sandbox-policy-identity-v1",
                ),
        },
    };
}
