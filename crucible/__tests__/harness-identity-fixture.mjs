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
            policyId: "fixture-policy-v1",
            helperSourceHash: hash("sandbox-helper-source", { harnessId }),
            helperBinaryHash: hash("measurement-file", { harnessId, helper: true }),
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
