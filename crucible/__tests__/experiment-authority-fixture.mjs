import {
    createHash,
    generateKeyPairSync,
    sign,
} from "node:crypto";

import {
    prepareExperimentManifest,
} from "../api/experiment-registry.mjs";
import {
    buildExperimentAuthorityManifest,
    createExperimentAuthorityEnvelope,
    EXPERIMENT_PUBLIC_KEY_ENV,
    readVerifiedExperimentAuthority,
    resolveExperimentTrust,
    verifyExperimentAuthority,
} from "../api/experiment-authority.mjs";
import {
    EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM,
    RUNTIME_CONFIG_AUTHORITY_KIND,
    RUNTIME_CONFIG_AUTHORITY_VERSION,
    experimentAuthorityManifestBytes,
    hashCanonical,
    normalizeRuntimeConfigAuthority,
    runtimeConfigAuthorityFingerprint,
} from "../domain/index.mjs";
import { fakeRuntimeIdentity } from "./v4-contract-fixture.mjs";

export function createExperimentAuthorityFixture() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
    const fingerprint = `${
        EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM
    }:${createHash("sha256").update(publicKeyDer).digest("hex")}`;
    return Object.freeze({
        publicKey,
        privateKey,
        publicKeyDer,
        fingerprint,
        env: Object.freeze({
            [EXPERIMENT_PUBLIC_KEY_ENV]: publicKeyDer.toString("base64"),
        }),
    });
}

export function prepareAndSignExperiment({
    config,
    allowlistPath,
    env,
    privateKey,
}) {
    const prepared = prepareExperimentManifest(config, {
        allowlistPath,
        env,
    });
    const signature = sign(
        null,
        Buffer.from(prepared.canonicalManifest, "utf8"),
        privateKey,
    );
    return Object.freeze({ prepared, signature });
}

export function createSignedInvestigationAuthority({
    contract,
    experimentId = "fixture-experiment",
    projectDir = process.cwd(),
    harnessSuiteId = contract.harnessSuite.id,
    fixture = createExperimentAuthorityFixture(),
} = {}) {
    const trust = resolveExperimentTrust(fixture.env);
    const manifest = buildExperimentAuthorityManifest({
        experimentId,
        projectDir,
        harnessSuiteId,
        contract,
        trustFingerprint: trust.fingerprint,
    });
    const signature = sign(
        null,
        experimentAuthorityManifestBytes(manifest),
        fixture.privateKey,
    );
    const envelope = createExperimentAuthorityEnvelope({
        manifest,
        signature,
        trustFingerprint: trust.fingerprint,
    });
    const capability = verifyExperimentAuthority({
        authority: envelope,
        experimentId,
        projectDir,
        harnessSuiteId,
        contract,
        investigationId: manifest.investigationId,
        env: fixture.env,
    });
    const authority = readVerifiedExperimentAuthority(capability).authority;
    return Object.freeze({
        authority,
        capability,
        investigationId: manifest.investigationId,
        env: fixture.env,
        fixture,
    });
}

export function createRuntimeConfigAuthorityFixture(
    investigationId,
    overrides = {},
) {
    const securityConfig = overrides.securityConfig ?? {
        runner: { investigationId },
    };
    const core = {
        version: RUNTIME_CONFIG_AUTHORITY_VERSION,
        kind: RUNTIME_CONFIG_AUTHORITY_KIND,
        securityConfig,
        identities: overrides.identities ?? {},
        runtimeIdentity: overrides.runtimeIdentity ?? fakeRuntimeIdentity(),
        workerAdditionalContextHash:
            overrides.workerAdditionalContextHash
            ?? hashCanonical(
                { content: null },
                "sha256:crucible-worker-additional-context-v1",
            ),
        sandbox: overrides.sandbox ?? { required: false },
    };
    return normalizeRuntimeConfigAuthority({
        ...core,
        fingerprint: runtimeConfigAuthorityFingerprint(core),
    });
}
