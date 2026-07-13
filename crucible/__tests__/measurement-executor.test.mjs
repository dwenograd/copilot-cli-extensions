import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { PassThrough } from "node:stream";

import { afterEach, describe, expect, it } from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    VERIFIER_PARSER_VERSION,
    createMeasurementExecutor,
    loadHarnessAllowlist,
} from "../measurement/index.mjs";
import {
    hashCanonical,
    impossibilityVerifierEnumerandResultsRoot,
    impossibilityVerifierFactsRoot,
    impossibilityVerifierRefutationReceiptHash,
    impossibilityVerifierRefutationRoot,
} from "../domain/index.mjs";
import {
    fixedIds,
    makeTempRoot,
    manualClock,
    materializeCandidateSnapshot,
    pinnedDependency,
    rmTempRoot,
    sha256HexOfFile,
    writeAllowlist,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const roots = [];

afterEach(() => {
    const failures = [];
    for (const root of roots.splice(0)) {
        try {
            rmTempRoot(root);
        } catch (error) {
            failures.push(error);
        }
        if (fs.existsSync(root)) {
            failures.push(new Error(`measurement component root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "measurement component cleanup failed");
    }
});

function makeFixture(label, entryOverrides = {}) {
    const root = makeTempRoot(`component-${label}`);
    roots.push(root);
    const executable = path.join(root, `${label}.exe`);
    fs.writeFileSync(executable, `synthetic executable ${label}`);
    const script = writeHarnessScript(
        root,
        label,
        `process.stdout.write('{"pass":true}');`,
    );
    const allowlistPath = writeAllowlist(root, label, {
        executable,
        executableSha256: sha256HexOfFile(executable),
        argvTemplate: [script, "{{candidatePath}}"],
        dependencies: [pinnedDependency(script)],
        ...entryOverrides,
    });
    const allowlist = loadHarnessAllowlist(allowlistPath);
    return {
        root,
        allowlist,
        verifiedEntry: allowlist.verifyEntry(label),
        candidateSnapshot: materializeCandidateSnapshot(
            root,
            `${label}-snapshot`,
            "candidate",
        ),
    };
}

function scriptedProcess({
    stdout = [Buffer.from('{"pass":true,"metrics":{"component":1}}', "utf8")],
    stderr = [],
    hang = false,
} = {}) {
    const terminations = [];
    const launches = [];
    let child = null;
    let closed = false;
    const close = (code, signal) => {
        if (closed || child === null) return;
        closed = true;
        child.stdout.end();
        child.stderr.end();
        setImmediate(() => child.emit("close", code, signal));
    };
    return {
        terminations,
        adapter: {
            spawn(executable, argv, options) {
                launches.push({ executable, argv, options });
                child = new EventEmitter();
                child.pid = 6101;
                child.stdout = new PassThrough();
                child.stderr = new PassThrough();
                if (!hang) {
                    setImmediate(() => {
                        for (const chunk of stdout) child.stdout.write(chunk);
                        for (const chunk of stderr) child.stderr.write(chunk);
                        close(0, null);
                    });
                }
                return child;
            },
            terminateTree(pid) {
                terminations.push(pid);
                close(null, "SIGKILL");
                return true;
            },
        },
        launches,
    };
}

function runFixture(fixture, process, options = {}, runInput = {}) {
    const executor = createMeasurementExecutor({
        allowlist: fixture.allowlist,
        processAdapter: process.adapter,
        scratchRoot: fixture.root,
        clock: manualClock(),
        ...options,
    });
    return executor.run({
        verifiedEntry: fixture.verifiedEntry,
        candidateSnapshot: fixture.candidateSnapshot,
        ...fixedIds(),
        ...runInput,
    });
}

describe("MeasurementExecutor fast component coverage", () => {
    it("stages, parses, receipts, and removes a synthetic successful launch", async () => {
        const fixture = makeFixture("success");
        const process = scriptedProcess();

        const result = await runFixture(fixture, process);

        expect(result.parsed).toMatchObject({
            pass: true,
            metrics: { component: 1 },
        });

        expect(result.receipt).toMatchObject({
            version: 6,
            exit: { code: 0, signal: null, timedOut: false },
            candidateSnapshotMutationCheck: {
                status: "passed",
            },
        });
        expect(process.terminations).toEqual([]);
        expect(fs.readdirSync(fixture.root)
            .filter((name) => name.startsWith(".crucible-stage-"))).toEqual([]);
    });

    it("passes deterministic block/arm bindings in argv, env, and receipt", async () => {
        const fixture = makeFixture("binding");
        const process = scriptedProcess();
        const measurementBinding = {
            role: "search",
            phase: "search",
            replicateIndex: 3,
            blockIndex: 3,
            armIndex: 1,
            armId: "control",
            deterministicSeed:
                `sha256:crucible-replication-arm-seed-v1:${"a".repeat(64)}`,
            subjectId: "rep-b000003-a01-abcdef123456",
            environmentIdentity:
                `sha256:crucible-harness-environment-v4:${"b".repeat(64)}`,
            suiteIdentity:
                `sha256:crucible-harness-suite-v4:${"c".repeat(64)}`,
        };

        const result = await runFixture(
            fixture,
            process,
            {},
            { measurementBinding },
        );

        expect(result.receipt).toMatchObject({
            version: 8,
            ...measurementBinding,
        });

        expect(process.launches).toHaveLength(1);
        const launch = process.launches[0];
        expect(launch.argv).toEqual(expect.arrayContaining([
            "--crucible-role=search",
            "--crucible-replicate-index=3",
            "--crucible-block-index=3",
            "--crucible-arm-index=1",
            "--crucible-arm-id=control",
            `--crucible-deterministic-seed=${
                measurementBinding.deterministicSeed
            }`,
        ]));
        expect(launch.options.env).toMatchObject({
            CRUCIBLE_ROLE: "search",
            CRUCIBLE_REPLICATE_INDEX: "3",
            CRUCIBLE_BLOCK_INDEX: "3",
            CRUCIBLE_ARM_INDEX: "1",
            CRUCIBLE_ARM_ID: "control",
            CRUCIBLE_DETERMINISTIC_SEED:
                measurementBinding.deterministicSeed,
        });
    });

    it("uses the separately pinned verifier parser and deterministic checker receipt", async () => {
        const fixture = makeFixture("verifier-parser");
        const tagged = (label) => hashCanonical(
            { label },
            "sha256:crucible-executor-verifier-test-v1",
        );
        const measurementBinding = {
            role: "impossibility_verifier",
            phase: "impossibility_verification",
            replicateIndex: null,
            blockIndex: 2,
            armIndex: null,
            armId: null,
            deterministicSeed: tagged("seed"),
            subjectId: "impossibility-3",
            environmentIdentity:
                `sha256:crucible-harness-environment-v4:${"e".repeat(64)}`,
            suiteIdentity:
                `sha256:crucible-harness-suite-v4:${"f".repeat(64)}`,
        };
        const evidenceRoots = {
            calibration: tagged("calibration"),
            control: tagged("control"),
            search: tagged("search"),
            scientificReplay: tagged("scientific-replay"),
        };
        const requestHash = tagged("request");
        const proposalHash = tagged("proposal");
        const proofArtifactHash = tagged("proof");
        const checkerEvidenceRoot = tagged("checker");
        const coverageClosureRoot = tagged("coverage");
        const verifierRoleIdentity = tagged("verifier-role");
        const claimStates = [{
            claimId: "acceptance.score",
            state: "REFUTED",
        }];
        const inputRoot = tagged("input-0");
        const receiptBindingsRoot = tagged("receipts-0");
        const evidenceRoot = impossibilityVerifierRefutationRoot({
            requestHash,
            verifierRoleIdentity,
            ordinal: 0,
            enumerandHash: tagged("enumerands-0"),
            inputRoot,
            claimStates,
        });
        const enumerandResults = [{
            ordinal: 0,
            enumerandHash: tagged("enumerands-0"),
            claimStates,
            inputRoot,
            receiptBindingsRoot,
            evidenceRoot,
            refutationReceiptHash:
                impossibilityVerifierRefutationReceiptHash({
                    requestHash,
                    verifierRoleIdentity,
                    ordinal: 0,
                    enumerandHash: tagged("enumerands-0"),
                    inputRoot,
                    receiptBindingsRoot,
                    claimStates,
                    evidenceRoot,
                }),
        }];
        const enumerandResultsRoot =
            impossibilityVerifierEnumerandResultsRoot(enumerandResults);
        const independentFactsRoot = impossibilityVerifierFactsRoot({
            mode: "enumerand_reexecution",
            enumerandResults,
            proofArtifactHash,
            proofCheckerIdentity: null,
            proofValidationReceiptHash: null,
            validatedProofArtifactHash: null,
        });
        const output = {
            version: "crucible-impossibility-verifier-output-v1",
            status: "VERIFIED",
            mode: "enumerand_reexecution",
            requestHash,
            proposedCertificateArtifactHash: proposalHash,
            proofArtifactHash,
            coverageClosureRoot,
            enumerandManifestRoot: tagged("enumerands"),
            enumerandCount: 1,
            checkedEnumerandCount: 1,
            enumerandResults,
            enumerandResultsRoot,
            evidenceRoots,
            statisticalPolicyIdentity: tagged("statistics"),
            alphaLedgerRoot: tagged("alpha"),
            checkerEvidenceRoot,
            independentFactsRoot,
            disagreementCount: 0,
            complete: true,
            certificateFormat: null,
            proofCheckerIdentity: null,
            proofValidationReceiptHash: null,
            validatedProofArtifactHash: null,
            certificate: {
                version: "crucible-impossibility-certificate-v2",
                status: "VERIFIED",
                verdict: "target_unreachable",
                mode: "enumerand_reexecution",
                requestHash,
                proposedCertificateArtifactHash: proposalHash,
                proofArtifactHash,
                contractHash: tagged("contract"),
                harnessSuiteIdentity: measurementBinding.suiteIdentity,
                verifierRoleIdentity,
                coverageClosureRoot,
                enumerandManifestRoot: tagged("enumerands"),
                enumerandResultsRoot,
                evidenceRoots,
                statisticalPolicyIdentity: tagged("statistics"),
                alphaLedgerRoot: tagged("alpha"),
                checkerEvidenceRoot,
                independentFactsRoot,
                certificateFormat: null,
                proofCheckerIdentity: null,
                proofValidationReceiptHash: null,
                validatedProofArtifactHash: null,
            },
            role: measurementBinding.role,
            phase: measurementBinding.phase,
            blockIndex: measurementBinding.blockIndex,
            deterministicSeed: measurementBinding.deterministicSeed,
            subjectId: measurementBinding.subjectId,
            environmentIdentity: measurementBinding.environmentIdentity,
            suiteIdentity: measurementBinding.suiteIdentity,
        };
        const process = scriptedProcess({
            stdout: [Buffer.from(JSON.stringify(output), "utf8")],
        });

        const result = await runFixture(
            fixture,
            process,
            {},
            { measurementBinding },
        );

        expect(result.parsed.status).toBe("VERIFIED");
        expect(result.receipt).toMatchObject({
            parserVersion: VERIFIER_PARSER_VERSION,
            role: "impossibility_verifier",
            blockIndex: 2,
            deterministicSeed: measurementBinding.deterministicSeed,
            subjectId: "impossibility-3",
        });
    });

    it("terminates and awaits a synthetic process at the executor timeout", async () => {
        const fixture = makeFixture("timeout", { timeoutMs: 10 });
        const process = scriptedProcess({ hang: true });

        await expect(runFixture(fixture, process)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
        });
        expect(process.terminations).toEqual([6101]);
        expect(fs.readdirSync(fixture.root)
            .filter((name) => name.startsWith(".crucible-stage-"))).toEqual([]);
    });

    it("fails closed on finite output overflow and retains exact telemetry", async () => {
        const fixture = makeFixture("overflow", { maxStdoutBytes: 16 });
        const bytes = Buffer.from('{"pass":true} trailing-overflow', "utf8");
        const process = scriptedProcess({ stdout: [bytes] });

        let error;
        try {
            await runFixture(fixture, process);
        } catch (caught) {
            error = caught;
        }

        expect(error).toMatchObject({
            code: MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW,
            details: {
                outputCapture: {
                    stdout: {
                        capBytes: 16,
                        totalObservedBytes: bytes.length,
                        retainedBytes: 16,
                        overflowed: true,
                        truncated: true,
                    },
                },
            },
        });
        expect(process.terminations).toEqual([6101]);
    });
});
