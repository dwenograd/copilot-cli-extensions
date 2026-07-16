import { test } from "node:test";
import assert from "node:assert/strict";

import {
    ANALYSIS_STAGES,
    ASSURANCE_BLOCKERS,
    EVASION_CLASSES,
    ASSURANCE_ANALYSIS_SCHEMA_REVISION,
    ASSURANCE_STAGES,
    EVASIVE_BLOCKER_CODES,
    EVASIVE_BLOCKERS,
    EvasiveContractError,
    createInitialAssuranceStageState,
    createAssuranceAnalysisSnapshot,
    createEvasiveDerivedArtifactRecord,
    createEvasiveObjectInventoryRecord,
    createEvasiveRedTeamCoverageRecord,
    createEvasiveSemanticReviewCoverageRecord,
    isAdjacentAssuranceStageTransition,
    mapEvasiveBlockerToAssuranceCode,
    transitionAssuranceStageState,
    validateAssuranceAnalysisSnapshot,
    validateEvasiveDerivedArtifactRecord,
    validateEvasiveObjectInventoryRecord,
    validateEvasiveRedTeamCoverageRecord,
    validateEvasiveSemanticReviewCoverageRecord,
    validateAssuranceStageState,
} from "../analysis/index.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE =
    "github.com/example/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);

function buildRecords() {
    const object = createEvasiveObjectInventoryRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path: "src/index.mjs",
        parentObjectId: null,
        objectKind: "source-text",
        byteLength: 128,
        status: "inventoried",
        blockerCodes: [],
        contentSha256: HASH_A,
        upstreamSha: "b".repeat(40),
    });
    const artifact = createEvasiveDerivedArtifactRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path: "src/index.mjs#abstract-syntax",
        sourceObjectId: object.objectId,
        artifactKind: "abstract-syntax",
        producer: "ecmascript-parser",
        producerVersion: "1.0.0",
        byteLength: 64,
        status: "decoded",
        blockerCodes: [],
        contentSha256: HASH_B,
        sourceObjectSha256: object.hashes.identitySha256,
    });
    const semantic = createEvasiveSemanticReviewCoverageRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path: object.path,
        objectId: object.objectId,
        artifactIds: [artifact.artifactId],
        producer: "semantic-review",
        producerVersion: "1.0.0",
        status: "bounded",
        evasionClasses: [
            EVASION_CLASSES.OBFUSCATION_GENERATION_AND_SELF_MODIFICATION,
            EVASION_CLASSES.INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION,
        ],
        blockerCodes: [],
        basisSha256: HASH_C,
        objectIdentitySha256: object.hashes.identitySha256,
    });
    const redTeam = createEvasiveRedTeamCoverageRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path: object.path,
        objectId: object.objectId,
        artifactIds: [artifact.artifactId],
        producer: "red-team-review",
        producerVersion: "1.0.0",
        status: "comprehensive",
        evasionClasses: [
            EVASION_CLASSES.REVIEWER_MANIPULATION_AND_PROMPT_INJECTION,
        ],
        blockerCodes: [],
        basisSha256: HASH_A,
        objectIdentitySha256: object.hashes.identitySha256,
    });
    return { object, artifact, semantic, redTeam };
}

test("assurance stages are audit-bound and adjacent-only", () => {
    assert.deepEqual(ANALYSIS_STAGES, [
        "acquired",
        "prepared",
        "scanned",
        "traced",
        "validated",
        "finalized",
    ]);
    assert.equal(ASSURANCE_ANALYSIS_SCHEMA_REVISION, 6);
    let state = createInitialAssuranceStageState({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
    });
    assert.ok(Object.isFrozen(state));
    assert.equal(isAdjacentAssuranceStageTransition("acquired", "inventoried"), true);
    assert.equal(isAdjacentAssuranceStageTransition("acquired", "decoded"), false);
    for (const next of ASSURANCE_STAGES.slice(1)) {
        state = transitionAssuranceStageState(state, {
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            from: state.current,
            to: next,
        });
    }
    assert.equal(state.current, "finalized");
    assert.deepEqual(state.history, ASSURANCE_STAGES);
    assert.throws(() => transitionAssuranceStageState(createInitialAssuranceStageState({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
        }), {
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            from: "acquired",
            to: "decoded",
        }),
        /illegal assurance stage transition/,
    );
    assert.throws(() => validateAssuranceStageState({
            schemaVersion: 5,
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            current: "acquired",
            history: ["acquired"],
        }),
        /baseline stage state is not assurance state/,
    );
});

test("assurance inventory and derived-artifact records are exact, hashed, and frozen", () => {
    const { object, artifact } = buildRecords();
    assert.deepEqual(validateEvasiveObjectInventoryRecord(object), object);
    assert.deepEqual(validateEvasiveDerivedArtifactRecord(artifact), artifact);
    assert.match(object.objectId, /^zto-[a-f0-9]{64}$/);
    assert.match(artifact.artifactId, /^zta-[a-f0-9]{64}$/);
    assert.ok(Object.isFrozen(object));
    assert.ok(Object.isFrozen(object.hashes));
    assert.ok(Object.isFrozen(artifact.blockerCodes));
    assert.throws(() => validateEvasiveObjectInventoryRecord({
            ...object,
            sourceText: "not permitted",
        }),
        /unknown field/,
    );
    assert.throws(() => validateEvasiveDerivedArtifactRecord({
            ...artifact,
            byteLength: artifact.byteLength + 1,
        }),
        /deterministic assurance identity and hashes/,
    );
});

test("assurance semantic and red-team coverage records bind subjects and assurance classes", () => {
    const { semantic, redTeam } = buildRecords();
    assert.deepEqual(validateEvasiveSemanticReviewCoverageRecord(semantic), semantic);
    assert.deepEqual(validateEvasiveRedTeamCoverageRecord(redTeam), redTeam);
    assert.ok(Object.isFrozen(semantic.evasionClasses));
    assert.ok(Object.isFrozen(redTeam.hashes));
    assert.throws(() => createEvasiveSemanticReviewCoverageRecord({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            path: "src/index.mjs",
            objectId: "zto-" + HASH_A,
            artifactIds: [],
            producer: "semantic-review",
            producerVersion: "1.0.0",
            status: "partial",
            evasionClasses: [
                EVASION_CLASSES.ENCODING_AND_PARSER_DIFFERENTIALS,
            ],
            blockerCodes: [],
            basisSha256: HASH_A,
            objectIdentitySha256: HASH_B,
        }),
        /must explain incomplete coverage/,
    );
});

test("assurance aggregate snapshots validate cross-record identity and component hashes", () => {
    const { object, artifact, semantic, redTeam } = buildRecords();
    const stageState = createInitialAssuranceStageState({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
    });
    const snapshot = createAssuranceAnalysisSnapshot({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        stageState,
        status: "incomplete",
        objectInventory: [object],
        derivedArtifacts: [artifact],
        semanticReviewCoverage: [semantic],
        redTeamCoverage: [redTeam],
        blockerCodes: [],
        sourceIdentitySha256: HASH_C,
    });
    assert.deepEqual(validateAssuranceAnalysisSnapshot(snapshot), snapshot);
    assert.match(snapshot.snapshotId, /^zts-[a-f0-9]{64}$/);
    assert.ok(Object.isFrozen(snapshot));
    assert.ok(Object.isFrozen(snapshot.objectInventory));
    assert.ok(Object.isFrozen(snapshot.hashes));

    const mismatchedCoverage = createEvasiveSemanticReviewCoverageRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path: "src/other.mjs",
        objectId: object.objectId,
        artifactIds: [],
        producer: "semantic-review",
        producerVersion: "1.0.0",
        status: "bounded",
        evasionClasses: [
            EVASION_CLASSES.ENCODING_AND_PARSER_DIFFERENTIALS,
        ],
        blockerCodes: [],
        basisSha256: HASH_A,
        objectIdentitySha256: object.hashes.identitySha256,
    });
    assert.throws(() => createAssuranceAnalysisSnapshot({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            stageState,
            status: "incomplete",
            objectInventory: [object],
            derivedArtifacts: [artifact],
            semanticReviewCoverage: [mismatchedCoverage],
            redTeamCoverage: [redTeam],
            blockerCodes: [],
            sourceIdentitySha256: HASH_C,
        }),
        /mismatched object binding/,
    );
    assert.throws(() => validateAssuranceAnalysisSnapshot({
            ...snapshot,
            schemaVersion: 5,
        }),
        EvasiveContractError,
    );
});

test("assurance blockers use phase namespaces and map into assurance without recomputing it", () => {
    assert.equal(
        mapEvasiveBlockerToAssuranceCode(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE),
        ASSURANCE_BLOCKERS.INCOMPLETE_SEMANTIC_COVERAGE,
    );
    assert.equal(
        mapEvasiveBlockerToAssuranceCode(EVASIVE_BLOCKERS.RELEASE_SOURCE_DIVERGENCE),
        ASSURANCE_BLOCKERS.UNRESOLVED_RELEASE_SOURCE_DIVERGENCE,
    );
    assert.throws(() => mapEvasiveBlockerToAssuranceCode("semantic/free-form"),
        EvasiveContractError,
    );
    assert.throws(() => createEvasiveObjectInventoryRecord({
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            path: "opaque.bin",
            parentObjectId: null,
            objectKind: "opaque",
            byteLength: 1,
            status: "blocked",
            blockerCodes: EVASIVE_BLOCKER_CODES,
            contentSha256: HASH_A,
            upstreamSha: null,
        }),
        /at most 16 entries/,
    );
});
