import { test } from "node:test";
import assert from "node:assert/strict";

import {
    ASSURANCE_BLOCKERS,
    ASSURANCE_LEVELS,
    ASSURANCE_SCHEMA_REVISION,
    EVASION_CLASSES,
    EVASION_CLASS_VALUES,
    AssuranceContractError,
    computeAssurance,
    normalizeAssuranceInputs,
    renderAssuranceWording,
    validateAssuranceResult,
} from "../analysis/index.mjs";

function coverage(status = "comprehensive") {
    return Object.fromEntries(
        EVASION_CLASS_VALUES.map((evasionClass) => [evasionClass, status]),
    );
}

function assuranceInputs(overrides = {}) {
    return {
        schemaVersion: ASSURANCE_SCHEMA_REVISION,
        artifactSupport: "supported",
        coverage: coverage(),
        blockers: [],
        ...overrides,
    };
}

test("assurance inputs are strict, bounded, frozen, and do not migrate baseline", () => {
    const normalized = normalizeAssuranceInputs(assuranceInputs());
    assert.equal(normalized.schemaVersion, 6);
    assert.equal(Object.keys(normalized.coverage).length, EVASION_CLASS_VALUES.length);
    assert.ok(Object.isFrozen(normalized));
    assert.ok(Object.isFrozen(normalized.coverage));
    assert.throws(() => normalizeAssuranceInputs({ ...assuranceInputs(), schemaVersion: 5 }),
        /baseline state is not assurance state/,
    );
    assert.throws(() => normalizeAssuranceInputs({
            ...assuranceInputs(),
            coverage: {
                ...coverage(),
                unknown: "comprehensive",
            },
        }),
        AssuranceContractError,
    );
    const missingCoverage = coverage();
    delete missingCoverage[EVASION_CLASSES.ENCODING_AND_PARSER_DIFFERENTIALS];
    assert.throws(() => normalizeAssuranceInputs({
            ...assuranceInputs(),
            coverage: missingCoverage,
        }),
        /is required/,
    );
    assert.throws(() => normalizeAssuranceInputs({
            ...assuranceInputs(),
            blockers: [{
                code: ASSURANCE_BLOCKERS.INCOMPLETE_VALIDATION,
                evasionClass:
                    EVASION_CLASSES.INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION,
                sourceText: "not permitted",
            }],
        }),
        /unknown field/,
    );
});

test("assurance computes the three completed static coverage levels", () => {
    assert.equal(
        computeAssurance(assuranceInputs({
            coverage: coverage("bounded"),
        })).assuranceLevel,
        "bounded-static",
    );

    const incompleteSupplyChain = coverage("comprehensive");
    incompleteSupplyChain[
        EVASION_CLASSES.DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION
    ] = "partial";
    assert.equal(
        computeAssurance(assuranceInputs({
            coverage: incompleteSupplyChain,
        })).assuranceLevel,
        "comprehensive-static",
    );

    assert.equal(
        computeAssurance(assuranceInputs()).assuranceLevel,
        "comprehensive-static-with-supply-chain",
    );
});

test("unsupported artifacts downgrade assurance to unsupported", () => {
    const result = computeAssurance(assuranceInputs({
        artifactSupport: "unsupported",
        blockers: [{
            code: ASSURANCE_BLOCKERS.UNSUPPORTED_ARTIFACT,
            evasionClass: EVASION_CLASSES.UNSUPPORTED_OR_OPAQUE_ARTIFACTS,
        }],
    }));
    assert.equal(result.assuranceLevel, "unsupported");
    assert.equal(result.basis.blockerCap, "unsupported");
});

test("incomplete semantic coverage downgrades assurance to partial", () => {
    const incompleteSemantics = coverage();
    incompleteSemantics[
        EVASION_CLASSES.OBFUSCATION_GENERATION_AND_SELF_MODIFICATION
    ] = "partial";
    const result = computeAssurance(assuranceInputs({
        coverage: incompleteSemantics,
        blockers: [{
            code: ASSURANCE_BLOCKERS.INCOMPLETE_SEMANTIC_COVERAGE,
            evasionClass:
                EVASION_CLASSES.OBFUSCATION_GENERATION_AND_SELF_MODIFICATION,
        }],
    }));
    assert.equal(result.assuranceLevel, "partial");
    assert.equal(result.basis.staticCoverage, "incomplete");
});

test("unresolved dynamic behavior downgrades otherwise comprehensive coverage", () => {
    const result = computeAssurance(assuranceInputs({
        blockers: [{
            code: ASSURANCE_BLOCKERS.UNRESOLVED_DYNAMIC_BEHAVIOR,
            evasionClass:
                EVASION_CLASSES.DYNAMIC_CODE_AND_EXTERNAL_PAYLOAD_LOADING,
        }],
    }));
    assert.equal(result.assuranceLevel, "partial");
    assert.equal(result.basis.blockerCap, "partial");
});

test("incomplete supply-chain coverage caps assurance at comprehensive static", () => {
    const result = computeAssurance(assuranceInputs({
        blockers: [{
            code: ASSURANCE_BLOCKERS.INCOMPLETE_SUPPLY_CHAIN,
            evasionClass:
                EVASION_CLASSES.DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION,
        }],
    }));
    assert.equal(result.assuranceLevel, "comprehensive-static");
    assert.equal(result.basis.blockerCap, "comprehensive-static");
});

test("assurance wording distinguishes findings from coverage without implying safety", () => {
    for (const level of ASSURANCE_LEVELS) {
        const wording = renderAssuranceWording(level);
        const combined = Object.values(wording).join(" ");
        assert.doesNotMatch(combined, /\b(?:safe|clean)\b/i);
        assert.match(wording.distinction, /findings verdict/i);
        assert.match(wording.distinction, /assurance reports/i);
        assert.match(wording.limitation, /Host build execution is neither isolation/i);
    }
});

test("assurance results reject changed levels or report wording", () => {
    const result = computeAssurance(assuranceInputs());
    assert.deepEqual(validateAssuranceResult(result), result);
    assert.throws(() => validateAssuranceResult({
            ...result,
            assuranceLevel: "bounded-static",
        }),
        /deterministic assurance computation/,
    );
    assert.throws(() => validateAssuranceResult({
            ...result,
            wording: {
                ...result.wording,
                summary: "Looks clean.",
            },
        }),
        /deterministic assurance computation/,
    );
});
