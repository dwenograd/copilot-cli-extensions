import {
    enumerandBinding,
    normalizeEnumerandManifest,
} from "../domain/enumerands.mjs";
import { immutableCanonical } from "../domain/canonical.mjs";
import { InvalidArgumentError } from "./errors.mjs";

function requirePlainObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        throw new InvalidArgumentError(`${field} must be a plain object`, {
            field,
        });
    }
    return value;
}

function rejectUnknownKeys(value, allowed, field) {
    const unknown = Object.keys(value).filter((key) => !allowed.has(key));
    if (unknown.length > 0) {
        throw new InvalidArgumentError(`${field} contains unknown fields`, {
            field,
            unknown,
        });
    }
}

function requireArtifactStore(artifactStore) {
    if (artifactStore === null
        || (typeof artifactStore !== "object"
            && typeof artifactStore !== "function")) {
        throw new InvalidArgumentError("artifactStore must be an object");
    }
    for (const method of [
        "ingestDirectory",
        "loadManifest",
        "materializeSnapshot",
        "verifySnapshot",
    ]) {
        if (typeof artifactStore[method] !== "function") {
            throw new InvalidArgumentError(
                `artifactStore must expose ${method}()`,
                { method },
            );
        }
    }
    return artifactStore;
}

function verifiedSnapshot(store, snapshot, field) {
    const status = store.verifySnapshot(snapshot);
    if (status?.ok !== true) {
        throw new InvalidArgumentError(
            `${field} failed immutable artifact-store verification`,
            { field, snapshot, status },
        );
    }
    store.loadManifest(snapshot);
    return snapshot;
}

function stageSource(store, sourceDir, field) {
    if (typeof sourceDir !== "string" || sourceDir.length === 0) {
        throw new InvalidArgumentError(`${field} must be a non-empty path`, {
            field,
        });
    }
    const staged = store.ingestDirectory({ sourceDir });
    if (staged === null
        || typeof staged !== "object"
        || typeof staged.snapshot !== "string") {
        throw new InvalidArgumentError(
            "artifactStore.ingestDirectory() returned an invalid snapshot",
            { field },
        );
    }
    return verifiedSnapshot(store, staged.snapshot, field);
}

export function stageFiniteEnumerandManifest(input) {
    requirePlainObject(input, "input");
    rejectUnknownKeys(
        input,
        new Set([
            "artifactStore",
            "control",
            "entries",
            "hypothesisPolicy",
            "observableRegistry",
        ]),
        "input",
    );
    const store = requireArtifactStore(input.artifactStore);
    if (!Array.isArray(input.entries) || input.entries.length === 0) {
        throw new InvalidArgumentError(
            "entries must contain at least one finite enumerand source",
        );
    }
    const stagedEntries = input.entries.map((entry, index) => {
        requirePlainObject(entry, `entries[${index}]`);
        const allowed = new Set([
            "artifactSnapshotHash",
            "id",
            "hypotheses",
            "ordinal",
            "sourceDir",
        ]);
        const unknown = Object.keys(entry).filter((key) => !allowed.has(key));
        if (unknown.length > 0) {
            throw new InvalidArgumentError(
                `entries[${index}] contains unknown fields`,
                { unknown },
            );
        }
        const hasSource = entry.sourceDir !== undefined;
        const hasSnapshot = entry.artifactSnapshotHash !== undefined;
        if (hasSource === hasSnapshot) {
            throw new InvalidArgumentError(
                `entries[${index}] must provide exactly one of sourceDir or artifactSnapshotHash`,
            );
        }
        return {
            id: entry.id,
            ordinal: entry.ordinal,
            artifactSnapshotHash: hasSource
                ? stageSource(store, entry.sourceDir, `entries[${index}].sourceDir`)
                : verifiedSnapshot(
                    store,
                    entry.artifactSnapshotHash,
                    `entries[${index}].artifactSnapshotHash`,
                ),
            ...(entry.hypotheses === undefined
                ? {}
                : { hypotheses: entry.hypotheses }),
        };
    });

    requirePlainObject(input.control, "control");
    let control;
    if (input.control.kind === "enumerand") {
        control = {
            kind: "enumerand",
            ordinal: input.control.ordinal,
        };
    } else if (input.control.kind === "reference") {
        const hasSource = input.control.sourceDir !== undefined;
        const hasReference = input.control.referenceHash !== undefined;
        if (hasSource === hasReference) {
            throw new InvalidArgumentError(
                "reference control must provide exactly one of sourceDir or referenceHash",
            );
        }
        control = {
            kind: "reference",
            referenceHash: hasSource
                ? stageSource(store, input.control.sourceDir, "control.sourceDir")
                : input.control.referenceHash,
        };
    } else {
        throw new InvalidArgumentError(
            "control.kind must be enumerand or reference",
        );
    }

    const manifest = normalizeEnumerandManifest({
        topology: "finite_enumerable",
        entries: stagedEntries,
        control,
    }, {
        topology: "finite_enumerable",
        observableRegistry: input.observableRegistry ?? [],
        hypothesisPolicy: input.hypothesisPolicy ?? {},
    });
    return immutableCanonical({
        manifest,
        stagedSnapshots: manifest.entries.map((entry) => ({
            ordinal: entry.ordinal,
            enumerandHash: entry.enumerandHash,
            artifactSnapshotHash: entry.artifactSnapshotHash,
        })),
    });
}

export function stageBoundedParameterizedManifest(input) {
    requirePlainObject(input, "input");
    rejectUnknownKeys(
        input,
        new Set([
            "control",
            "entries",
            "hypothesisPolicy",
            "observableRegistry",
            "topology",
        ]),
        "input",
    );
    if (input.topology !== undefined
        && input.topology !== "bounded_parameterized") {
        throw new InvalidArgumentError(
            "input.topology must be bounded_parameterized",
        );
    }
    return normalizeEnumerandManifest({
        topology: "bounded_parameterized",
        entries: input.entries,
        control: input.control,
    }, {
        topology: "bounded_parameterized",
        observableRegistry: input.observableRegistry ?? [],
        hypothesisPolicy: input.hypothesisPolicy ?? {},
    });
}

export function verifyStagedFiniteEnumerands(input) {
    requirePlainObject(input, "input");
    rejectUnknownKeys(
        input,
        new Set([
            "artifactStore",
            "hypothesisPolicy",
            "manifest",
            "observableRegistry",
        ]),
        "input",
    );
    const store = requireArtifactStore(input.artifactStore);
    const manifest = normalizeEnumerandManifest(input.manifest, {
        topology: "finite_enumerable",
        observableRegistry: input.observableRegistry ?? [],
        hypothesisPolicy: input.hypothesisPolicy ?? {},
    });
    const snapshots = manifest.entries.map((entry) => ({
        ordinal: entry.ordinal,
        enumerandHash: entry.enumerandHash,
        artifactSnapshotHash: verifiedSnapshot(
            store,
            entry.artifactSnapshotHash,
            `manifest.entries[${entry.ordinal}].artifactSnapshotHash`,
        ),
    }));
    if (manifest.control.kind === "reference"
        && /^sha256:[a-f0-9]{64}$/u.test(manifest.control.referenceHash)) {
        verifiedSnapshot(
            store,
            manifest.control.referenceHash,
            "manifest.control.referenceHash",
        );
    }
    return immutableCanonical({
        manifestRoot: manifest.merkleRoot,
        snapshots,
    });
}

export function materializeFiniteEnumerand(input) {
    requirePlainObject(input, "input");
    rejectUnknownKeys(
        input,
        new Set([
            "artifactStore",
            "destDir",
            "manifest",
            "hypothesisPolicy",
            "observableRegistry",
            "ordinal",
            "readOnly",
        ]),
        "input",
    );
    const store = requireArtifactStore(input.artifactStore);
    const manifest = normalizeEnumerandManifest(input.manifest, {
        topology: "finite_enumerable",
        observableRegistry: input.observableRegistry ?? [],
        hypothesisPolicy: input.hypothesisPolicy ?? {},
    });
    const binding = enumerandBinding(manifest, input.ordinal, {
        topology: "finite_enumerable",
        observableRegistry: input.observableRegistry ?? [],
        hypothesisPolicy: input.hypothesisPolicy ?? {},
    });
    verifiedSnapshot(
        store,
        binding.artifactSnapshotHash,
        "enumerand.artifactSnapshotHash",
    );
    const result = store.materializeSnapshot({
        snapshot: binding.artifactSnapshotHash,
        destDir: input.destDir,
        readOnly: input.readOnly ?? true,
    });
    return immutableCanonical({
        binding,
        materialized: result,
    });
}
