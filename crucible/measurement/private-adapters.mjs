// Internal dependency-injection keys shared by trusted production modules and
// focused tests. These are intentionally not re-exported from measurement/index.

export const MEASUREMENT_LIFECYCLE_ADAPTER = Symbol(
    "crucible.measurement.lifecycle-adapter",
);
