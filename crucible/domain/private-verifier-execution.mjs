import {
    canonicalEqual,
    immutableCanonical,
} from "./canonical.mjs";

const issuedCapabilities = new WeakMap();
const aggregateCapabilities = new WeakMap();
const eventCapabilities = new WeakMap();

export function issueVerifiedImpossibilityExecutionCapability({
    commandId,
    observationId,
    reference,
} = {}) {
    const binding = immutableCanonical({
        commandId,
        observationId,
        reference,
    });
    const capability = Object.freeze(Object.create(null));
    issuedCapabilities.set(capability, binding);
    return capability;
}

export function readVerifiedImpossibilityExecutionCapability(
    capability,
    {
        commandId = null,
        observationId = null,
        reference = null,
    } = {},
) {
    const binding = capability !== null
        && typeof capability === "object"
        ? issuedCapabilities.get(capability) ?? null
        : null;
    if (binding === null
        || (commandId !== null && binding.commandId !== commandId)
        || (observationId !== null && binding.observationId !== observationId)
        || (reference !== null
            && !canonicalEqual(binding.reference, reference))) {
        return null;
    }
    return binding;
}

export function bindAggregateImpossibilityExecution(
    aggregate,
    observationId,
    capability,
) {
    const binding = readVerifiedImpossibilityExecutionCapability(capability, {
        observationId,
    });
    if (binding === null) {
        throw new TypeError(
            "impossibility execution binding requires a privately issued capability",
        );
    }
    const existing = aggregateCapabilities.get(aggregate) ?? new Map();
    const next = new Map(existing);
    next.set(observationId, capability);
    aggregateCapabilities.set(aggregate, next);
}

export function bindEventImpossibilityExecution(event, capability) {
    if (readVerifiedImpossibilityExecutionCapability(capability) === null) {
        throw new TypeError(
            "impossibility event binding requires a privately issued capability",
        );
    }
    eventCapabilities.set(event, capability);
    return event;
}

export function verifierExecutionCapabilityForEvent(event) {
    return event !== null && typeof event === "object"
        ? eventCapabilities.get(event) ?? null
        : null;
}

export function inheritAggregateImpossibilityExecutions(source, target) {
    const existing = aggregateCapabilities.get(source);
    if (existing !== undefined) {
        aggregateCapabilities.set(target, new Map(existing));
    }
    return target;
}

export function verifiedImpossibilityExecutionFor(
    aggregate,
    observationId,
    reference = null,
) {
    const capability =
        aggregateCapabilities.get(aggregate)?.get(observationId) ?? null;
    return readVerifiedImpossibilityExecutionCapability(capability, {
        observationId,
        reference,
    })?.reference ?? null;
}
