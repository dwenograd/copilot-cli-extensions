import {
    ANALYSIS_SCHEMA_VERSION,
    LIMITS,
    validateAuditId,
    validateBehaviorGraphDocument,
    validateGraphEdge,
    validateGraphNode,
    validatePluginOutput,
} from "./schemas.mjs";

function sameValue(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
}

function clone(value) {
    return structuredClone(value);
}

export class BehaviorGraph {
    #auditId;
    #maxNodes;
    #maxEdges;
    #nodes = new Map();
    #edges = new Map();

    constructor({
        auditId,
        maxNodes = LIMITS.graphNodes,
        maxEdges = LIMITS.graphEdges,
    }) {
        this.#auditId = validateAuditId(auditId);
        if (!Number.isSafeInteger(maxNodes) || maxNodes < 1 || maxNodes > LIMITS.graphNodes) {
            throw new RangeError(`maxNodes must be between 1 and ${LIMITS.graphNodes}`);
        }
        if (!Number.isSafeInteger(maxEdges) || maxEdges < 1 || maxEdges > LIMITS.graphEdges) {
            throw new RangeError(`maxEdges must be between 1 and ${LIMITS.graphEdges}`);
        }
        this.#maxNodes = maxNodes;
        this.#maxEdges = maxEdges;
    }

    get auditId() {
        return this.#auditId;
    }

    get nodeCount() {
        return this.#nodes.size;
    }

    get edgeCount() {
        return this.#edges.size;
    }

    addNode(input) {
        const node = validateGraphNode(input);
        if (node.auditId !== this.#auditId) {
            throw new Error("graph node auditId does not match graph auditId");
        }
        const existing = this.#nodes.get(node.id);
        if (existing) {
            if (!sameValue(existing, node)) {
                throw new Error(`conflicting graph node id: ${node.id}`);
            }
            return clone(existing);
        }
        if (this.#nodes.size >= this.#maxNodes) {
            throw new RangeError(`graph node limit exceeded (${this.#maxNodes})`);
        }
        this.#nodes.set(node.id, node);
        return clone(node);
    }

    addEdge(input) {
        const edge = validateGraphEdge(input);
        if (edge.auditId !== this.#auditId) {
            throw new Error("graph edge auditId does not match graph auditId");
        }
        if (!this.#nodes.has(edge.from) || !this.#nodes.has(edge.to)) {
            throw new Error(`graph edge ${edge.id} references an unknown node`);
        }
        const existing = this.#edges.get(edge.id);
        if (existing) {
            if (!sameValue(existing, edge)) {
                throw new Error(`conflicting graph edge id: ${edge.id}`);
            }
            return clone(existing);
        }
        if (this.#edges.size >= this.#maxEdges) {
            throw new RangeError(`graph edge limit exceeded (${this.#maxEdges})`);
        }
        this.#edges.set(edge.id, edge);
        return clone(edge);
    }

    mergePluginOutput(input) {
        const output = validatePluginOutput(input);
        if (output.auditId !== this.#auditId) {
            throw new Error("plugin output auditId does not match graph auditId");
        }
        const outputNodeIds = new Set(output.nodes.map((node) => node.id));
        let nodesAdded = 0;
        let edgesAdded = 0;
        for (const node of output.nodes) {
            const existing = this.#nodes.get(node.id);
            if (existing && !sameValue(existing, node)) {
                throw new Error(`conflicting graph node id: ${node.id}`);
            }
            if (!existing) nodesAdded += 1;
        }
        if (this.#nodes.size + nodesAdded > this.#maxNodes) {
            throw new RangeError(`graph node limit exceeded (${this.#maxNodes})`);
        }
        for (const edge of output.edges) {
            if ((!this.#nodes.has(edge.from) && !outputNodeIds.has(edge.from))
                || (!this.#nodes.has(edge.to) && !outputNodeIds.has(edge.to))) {
                throw new Error(`graph edge ${edge.id} references an unknown node`);
            }
            const existing = this.#edges.get(edge.id);
            if (existing && !sameValue(existing, edge)) {
                throw new Error(`conflicting graph edge id: ${edge.id}`);
            }
            if (!existing) edgesAdded += 1;
        }
        if (this.#edges.size + edgesAdded > this.#maxEdges) {
            throw new RangeError(`graph edge limit exceeded (${this.#maxEdges})`);
        }
        for (const node of output.nodes) {
            if (!this.#nodes.has(node.id)) this.#nodes.set(node.id, node);
        }
        for (const edge of output.edges) {
            if (!this.#edges.has(edge.id)) this.#edges.set(edge.id, edge);
        }
        return {
            nodesAdded,
            edgesAdded,
        };
    }

    getNode(id) {
        const node = this.#nodes.get(id);
        return node ? clone(node) : null;
    }

    getEdge(id) {
        const edge = this.#edges.get(id);
        return edge ? clone(edge) : null;
    }

    toDocument() {
        return validateBehaviorGraphDocument({
            schemaVersion: ANALYSIS_SCHEMA_VERSION,
            auditId: this.#auditId,
            nodes: [...this.#nodes.values()],
            edges: [...this.#edges.values()],
        });
    }
}
