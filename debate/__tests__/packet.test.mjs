// debate packet snapshot tests — lock exact wording of instruction packets
// to catch typos and accidental wording drift that handler tests don't notice.

import { describe, it, expect, vi } from "vitest";
import { runHandler } from "../handler.mjs";

function mockDeps() {
    const logged = [];
    return {
        deps: { log: vi.fn(async (msg) => logged.push(msg)) },
        logged,
    };
}

function stableSnap(packet) {
    // Replace any 16-char hex nonce inside <<<...>>> markers with a fixed token
    return packet.replace(/<<<[a-f0-9]{16}>>>/g, "<<<NONCE>>>");
}

describe("debate packet snapshots", () => {
    it("defaults — minimum input", async () => {
        const { deps } = mockDeps();
        const r = await runHandler(
            { question: "should we use a state machine?" },
            deps
        );
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });

    it("cheap mode", async () => {
        const { deps } = mockDeps();
        const r = await runHandler(
            { question: "should we use a state machine?", cheap: true },
            deps
        );
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });

    it("multi-round — rounds: 3", async () => {
        const { deps } = mockDeps();
        const r = await runHandler(
            { question: "should we use a state machine?", rounds: 3 },
            deps
        );
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });

    it("both positions specified", async () => {
        const { deps } = mockDeps();
        const r = await runHandler(
            {
                question: "should we use a state machine?",
                position_a: "yes, use a state machine for clarity",
                position_b: "no, conditionals are simpler",
            },
            deps
        );
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });

    it("explicit debaters + judge", async () => {
        const { deps } = mockDeps();
        const r = await runHandler(
            {
                question: "should we use a state machine?",
                debaters: ["gpt-5.5", "claude-opus-4.7"],
                judge: "claude-opus-4.6",
            },
            deps
        );
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });

    it("with context", async () => {
        const { deps } = mockDeps();
        const r = await runHandler(
            {
                question: "should we use a state machine?",
                context: "our UI flow has 15 states and is getting complex",
            },
            deps
        );
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });
});
