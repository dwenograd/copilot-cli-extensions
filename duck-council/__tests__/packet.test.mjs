// duck-council packet snapshot tests — lock exact wording of instruction
// packets to catch wording drift that handler tests don't notice.

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

describe("duck-council packet snapshots", () => {
    it("defaults — minimum input (judge ON)", async () => {
        const { deps } = mockDeps();
        const r = await runHandler({ topic: "test topic" }, deps);
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });

    it("skip_judge=true — raw outputs only", async () => {
        const { deps } = mockDeps();
        const r = await runHandler({ topic: "test topic", skip_judge: true }, deps);
        expect(r.resultType).toBe("success");
        expect(stableSnap(r.textResultForLlm)).toMatchSnapshot();
    });
});
