import assert from "node:assert/strict";
import test from "node:test";

import { failure, success } from "../safeWrappers/result.mjs";

test("wrapper success envelope is stable", () => {
    assert.deepEqual(success({ value: 7 }), {
        textResultForLlm: `{
  "ok": true,
  "value": 7
}`,
        resultType: "success",
    });
});

test("wrapper failure envelope is stable", () => {
    assert.deepEqual(failure("refused"), {
        textResultForLlm: `{
  "ok": false,
  "error": "refused"
}`,
        resultType: "failure",
    });
});

test("wrapper failure preserves supplemental data ordering", () => {
    assert.deepEqual(failure("incomplete", { blocker: "coverage", count: 2 }), {
        textResultForLlm: `{
  "ok": false,
  "error": "incomplete",
  "blocker": "coverage",
  "count": 2
}`,
        resultType: "failure",
    });
});
