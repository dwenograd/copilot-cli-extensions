import path from "node:path";

import { describe, expect, it } from "vitest";

import {
    SDK_AVAILABILITY_CODES,
    probeNoninteractiveSdkAvailability,
} from "../runtime/index.mjs";

function input() {
    return {
        sdkPath: path.resolve("sdk-probe-sdk"),
        cliPath: path.resolve("sdk-probe-copilot.exe"),
        workingDirectory: path.resolve("sdk-probe-work"),
        requiredModels: ["model-a", "model-b"],
    };
}

function dependencies({
    auth = { isAuthenticated: true },
    models = [{ id: "model-a" }, { id: "model-b" }],
} = {}) {
    const calls = [];
    const client = {
        async start() {
            calls.push("start");
        },
        async getAuthStatus() {
            calls.push("auth");
            return auth;
        },
        async listModels() {
            calls.push("models");
            return models;
        },
        async stop() {
            calls.push("stop");
        },
        async forceStop() {
            calls.push("force-stop");
        },
    };
    return {
        calls,
        client,
        dependencies: {
            sdkLoader: async () => ({
                CopilotClient: class {},
                RuntimeConnection: {
                    forStdio: ({ path: cliPath }) => ({ cliPath }),
                },
            }),
            clientFactory: async ({ clientOptions }) => {
                expect(clientOptions).toMatchObject({
                    mode: "empty",
                    useLoggedInUser: true,
                    logLevel: "error",
                });
                return client;
            },
        },
    };
}

describe("noninteractive SDK availability probe", () => {
    it("fails closed when same-user authentication is unavailable", async () => {
        const setup = dependencies({
            auth: { isAuthenticated: false, statusMessage: "login required" },
        });
        const result = await probeNoninteractiveSdkAvailability(
            input(),
            setup.dependencies,
        );
        expect(result).toMatchObject({
            ok: false,
            code: SDK_AVAILABILITY_CODES.AUTH_UNAVAILABLE,
            authenticated: false,
        });
        expect(setup.calls).toEqual(["start", "auth", "stop"]);
        expect(JSON.stringify(result)).not.toContain("login required");
    });

    it("requires every frozen model without making a model call", async () => {
        const setup = dependencies({
            models: [{ id: "model-a" }],
        });
        const result = await probeNoninteractiveSdkAvailability(
            input(),
            setup.dependencies,
        );
        expect(result).toMatchObject({
            ok: false,
            code: SDK_AVAILABILITY_CODES.MODEL_UNAVAILABLE,
            missingModels: ["model-b"],
        });
        expect(setup.calls).toEqual([
            "start",
            "auth",
            "models",
            "stop",
        ]);
    });

    it("accepts authenticated model enumeration", async () => {
        const setup = dependencies();
        await expect(probeNoninteractiveSdkAvailability(
            input(),
            setup.dependencies,
        )).resolves.toMatchObject({
            ok: true,
            code: SDK_AVAILABILITY_CODES.AVAILABLE,
            requiredModelCount: 2,
        });
    });
});
