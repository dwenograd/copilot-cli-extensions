import cargoBuild from "./builtins/cargoBuild.mjs";
import cmakeMake from "./builtins/cmakeMake.mjs";
import containerDevcontainer from "./builtins/containerDevcontainer.mjs";
import dotnetMsbuild from "./builtins/dotnetMsbuild.mjs";
import extensionActivation from "./builtins/extensionActivation.mjs";
import githubActions from "./builtins/githubActions.mjs";
import nodeLifecycle from "./builtins/nodeLifecycle.mjs";
import pythonPackaging from "./builtins/pythonPackaging.mjs";
import shellLaunch from "./builtins/shellLaunch.mjs";
import { definePlugin } from "./contract.mjs";

const BUILTIN_PLUGINS = [
    nodeLifecycle,
    extensionActivation,
    githubActions,
    pythonPackaging,
    cargoBuild,
    dotnetMsbuild,
    shellLaunch,
    cmakeMake,
    containerDevcontainer,
];

function validateRegistry(plugins) {
    if (!Array.isArray(plugins)) throw new TypeError("plugin registry must be an array");
    const seen = new Set();
    return Object.freeze(plugins.map((plugin) => {
        const validated = definePlugin(plugin);
        if (seen.has(validated.id)) throw new TypeError(`duplicate plugin id: ${validated.id}`);
        seen.add(validated.id);
        return validated;
    }).sort((left, right) => left.id.localeCompare(right.id)));
}

export const PLUGIN_REGISTRY = validateRegistry(BUILTIN_PLUGINS);

export function getRegisteredPlugins() {
    return PLUGIN_REGISTRY;
}

export const __internals = Object.freeze({
    validateRegistry,
    BUILTIN_PLUGINS,
});
