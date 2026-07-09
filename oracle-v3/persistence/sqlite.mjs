// oracle-v3/persistence/sqlite.mjs
//
// Loader shim for the Node 24 built-in `node:sqlite` module.
//
// `node:sqlite` is exposed by Node only under its prefixed specifier and is not
// present in `module.builtinModules` without the prefix. Bundlers/test runners
// that key their builtin detection off the unprefixed name (Vite/Vitest strip
// `node:` and look up `sqlite`, which is absent) will otherwise try to resolve
// it as a real package and fail. Loading it through `createRequire` performs a
// runtime Node resolution and keeps it out of the static import graph.

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export const { DatabaseSync } = require("node:sqlite");
