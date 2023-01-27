#!/usr/bin/env node

import * as esbuild from "esbuild";

let makeAllPackagesExternalPlugin = {
  name: "make-all-packages-external",
  setup(build) {
    let filter = /^[^.\/]|^\.[^.\/]|^\.\.[^\/]/; // Must not start with "/" or "./" or "../"
    build.onResolve({ filter }, (args) => ({
      path: args.path,
      external: true,
    }));
  },
};

esbuild
  .build({
    entryPoints: ["./src/index.ts"],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "es2020",
    minify: false,
    sourcemap: false,
    outfile: "./lib/index.js",
    mainFields: ["main"],
    preserveSymlinks: false,
    plugins: [makeAllPackagesExternalPlugin],
  })
  .catch((reason) => {
    console.log(reason);
    process.exit(1);
  });
