import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    outDir: "dist",
    clean: true,
    sourcemap: true,
    external: ["keytar"],
  },
  {
    entry: { cli: "src/cli/main.ts" },
    format: ["esm"],
    outDir: "dist",
    banner: { js: "#!/usr/bin/env node" },
    external: ["keytar"],
  },
  {
    entry: {
      "font-data/noto-sans/metrics": "src/core/appearance/font-data/noto-sans/metrics.ts",
      "font-data/ghea-mariam/metrics": "src/core/appearance/font-data/ghea-mariam/metrics.ts",
      "font-data/ghea-grapalat/metrics": "src/core/appearance/font-data/ghea-grapalat/metrics.ts",
    },
    format: ["esm"],
    outDir: "dist",
  },
]);
