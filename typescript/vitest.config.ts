import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/integration/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/cli/**",
        "src/core/appearance/font-data/**",
        "src/network/legacy-tls.ts",
        "src/network/rc4-cipher-suite.ts",
        "src/network/protocol.ts",
      ],
      thresholds: {
        branches: 88,
        functions: 99,
        lines: 96,
        statements: 96,
      },
    },
  },
});
