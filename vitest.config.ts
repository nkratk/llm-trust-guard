import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts", "src/index.ts"],
      thresholds: {
        lines: 78,
        functions: 68,
        branches: 65,
        statements: 78,
      },
    },
    testTimeout: 10000,
  },
});
