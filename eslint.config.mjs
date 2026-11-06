// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

// Strict from the first commit. Nothing is a warning.
// - typescript-eslint strictTypeChecked;
// - no type assertions (only `as const`), no `!`, no `any`, no @ts- comments;
// - no eslint-disable comments: a rule that does not fit is changed here;
// - every regular expression in src/ goes through the pattern compiler, so
//   the safety check sees it. Regex literals and `new RegExp` are allowed
//   only in src/pattern/compile.ts.
export default tseslint.config(
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "coverage/**",
      "reports/**",
      ".stryker-tmp/**",
      "test/consumer/**",
    ],
  },
  {
    linterOptions: {
      noInlineConfig: true,
      reportUnusedDisableDirectives: "error",
    },
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      curly: ["error", "all"],
      "@typescript-eslint/consistent-type-assertions": ["error", { assertionStyle: "never" }],
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/ban-ts-comment": [
        "error",
        { "ts-expect-error": true, "ts-ignore": true, "ts-nocheck": true, "ts-check": false },
      ],
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-floating-promises": [
        "error",
        {
          // node:test's describe and it return promises the runner awaits.
          allowForKnownSafeCalls: [{ from: "package", name: ["describe", "it"], package: "node:test" }],
        },
      ],
      "@typescript-eslint/strict-boolean-expressions": [
        "error",
        { allowString: false, allowNumber: false, allowNullableObject: true },
      ],
      eqeqeq: "error",
      "no-console": "error",
      "no-eval": "error",
      "no-new-func": "error",
    },
  },
  {
    files: ["src/**/*.ts"],
    // parse.ts reads rule sources (never scanned text) with a few fixed,
    // anchored expressions.
    ignores: ["src/pattern/compile.ts", "src/pattern/parse.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "Literal[regex]",
          message: "Write the pattern as a rule string. src/pattern/compile.ts checks and builds it.",
        },
        {
          selector: "NewExpression[callee.name='RegExp'], CallExpression[callee.name='RegExp']",
          message: "Only src/pattern/compile.ts builds a RegExp, after the safety check.",
        },
      ],
    },
  },
  {
    files: ["**/*.mjs"],
    ...tseslint.configs.disableTypeChecked,
  },
);
