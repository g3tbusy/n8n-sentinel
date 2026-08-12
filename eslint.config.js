import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    // Файлы деклараций — это типы, а не код: линтеру там нечего проверять, а без проекта
    // tsconfig типизированные правила на них просто падают.
    ignores: ['**/dist/**', '**/node_modules/**', '**/coverage/**', 'fixtures/**', '**/*.d.mts'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ['packages/*/src/**/*.ts', 'packages/*/test/**/*.ts'],
    ignores: ['packages/web/**'],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.eslint.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    // Визуализатор: браузерное приложение, поэтому у него свой tsconfig с библиотекой DOM.
    files: ['packages/web/src/**/*.ts', 'packages/web/test/**/*.ts', 'packages/web/*.ts'],
    languageOptions: {
      parserOptions: {
        project: ['./packages/web/tsconfig.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    // Отдельные скрипты и полигон — это обычный ESM для Node, они не входят ни в один
    // проект tsconfig.
    files: ['scripts/**/*.mjs', 'packages/range/**/*.mjs', 'eslint.config.js', 'vitest.config.ts'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: {
        console: 'readonly',
        process: 'readonly',
        URL: 'readonly',
        fetch: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
      },
    },
  },
  prettier,
);
