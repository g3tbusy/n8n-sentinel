import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// CLI импортирует `@n8n-sentinel/core` по имени пакета, а оно разрешается в `dist`. Под
// тестами это должны быть исходники, чтобы `pnpm test` молча не зависел от свежести сборки:
// устаревший dist — это ровно тот зелёный прогон, который ничего не значит.
export default defineConfig({
  resolve: {
    alias: {
      // Сначала самый длинный: подстановка срабатывает по префиксу, иначе голое имя пакета
      // проглотило бы подпуть и разрешило его в `index.ts/browser`.
      '@n8n-sentinel/core/browser': fileURLToPath(
        new URL('./packages/core/src/browser.ts', import.meta.url),
      ),
      '@n8n-sentinel/core': fileURLToPath(new URL('./packages/core/src/index.ts', import.meta.url)),
    },
  },
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    environment: 'node',
  },
});
