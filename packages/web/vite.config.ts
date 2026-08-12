import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import type { Plugin } from 'vite';

const fromHere = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

/**
 * Сборка — это один HTML-файл.
 *
 * Не ради изящества: страница утверждает, что брошенный на неё воркфлоу никуда с машины не
 * уходит, и единственный файл, который можно сохранить, прочитать и открыть из `file://`, —
 * это та форма утверждения, которую скептик проверяет за минуту. Заодно это то, что делает
 * страницу пригодной для человека, который ничего устанавливать не станет.
 *
 * Написано здесь, а не взято плагином, потому что это тридцать строк против ещё одной
 * зависимости — и потому что настройка TLS на этой машине превращает любую установку в
 * небольшое приключение
 */
function inlineIntoOneFile(): Plugin {
  const escapeForRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  return {
    name: 'n8n-sentinel:inline-into-one-file',
    enforce: 'post',
    apply: 'build',

    generateBundle(_options, bundle) {
      const html = Object.values(bundle).find(
        (output) => output.type === 'asset' && output.fileName.endsWith('.html'),
      );
      if (html === undefined || html.type !== 'asset') return;

      let source = String(html.source);

      for (const [name, output] of Object.entries(bundle)) {
        if (output.type === 'chunk') {
          const tag = new RegExp(`<script[^>]*src="[^"]*${escapeForRegExp(name)}"[^>]*></script>`);
          // Функция-замена, чтобы `$&` и его родня в минифицированном коде не разворачивались.
          // `</script` внутри строки или регулярного выражения закрыл бы тег раньше времени;
          // `<\/script` — тот же самый JavaScript и закрывающим тегом не является.
          const code = output.code.replace(/<\/script/gi, '<\\/script');
          source = source.replace(tag, () => `<script type="module">${code}</script>`);
        } else if (output.fileName.endsWith('.css')) {
          const tag = new RegExp(`<link[^>]*href="[^"]*${escapeForRegExp(name)}"[^>]*>`);
          source = source.replace(tag, () => `<style>${String(output.source)}</style>`);
        } else {
          continue;
        }
        delete bundle[name];
      }

      html.source = source;
    },

    transformIndexHtml: {
      order: 'post',
      handler(html) {
        // Не обещание, а принуждение. Всё, что нужно странице, лежит внутри неё, поэтому
        // разрешить остаётся только встроенные скрипт и стиль; `connect-src 'none'` означает,
        // что браузер откажет и fetch, и XHR, и WebSocket, даже если будущая правка случайно
        // их добавит. Вставляется только при сборке: серверу разработки нужен его сокет.
        const policy = [
          "default-src 'none'",
          "script-src 'unsafe-inline'",
          "style-src 'unsafe-inline'",
          'img-src data:',
          'font-src data:',
          "connect-src 'none'",
          "form-action 'none'",
          "base-uri 'none'",
        ].join('; ');
        return html.replace(
          '<head>',
          `<head>\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />`,
        );
      },
    },
  };
}

export default defineConfig({
  base: './',
  resolve: {
    alias: {
      '@n8n-sentinel/core/browser': fromHere('../core/src/browser.ts'),
    },
  },
  server: {
    // Файлы правил и демонстрационные воркфлоу лежат вне этого пакета.
    fs: { allow: [fromHere('../..')] },
  },
  build: {
    target: 'es2022',
    cssCodeSplit: false,
    modulePreload: false,
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
  plugins: [inlineIntoOneFile()],
});
