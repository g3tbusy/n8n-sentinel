import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

/**
 * Браузерная точка входа не должна дотягиваться до файловой системы.
 *
 * Проверяется обходом импортов, а не сборкой, потому что поломка, от которой это стережёт,
 * в момент возникновения молчалива: добавить `readFileSync` в чекер на Node ничего не стоит,
 * все остальные тесты это пройдут, и всплывёт оно сломанной сборкой визуализатора сильно
 * позже. Обход графа называет модуль и виноватый импорт в тот же момент, когда он появился.
 */

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'src');

/**
 * Статические спецификаторы `import`/`export … from` и `import(...)` с литеральным аргументом.
 *
 * Кусок между ключевым словом и `from` сопоставляется как «ни кавычки, ни точки с запятой»:
 * так он покрывает многострочные блоки `export { … }` этого пакета и при этом отказывается
 * убегать за конец инструкции. Более свободное сопоставление заходит прямо в шаблонные строки
 * репортеров и вычитывает ``from "${source}"`` из строки.
 */
function specifiersOf(source: string): string[] {
  const found: string[] = [];
  const patterns = [
    /(?:^|\n)\s*import\s+(?:[^'";]+?\s+from\s+)?['"]([^'"]+)['"]/g,
    /(?:^|\n)\s*export\s+[^'";]+?\s+from\s+['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier !== undefined) found.push(specifier);
    }
  }
  return found;
}

interface Reach {
  readonly files: Set<string>;
  /** Голые спецификаторы, сопоставленные с файлом, который их импортировал. */
  readonly packages: Map<string, string>;
}

function reachableFrom(entry: string): Reach {
  const files = new Set<string>();
  const packages = new Map<string, string>();
  const queue = [entry];

  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (files.has(file)) continue;
    files.add(file);

    for (const specifier of specifiersOf(readFileSync(file, 'utf8'))) {
      if (!specifier.startsWith('.')) {
        if (!packages.has(specifier)) packages.set(specifier, file);
        continue;
      }
      // Импорты в исходниках несут расширение `.js`, которое пишет TypeScript; файл — `.ts`.
      const target = resolve(dirname(file), specifier.replace(/\.js$/, '.ts'));
      queue.push(target);
    }
  }
  return { files, packages };
}

describe('браузерная точка входа', () => {
  const reach = reachableFrom(join(SRC, 'browser.ts'));

  it('не дотягивается ни до одного встроенного модуля Node', () => {
    const builtins = [...reach.packages].filter(([specifier]) => specifier.startsWith('node:'));
    expect(builtins, `imported by: ${builtins.map(([s, f]) => `${s} <- ${f}`).join(', ')}`).toEqual(
      [],
    );
  });

  it('зависит от одного пакета, и тот работает в браузере', () => {
    // `yaml` — чистый JavaScript. Для любого пополнения этого списка должно быть верно то же
    // самое, поэтому список проверяется точным равенством, а не фильтром.
    expect([...reach.packages.keys()].sort()).toEqual(['yaml']);
  });

  it('не дотягивается до модуля, читающего файлы правил', () => {
    expect([...reach.files].map((f) => f.slice(SRC.length + 1))).not.toContain(
      join('rules', 'default-rules.ts'),
    );
  });

  it('покрывает тот анализ, который вызывающему действительно нужен', () => {
    const names = [...reach.files].map((f) => f.slice(SRC.length + 1));
    for (const required of [
      'analyse.ts',
      join('parser', 'parse-workflow.ts'),
      join('taint', 'engine.ts'),
      join('checkers', 'index.ts'),
      join('report', 'index.ts'),
      join('rules', 'registry.ts'),
    ]) {
      expect(names).toContain(required);
    }
  });

  it('это то, что реэкспортирует точка входа для Node', async () => {
    const browser = await import('../src/browser.js');
    const index = await import('../src/index.js');
    for (const name of Object.keys(browser)) expect(index).toHaveProperty(name);
    // Точка входа для Node добавляет ровно два помощника, читающих файлы.
    const extra = Object.keys(index).filter((name) => !(name in browser));
    expect(extra.sort()).toEqual(['defaultRegistry', 'defaultRules']);
  });
});
