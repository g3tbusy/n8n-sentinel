import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

// Только исходники. `fixtures/` байт в байт совпадает с тем, что отдаёт библиотека шаблонов,
// и править их нельзя: в одном из тех воркфлоу действительно есть неразрывный пробел, и это
// факт о корпусе, а не дефект этого репозитория. `corpus-study/` генерируется, а схема SARIF
// вложена без изменений.
const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  '.git',
  'coverage',
  '.corpus-cache',
  'fixtures',
  'corpus-study',
]);
const SKIP_FILES = new Set(['sarif-2.1.0.schema.json', 'pnpm-lock.yaml']);
const TEXT = /\.(ts|mjs|js|json|yaml|yml|md)$/;

function sourceFiles(dir: string, found: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.github') continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) sourceFiles(path, found);
    } else if (TEXT.test(entry.name) && !SKIP_FILES.has(entry.name)) {
      found.push(path);
    }
  }
  return found;
}

/**
 * Невидимый управляющий символ в исходнике — это баг, который прячется от ревью.
 *
 * Тест появился потому, что это случилось дважды. Разделитель внутри шаблонной строки — из
 * тех, что редактор рисует пробелом, а diff не показывает никак, — оказался байтом NUL,
 * уехал в опубликованный `data.json` экранированным `\u0000` и разрезал там ключи так, что
 * по чтению кода этого было не увидеть. Оба случая настоящие: один в ключе дедупликации
 * графа, другой в исследовании корпуса.
 *
 * Всё, чему управляющий символ действительно нужен, пишет его escape-последовательностью,
 * которая видна.
 */
describe('никаких невидимых символов в исходниках', () => {
  const files = sourceFiles(REPO_ROOT);

  it('находит файлы для проверки', () => {
    expect(files.length).toBeGreaterThan(20);
  });

  // Записано escape-последовательностями намеренно: тест, запрещающий невидимые символы, не
  // должен протаскивать такой символ в собственный исходник.
  it.each([
    ['NUL', '\u0000'],
    ['zero-width space', '\u200b'],
    ['non-breaking space', '\u00a0'],
  ])('contains no literal %s', (_name, character) => {
    const offenders = files
      .filter((path) => readFileSync(path, 'utf8').includes(character))
      .map((path) => relative(REPO_ROOT, path));
    expect(offenders).toEqual([]);
  });
});
