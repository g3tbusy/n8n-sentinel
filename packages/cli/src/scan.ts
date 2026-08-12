import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { analyseWorkflow } from '@n8n-sentinel/core';
import type { Rules, ScannedFile } from '@n8n-sentinel/core';

/** Директории, заходить в которые никогда не стоит. */
const SKIP = new Set(['node_modules', '.git', 'dist', 'coverage', '.corpus-cache']);

export interface ScanOptions {
  readonly rules: Rules;
  /** Пути печатаются относительно этого каталога. */
  readonly root: string;
}

export interface ScanFailure {
  readonly path: string;
  readonly reason: string;
}

export interface ScanOutcome {
  readonly files: ScannedFile[];
  /** Файлы, которые не удалось прочитать или которые вообще не JSON. Сообщаются, но не фатальны. */
  readonly failures: ScanFailure[];
  /**
   * Файлы JSON, найденные обходом директории и оказавшиеся вовсе не воркфлоу.
   *
   * Считаются, а не перечисляются по одному. Тот, кто указал на папку, не спрашивал про её
   * `package.json`, и страница «это не воркфлоу» перед находками — ровно тот способ, которым
   * отчёт приучает людей его пролистывать. Явно названный файл предупреждение всё же получит:
   * там вопрос был именно про него.
   */
  readonly skipped: string[];
}

/**
 * Сканирует файлы и директории в том порядке, в каком их передали.
 *
 * Прогон по корпусу трогает тысячи документов, и двухсотый битый файл не должен его
 * заканчивать — по той же причине, по которой `parseWorkflow` никогда не бросает исключение.
 * Нечитаемые файлы собираются и показываются в конце, а не поднимают ошибку.
 */
export function scanPaths(paths: readonly string[], options: ScanOptions): ScanOutcome {
  const files: ScannedFile[] = [];
  const failures: ScanFailure[] = [];
  const skipped: string[] = [];

  for (const target of paths) {
    const { found, explicit } = expand(target, failures);
    for (const file of found) {
      const scanned = scanFile(file, options);
      if ('reason' in scanned) {
        failures.push(scanned);
        continue;
      }
      if (!explicit && notAWorkflow(scanned)) {
        skipped.push(scanned.path);
        continue;
      }
      files.push(scanned);
    }
  }

  return { files, failures, skipped };
}

/** В документе нет массива `nodes` — это какой-то другой JSON, случайно попавшийся под руку. */
const notAWorkflow = (file: ScannedFile): boolean =>
  file.warnings.some((w) => w.code === 'not_a_workflow');

function scanFile(path: string, options: ScanOptions): ScannedFile | ScanFailure {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    return { path, reason: `не удалось прочитать: ${message(error)}` };
  }

  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch (error) {
    return { path, reason: `не является корректным JSON: ${message(error)}` };
  }

  const result = analyseWorkflow(document, options.rules);
  return {
    path: printable(path, options.root),
    workflow: result.workflow,
    findings: result.findings,
    warnings: result.warnings,
    text,
  };
}

/** Файл остаётся собой; директория превращается в каждый `.json` под ней, по алфавиту. */
function expand(target: string, failures: ScanFailure[]): { found: string[]; explicit: boolean } {
  let stats;
  try {
    stats = statSync(target);
  } catch (error) {
    failures.push({ path: target, reason: `не удалось открыть: ${message(error)}` });
    return { found: [], explicit: true };
  }

  if (stats.isFile()) return { found: [target], explicit: true };
  if (!stats.isDirectory()) return { found: [], explicit: true };

  const found: string[] = [];
  const walk = (dir: string): void => {
    // Отсортировано, чтобы два прогона по одному дереву давали один и тот же отчёт, в каком
    // бы порядке файловая система ни возвращала записи.
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      if (entry.isDirectory()) {
        if (!SKIP.has(entry.name) && !entry.name.startsWith('.')) walk(join(dir, entry.name));
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        found.push(join(dir, entry.name));
      }
    }
  };
  walk(target);
  return { found, explicit: false };
}

/** Относительный путь, если он короче и остаётся внутри дерева; иначе абсолютный. */
function printable(path: string, root: string): string {
  const rel = relative(root, path);
  return rel === '' || rel.startsWith(`..${sep}`) ? path : rel;
}

const message = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);
