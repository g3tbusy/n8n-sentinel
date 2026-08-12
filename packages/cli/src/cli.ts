import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Command, InvalidArgumentError } from 'commander';
import { atOrAbove, defaultRules, renderHuman, renderJson, renderSarif } from '@n8n-sentinel/core';
import type { ScanReport, Severity } from '@n8n-sentinel/core';
import { scanPaths } from './scan.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = (
  JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8')) as { version: string }
).version;

const FORMATS = ['human', 'json', 'sarif'] as const;
type Format = (typeof FORMATS)[number];

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

/**
 * Коды возврата, выбранные так, чтобы шаг CI различал три исхода.
 *
 * Важно различие с **2**: скан не состоялся. Иначе конвейер, считающий любой ненулевой код
 * за «нашлись уязвимости», объявит сломанный checkout проблемой безопасности, — а сканер,
 * который выходит с нулём на файле, который не смог прочитать, хуже, чем не установленный.
 */
export const EXIT = { clean: 0, findings: 1, error: 2 } as const;

/** Всё, куда CLI пишет; передаётся снаружи, чтобы тесты не перехватывали потоки процесса. */
export interface Io {
  out(text: string): void;
  err(text: string): void;
  /** Терминал ли на stdout. Решает только вопрос цвета. */
  readonly interactive: boolean;
  readonly cwd: string;
}

export function main(argv: readonly string[], io: Io): number {
  const program = new Command();
  let code: number = EXIT.clean;

  // `scan` — единственный глагол, который есть, поэтому он необязателен: `n8n-sentinel scan
  // x.json` и `n8n-sentinel x.json` это одна и та же команда. Отрезать его здесь, а не
  // объявлять подкоманду, нужно, чтобы `--help` продолжал показывать флаги: экран помощи, в
  // котором нет ни `--format`, ни `--fail-on`, хуже, чем отсутствие помощи.
  const args = argv[0] === 'scan' ? argv.slice(1) : argv;

  program
    .name('n8n-sentinel')
    .description(
      'Статический taint-анализ воркфлоу n8n. Находит пути, по которым недоверенный ввод ' +
        'доходит до необратимого действия, и жёстче всего помечает те, что идут туда через ' +
        'LLM с инструментами и без человека в цикле.',
    )
    .version(VERSION)
    .argument('<paths...>', 'файлы JSON с воркфлоу или директории для обхода')
    .option('-f, --format <format>', `формат вывода: ${FORMATS.join(', ')}`, parseFormat, 'human')
    .option(
      '--fail-on <severity>',
      `выйти с кодом ${EXIT.findings}, если найдено что-то этой severity или хуже: ` +
        SEVERITIES.join(', '),
      parseSeverity,
    )
    .option('--no-colour', 'никогда не использовать цвет ANSI')
    .option('--show-clean', 'перечислять и файлы, в которых ничего не найдено')
    .addHelpText(
      'after',
      '\nКоды возврата:\n' +
        `  ${EXIT.clean}  ничего на уровне --fail-on и выше\n` +
        `  ${EXIT.findings}  есть находки на уровне --fail-on и выше\n` +
        `  ${EXIT.error}  скан не состоялся: не удалось прочитать путь\n`,
    )
    .exitOverride()
    .configureOutput({ writeOut: (s) => io.out(s), writeErr: (s) => io.err(s) })
    .showHelpAfterError()
    .action((paths: string[], flags: ScanFlags) => {
      code = runScan(paths, flags, io);
    });

  try {
    program.parse(args, { from: 'user' });
  } catch (error) {
    // Commander бросает исключение и на `--help`, и на `--version`, не только на плохой
    // ввод. Оба уже написали всё, что хотели сказать.
    const kind = (error as { code?: string }).code ?? '';
    if (kind.startsWith('commander.help') || kind === 'commander.version') return EXIT.clean;
    io.err(`${describe(error)}\n`);
    return EXIT.error;
  }
  return code;
}

interface ScanFlags {
  readonly format: Format;
  readonly failOn?: Severity;
  readonly colour: boolean;
  readonly showClean?: boolean;
}

function runScan(paths: readonly string[], flags: ScanFlags, io: Io): number {
  const { files, failures, skipped } = scanPaths(paths, { rules: defaultRules(), root: io.cwd });

  const report: ScanReport = {
    tool: {
      name: 'n8n-sentinel',
      version: VERSION,
      informationUri: 'https://github.com/n8n-sentinel/n8n-sentinel',
    },
    files,
  };

  io.out(`${render(report, flags, io)}\n`);

  if (skipped.length > 0) {
    io.err(
      `n8n-sentinel: пропущено файлов JSON, не являющихся документами воркфлоу: ${skipped.length}\n`,
    );
  }
  for (const failure of failures) io.err(`n8n-sentinel: ${failure.path} ${failure.reason}\n`);
  // Файл, который не удалось прочитать, — это не чистый скан. Сказать об этом лучше, чем
  // поставить зелёную галочку над директорией, половину которой никто не смотрел.
  if (failures.length > 0) return EXIT.error;

  if (flags.failOn === undefined) return EXIT.clean;
  return atOrAbove(report, flags.failOn).length > 0 ? EXIT.findings : EXIT.clean;
}

function render(report: ScanReport, flags: ScanFlags, io: Io): string {
  switch (flags.format) {
    case 'json':
      return renderJson(report);
    case 'sarif':
      return renderSarif(report);
    case 'human':
      return renderHuman(report, {
        // Цвет только когда смотрит человек. Перенаправленный поток получает простой текст,
        // так что и `> report.txt`, и лог CI остаются читаемыми.
        colour: flags.colour && io.interactive,
        showClean: flags.showClean === true,
      });
  }
}

function parseFormat(value: string): Format {
  if (!(FORMATS as readonly string[]).includes(value)) {
    throw new InvalidArgumentError(`ожидалось одно из: ${FORMATS.join(', ')}`);
  }
  return value as Format;
}

function parseSeverity(value: string): Severity {
  if (!(SEVERITIES as readonly string[]).includes(value)) {
    throw new InvalidArgumentError(`ожидалось одно из: ${SEVERITIES.join(', ')}`);
  }
  return value as Severity;
}

const describe = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);
