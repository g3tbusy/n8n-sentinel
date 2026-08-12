import { afterAll, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { EXIT, main } from '../src/cli.js';
import type { Io } from '../src/cli.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const FIXTURES = join(REPO_ROOT, 'fixtures', 'real');
const VULNERABLE = join(FIXTURES, '04057-auto-respond-to-gmail-enquiries-using-gpt-4o-dum.json');
const GATED = join(FIXTURES, '13216-post-ai-news-to-telegram-with-google-gemini-and-.json');

interface Run {
  readonly code: number;
  readonly out: string;
  readonly err: string;
}

/** Runs the CLI exactly as the bin shim does, minus the process streams. */
function run(...argv: string[]): Run {
  let out = '';
  let err = '';
  const io: Io = {
    out: (text) => {
      out += text;
    },
    err: (text) => {
      err += text;
    },
    interactive: false,
    cwd: REPO_ROOT,
  };
  return { code: main(argv, io), out, err };
}

const scratch = mkdtempSync(join(tmpdir(), 'n8n-sentinel-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

describe('сканирование', () => {
  it('сканирует один файл', () => {
    const result = run(VULNERABLE);
    expect(result.code).toBe(EXIT.clean);
    expect(result.out).toContain('INDIRECT_PROMPT_INJECTION');
    expect(result.out).toContain('Send Email Response via Gmail');
  });

  it('обходит директорию', () => {
    const result = run(FIXTURES);
    expect(result.out).toMatch(/в \d+ воркфлоу из 24/);
  });

  it('печатает пути относительно места запуска скана', () => {
    expect(run(VULNERABLE).out).toContain('fixtures/real/04057');
  });

  it('считает JSON в директории, который не воркфлоу, не расписывая это на страницу', () => {
    // `fixtures/real/manifest.json` — это индексные данные, а не воркфлоу. Тот, кто указал на
    // папку, спрашивал не про него.
    const result = run(FIXTURES);
    expect(result.err).toContain('пропущено файлов JSON, не являющихся документами воркфлоу: 1');
    expect(result.out).not.toContain('manifest.json');
  });

  it('всё же сообщает о не-воркфлоу, названном явно', () => {
    const result = run(join(FIXTURES, 'manifest.json'));
    expect(result.out).toContain('not_a_workflow');
  });

  it('сканирует остальное, когда один файл из списка битый', () => {
    const broken = join(scratch, 'broken.json');
    writeFileSync(broken, '{ this is not json');

    const result = run(VULNERABLE, broken);
    expect(result.out).toContain('INDIRECT_PROMPT_INJECTION');
    expect(result.err).toContain('не является корректным JSON');
    expect(result.code).toBe(EXIT.error);
  });
});

describe('коды возврата', () => {
  it('молчит о находках, пока не попросят падать на них', () => {
    // Сканировать не значит блокировать. Прогон без порога показывает находки и выходит с нулём.
    expect(run(VULNERABLE).code).toBe(EXIT.clean);
  });

  it('падает на находке на уровне порога и выше', () => {
    expect(run(VULNERABLE, '--fail-on', 'critical').code).toBe(EXIT.findings);
  });

  it('проходит, когда до порога ничего не дотягивает', () => {
    // У воркфлоу с гейтом все находки уровня `low`.
    expect(run(GATED, '--fail-on', 'critical').code).toBe(EXIT.clean);
    expect(run(GATED, '--fail-on', 'low').code).toBe(EXIT.findings);
  });

  it('отличает «не смог просканировать» от «что-то нашёл»', () => {
    // Конвейер, считающий любой ненулевой код за уязвимости, иначе объявит сломанный checkout
    // проблемой безопасности.
    const missing = run(join(scratch, 'absent.json'));
    expect(missing.code).toBe(EXIT.error);
    expect(missing.err).toContain('не удалось открыть');
  });

  it('отвергает порог, которого у него нет', () => {
    const result = run(VULNERABLE, '--fail-on', 'catastrophic');
    expect(result.code).toBe(EXIT.error);
    expect(result.err).toContain('ожидалось одно из');
  });

  it('отвергает формат, который не умеет писать', () => {
    const result = run(VULNERABLE, '--format', 'xml');
    expect(result.code).toBe(EXIT.error);
    expect(result.err).toContain('ожидалось одно из');
  });

  it('выходит с нулём на --help', () => {
    const result = run('--help');
    expect(result.code).toBe(EXIT.clean);
    expect(result.out).toContain('--fail-on');
  });
});

describe('форматы', () => {
  it('пишет JSON, который разбирается', () => {
    const result = run(VULNERABLE, '--format', 'json');
    const parsed = JSON.parse(result.out) as { version: number; files: unknown[] };
    expect(parsed.version).toBe(1);
    expect(parsed.files).toHaveLength(1);
  });

  it('пишет SARIF, который разбирается', () => {
    const parsed = JSON.parse(run(VULNERABLE, '--format', 'sarif').out) as { version: string };
    expect(parsed.version).toBe('2.1.0');
  });

  it('пишет простой текст, когда на stdout не терминал', () => {
    expect(run(VULNERABLE).out).not.toMatch(/\[/);
  });
});
