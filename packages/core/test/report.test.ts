import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';
import { analyseWorkflow } from '../src/analyse.js';
import { defaultRules } from '../src/rules/default-rules.js';
import { renderHuman } from '../src/report/human.js';
import { renderJson } from '../src/report/json.js';
import { renderSarif } from '../src/report/sarif.js';
import { locateNode } from '../src/report/locate.js';
import { atOrAbove, summarise } from '../src/report/types.js';
import type { ScanReport, ScannedFile } from '../src/report/types.js';

// ajv поставляется как CommonJS. При NodeNext импорт по умолчанию связывается с пространством
// имён модуля, а не с классом, поэтому он требуется явно, а не заклеивается лживым приведением
// типа.
const require_ = createRequire(import.meta.url);
const Ajv = require_('ajv') as new (options: object) => {
  compile(schema: object): { (data: unknown): boolean; errors?: unknown[] | null | undefined };
};
const addFormats = require_('ajv-formats') as (ajv: unknown) => void;

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', '..', '..', 'fixtures', 'real');
const rules = defaultRules();

const VULNERABLE = '04057-auto-respond-to-gmail-enquiries-using-gpt-4o-dum.json';
const GATED = '13216-post-ai-news-to-telegram-with-google-gemini-and-.json';

function scanned(file: string): ScannedFile {
  const text = readFileSync(join(FIXTURES, file), 'utf8');
  const result = analyseWorkflow(JSON.parse(text), rules);
  return {
    path: `fixtures/real/${file}`,
    workflow: result.workflow,
    findings: result.findings,
    warnings: result.warnings,
    text,
  };
}

const reportOf = (...files: string[]): ScanReport => ({
  tool: { name: 'n8n-sentinel', version: '0.0.0', informationUri: 'https://example.invalid' },
  files: files.map(scanned),
});

const full = reportOf(VULNERABLE, GATED);

describe('поиск ноды в файле', () => {
  it('находит строку, где объявлена нода', () => {
    const text = readFileSync(join(FIXTURES, VULNERABLE), 'utf8');
    const region = locateNode(text, 'Send Email Response via Gmail');

    expect(region).toBeDefined();
    const line = text.split('\n')[(region as { line: number }).line - 1] ?? '';
    expect(line).toContain('"name": "Send Email Response via Gmail"');
  });

  it('возвращает пустоту, а не неверную строку', () => {
    // Отсутствующий номер строки — меньшая ложь, чем выдуманный.
    expect(locateNode('{"nodes":[]}', 'Nobody')).toBeUndefined();
  });

  it('переживает имя ноды с символами, которые сломали бы регулярное выражение', () => {
    const text = '{\n  "nodes": [\n    { "name": "Send (a) [thing] +/*" }\n  ]\n}';
    expect(locateNode(text, 'Send (a) [thing] +/*')?.line).toBe(3);
  });
});

describe('человекочитаемый отчёт', () => {
  const text = renderHuman(full);

  it('показывает трассу, а не только приговор', () => {
    // То, что читатель может сверить с холстом перед собой.
    expect(text).toContain('Watch Gmail for New Incoming Emails');
    expect(text).toContain('Classify Email Type with GPT-4o');
    expect(text).toContain('LangChain Agent Handles Reply Logic');
    expect(text).toContain('Send Email Response via Gmail');
  });

  it('помечает шаг, который n8n хранит задом наперёд', () => {
    expect(text).toContain('(агент → инструмент, выведено)');
  });

  it('называет слабый гейт на пути', () => {
    expect(text).toContain('слабый гейт');
  });

  it('даёт каждой находке объяснение и починку', () => {
    expect(text).toContain('почему  ');
    expect(text).toContain('чинить  ');
  });

  it('заканчивается итогом по severity и по правилам', () => {
    expect(text).toMatch(/critical \d+/);
    expect(text).toContain('INDIRECT_PROMPT_INJECTION');
  });

  it('не выдаёт escape-последовательностей, пока не попросят', () => {
    // eslint-disable-next-line no-control-regex
    expect(text).not.toMatch(/\[/);
    // eslint-disable-next-line no-control-regex
    expect(renderHuman(full, { colour: true })).toMatch(/\[/);
  });

  it('говорит, что чистый скан значит, а что нет', () => {
    const clean = renderHuman({ tool: full.tool, files: [] });
    expect(clean).toContain('Ничего не найдено');
    expect(clean).toContain('не справка о здоровье');
  });
});

describe('отчёт JSON', () => {
  const parsed = JSON.parse(renderJson(full)) as {
    version: number;
    summary: { findings: number; bySeverity: Record<string, number> };
    files: { path: string; findings: { rule: string; remediation: string }[] }[];
  };

  it('несёт версию, чтобы форма могла меняться, не ломая потребителя молча', () => {
    expect(parsed.version).toBe(1);
  });

  it('считает то, что содержит', () => {
    const counted = parsed.files.reduce((n, f) => n + f.findings.length, 0);
    expect(parsed.summary.findings).toBe(counted);
  });

  it('сохраняет рекомендацию у каждой находки', () => {
    for (const file of parsed.files) {
      for (const finding of file.findings) expect(finding.remediation.length).toBeGreaterThan(20);
    }
  });

  it('выбрасывает текст файла: он был входными данными, а не результатом', () => {
    expect(renderJson(full)).not.toContain('"text"');
  });
});

describe('отчёт SARIF', () => {
  const sarif = JSON.parse(renderSarif(full)) as {
    version: string;
    runs: {
      tool: { driver: { name: string; rules: { id: string; properties: { tags: string[] } }[] } };
      results: {
        ruleId: string;
        ruleIndex: number;
        level: string;
        locations: { physicalLocation: { region?: { startLine: number } } }[];
        properties: Record<string, unknown>;
        partialFingerprints: Record<string, string>;
        codeFlows?: { threadFlows: { locations: unknown[] }[] }[];
      }[];
    }[];
  };
  const run = sarif.runs[0] as (typeof sarif.runs)[number];

  // Definition of Done этой фазы. Вложена из schemastore.org, чтобы проверка работала офлайн
  // и схема не могла тихо измениться под тестом.
  it('проходит валидацию по схеме SARIF 2.1.0', () => {
    const schema = JSON.parse(
      readFileSync(join(HERE, 'sarif-2.1.0.schema.json'), 'utf8'),
    ) as object;
    const ajv = new Ajv({ strict: false, allErrors: true });
    addFormats(ajv);

    const validate = ajv.compile(schema);
    const valid = validate(sarif);
    expect(validate.errors ?? [], JSON.stringify(validate.errors?.slice(0, 5), null, 2)).toEqual(
      [],
    );
    expect(valid).toBe(true);
  });

  it('рекламирует только сработавшие правила', () => {
    const fired = new Set(run.results.map((r) => r.ruleId));
    expect(new Set(run.tool.driver.rules.map((r) => r.id))).toEqual(fired);
  });

  it('указывает каждым индексом правила на то правило, которое называет', () => {
    for (const result of run.results) {
      expect(run.tool.driver.rules[result.ruleIndex]?.id).toBe(result.ruleId);
    }
  });

  it('даёт GitHub то, что нужно, чтобы показать это оповещениями безопасности', () => {
    // GitHub читает `security-severity`, а не четыре уровня SARIF, и считает результат
    // оповещением безопасности, только когда у его правила есть тег `security`.
    for (const rule of run.tool.driver.rules) expect(rule.properties.tags).toContain('security');
    for (const result of run.results) {
      expect(Number(result.properties['security-severity'])).toBeGreaterThan(0);
    }
  });

  it('указывает на строку, а не только на файл', () => {
    for (const result of run.results) {
      expect(result.locations[0]?.physicalLocation.region?.startLine).toBeGreaterThan(0);
    }
  });

  it('несёт путь taint в виде codeFlow', () => {
    const injection = run.results.find((r) => r.ruleId === 'INDIRECT_PROMPT_INJECTION');
    const steps = injection?.codeFlows?.[0]?.threadFlows[0]?.locations ?? [];
    // Триггер Gmail, классификатор, фильтр, агент, отправка — те же пять, что показывает отчёт.
    expect(steps).toHaveLength(5);
  });

  it('считает отпечаток находки по пути, а не по severity', () => {
    const [first] = run.results;
    expect(Object.values(first?.partialFingerprints ?? {})[0]).toMatch(/^[0-9a-f]{8}$/);
  });

  it('остаётся валидным, когда сообщать нечего', () => {
    const empty = JSON.parse(renderSarif({ tool: full.tool, files: [] })) as {
      runs: { results: unknown[]; tool: { driver: { rules: unknown[] } } }[];
    };
    expect(empty.runs[0]?.results).toEqual([]);
    expect(empty.runs[0]?.tool.driver.rules).toEqual([]);
  });
});

describe('пороги', () => {
  it('считает severity и всё, что хуже', () => {
    const bands = summarise(full).bySeverity;
    expect(atOrAbove(full, 'critical')).toHaveLength(bands.critical);
    expect(atOrAbove(full, 'high')).toHaveLength(bands.critical + bands.high);
    expect(atOrAbove(full, 'low')).toHaveLength(summarise(full).findings);
  });
});
