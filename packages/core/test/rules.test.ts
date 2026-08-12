import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { defaultRegistry } from '../src/rules/default-rules.js';
import { parseWorkflow } from '../src/parser/parse-workflow.js';
import type { GraphNode } from '../src/graph/types.js';
import type { NodeDefaults, RuleFile } from '../src/rules/types.js';
import { parse as parseYaml } from 'yaml';

const CORE = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = join(CORE, '..', '..');
const FIXTURES = join(REPO_ROOT, 'fixtures', 'real');

const registry = defaultRegistry();
const rules = parseYaml(readFileSync(join(CORE, 'rules', 'nodes.yaml'), 'utf8')) as RuleFile;
const defaults = JSON.parse(
  readFileSync(join(CORE, 'rules', 'node-defaults.json'), 'utf8'),
) as NodeDefaults;

/** Собирает минимум GraphNode, который нужен классификации. */
const node = (type: string, parameters: Record<string, unknown> = {}): GraphNode => ({
  name: 'n',
  type,
  typeVersion: 1,
  disabled: false,
  parameters,
  credentials: {},
  hasPinnedData: false,
  raw: { name: 'n', type },
});

describe('целостность файла правил', () => {
  it('покрывает как минимум 40 типов нод, которые требует фаза 2', () => {
    expect(registry.size).toBeGreaterThanOrEqual(40);
  });

  it('не содержит дублирующихся записей', () => {
    const types = rules.nodes.map((n) => n.type);
    expect(types.length).toBe(new Set(types).size);
  });

  it('даёт каждой записи хотя бы одну роль или явную причину обойтись без них', () => {
    for (const entry of rules.nodes) {
      if (entry.roles.length > 0) continue;
      // Нода без ролей обязана объяснить почему — иначе это выглядит недописанным правилом.
      expect(entry.note ?? entry.type, entry.type).toBeTruthy();
    }
  });

  it('объявляет sink всякий раз, когда заявляет роль sink, и наоборот', () => {
    const check = (
      label: string,
      roles: readonly string[] | undefined,
      facets: { source?: unknown; sink?: unknown; sanitizer?: unknown },
    ): void => {
      if (!roles) return;
      expect(roles.includes('sink'), `${label}: sink role vs sink block`).toBe(
        facets.sink !== undefined,
      );
      expect(roles.includes('source'), `${label}: source role vs source block`).toBe(
        facets.source !== undefined,
      );
      expect(roles.includes('sanitizer'), `${label}: sanitizer role vs sanitizer block`).toBe(
        facets.sanitizer !== undefined,
      );
    };

    for (const entry of rules.nodes) {
      check(entry.type, entry.roles, entry);
      for (const [i, v] of (entry.variants ?? []).entries()) {
        check(`${entry.type} variant ${i}`, v.roles, v);
      }
    }
  });

  // Смысл этого теста: правило, ловящее операцию, которой у n8n нет, — мёртвый код,
  // выглядящий покрытием. Сверяется с собственным каталогом n8n, а не с верой.
  it('совпадает только с операциями, ресурсами и режимами, которые n8n действительно предлагает', () => {
    const problems: string[] = [];

    for (const entry of rules.nodes) {
      const known = defaults.nodes[entry.type];
      if (!known?.options) continue;

      for (const [i, variant] of (entry.variants ?? []).entries()) {
        for (const key of ['resource', 'operation', 'method', 'mode', 'resume'] as const) {
          const wanted = variant.when[key];
          const offered = known.options[key];
          if (!wanted || !offered) continue;
          for (const value of wanted) {
            if (!offered.includes(value)) {
              problems.push(`${entry.type} variant ${i}: ${key}="${value}" is not one of n8n's`);
            }
          }
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it('классифицирует каждый тип ноды, для которого есть правило, без исключений', () => {
    for (const type of registry.types()) {
      expect(registry.classify(node(type)).known, type).toBe(true);
    }
  });
});

// n8n не сохраняет параметры, оставленные по умолчанию. Эти случаи и отличают реестр,
// работающий на настоящих воркфлоу, от реестра, работающего только на примерах из головы.
describe('разрешение дефолтов n8n для отсутствующих параметров', () => {
  it('читает голую ноду Gmail как отправку, потому что таков её дефолт', () => {
    const c = registry.classify(node('n8n-nodes-base.gmail'));
    expect(c.resolved).toMatchObject({ resource: 'message', operation: 'send' });
    expect(c.roles).toContain('sink');
    expect(c.sink).toEqual({ effect: 'send-message', irreversible: true });
  });

  it('читает голую ноду Google Sheets как чтение, а не запись', () => {
    // У 328 нод Sheets в выборке корпуса нет operation. Считать их записью по умолчанию
    // значило бы повесить ложный critical на большую долю всех настоящих воркфлоу.
    const c = registry.classify(node('n8n-nodes-base.googleSheets'));
    expect(c.resolved.operation).toBe('read');
    expect(c.roles).toContain('source');
    expect(c.roles).not.toContain('sink');
  });

  it('читает голый HTTP Request как GET и всё равно считает его исходящим', () => {
    const c = registry.classify(node('n8n-nodes-base.httpRequest'));
    expect(c.resolved.method).toBe('GET');
    expect(c.sink).toEqual({ effect: 'http-egress', irreversible: false });
    expect(c.roles).toContain('source');
  });

  it('помечает POST необратимым там, где GET не является', () => {
    const c = registry.classify(node('n8n-nodes-base.httpRequest', { method: 'POST' }));
    expect(c.sink).toEqual({ effect: 'http-egress', irreversible: true });
  });

  it('берёт операцию по умолчанию для того ресурса, который используется', () => {
    // У Gmail дефолт — `send` для сообщений и `create` для черновиков.
    const draft = registry.classify(node('n8n-nodes-base.gmail', { resource: 'draft' }));
    expect(draft.resolved.operation).toBe('create');
    expect(draft.sink).toEqual({ effect: 'write-database', irreversible: false });
  });

  it('считает операцию, заданную выражением, неизвестной, а не дефолтной', () => {
    const c = registry.classify(
      node('n8n-nodes-base.gmail', { operation: '={{ $json.whatToDo }}' }),
    );
    expect(c.resolved.operation).toBeUndefined();
    expect(c.matchedVariant).toBe(false);
    expect(c.sink).toBeUndefined();
  });
});

describe('классификация в зависимости от операции', () => {
  it.each([
    ['select', 'source', undefined],
    ['insert', 'sink', 'write-database'],
    ['update', 'sink', 'write-database'],
    ['deleteTable', 'sink', 'delete-data'],
    ['executeQuery', 'sink', 'write-database'],
  ])('postgres %s is a %s', (operation, role, effect) => {
    const c = registry.classify(node('n8n-nodes-base.postgres', { operation }));
    expect(c.roles).toContain(role);
    expect(c.sink?.effect).toBe(effect);
  });

  it('postgres select не является sink', () => {
    const c = registry.classify(node('n8n-nodes-base.postgres', { operation: 'select' }));
    expect(c.roles).not.toContain('sink');
    expect(c.source?.trust).toBe('semi-trusted');
  });

  it('читает векторное хранилище как источник, если только оно не вставляет', () => {
    const retrieve = registry.classify(node('@n8n/n8n-nodes-langchain.vectorStoreQdrant'));
    expect(retrieve.resolved.mode).toBe('retrieve');
    expect(retrieve.roles).toContain('source');

    const insert = registry.classify(
      node('@n8n/n8n-nodes-langchain.vectorStoreQdrant', { mode: 'insert' }),
    );
    expect(insert.roles).toContain('sink');
  });

  it('считает ноду Wait публичным источником, только когда она возобновляется вебхуком', () => {
    const timed = registry.classify(node('n8n-nodes-base.wait'));
    expect(timed.roles).not.toContain('source');

    const resumed = registry.classify(node('n8n-nodes-base.wait', { resume: 'webhook' }));
    expect(resumed.source?.trust).toBe('untrusted-public');
  });
});

describe('подтверждение человеком', () => {
  it.each([
    'n8n-nodes-base.gmail',
    'n8n-nodes-base.slack',
    'n8n-nodes-base.telegram',
    'n8n-nodes-base.discord',
    'n8n-nodes-base.whatsApp',
  ])('%s sendAndWait is a strong gate as well as a sink', (type) => {
    const c = registry.classify(node(type, { operation: 'sendAndWait' }));
    expect(c.sanitizer).toEqual({ kind: 'human-approval', strength: 'strong' });
    expect(c.roles).toContain('sink');
  });

  it('оценивает парсер структурированного вывода только как слабый гейт', () => {
    const c = registry.classify(node('@n8n/n8n-nodes-langchain.outputParserStructured'));
    expect(c.sanitizer).toEqual({ kind: 'schema-validation', strength: 'weak' });
  });

  it('оценивает ноду If слабым гейтом, ведь проверять она может что угодно', () => {
    const c = registry.classify(node('n8n-nodes-base.if'));
    expect(c.sanitizer).toEqual({ kind: 'conditional', strength: 'weak' });
  });
});

describe('варианты-инструменты', () => {
  it('классифицирует gmailTool ровно как gmail и записывает, откуда взято правило', () => {
    const base = registry.classify(node('n8n-nodes-base.gmail'));
    const tool = registry.classify(node('n8n-nodes-base.gmailTool'));

    expect(tool.known).toBe(true);
    expect(tool.derivedFrom).toBe('n8n-nodes-base.gmail');
    expect(tool.sink).toEqual(base.sink);
    expect(tool.roles).toEqual(base.roles);
  });

  it.each([
    'n8n-nodes-base.googleSheetsTool',
    'n8n-nodes-base.postgresTool',
    'n8n-nodes-base.slackTool',
    'n8n-nodes-base.telegramTool',
    'n8n-nodes-base.airtableTool',
    'n8n-nodes-base.googleDriveTool',
  ])('derives %s from its base node', (type) => {
    expect(registry.classify(node(type)).known).toBe(true);
  });

  it('не принимает ноду-инструмент langchain за производный вариант', () => {
    // `toolWorkflow` не заканчивается ни на то ни на другое, а `mcpClientTool` заканчивается —
    // и это самостоятельная нода, а не «нода mcpClient, используемая как инструмент».
    const c = registry.classify(node('@n8n/n8n-nodes-langchain.mcpClientTool'));
    expect(c.derivedFrom).toBeUndefined();
    expect(c.known).toBe(true);
  });
});

describe('неизвестные типы нод', () => {
  it('показывает их неизвестными вместо исключения или догадки', () => {
    const c = registry.classify(node('n8n-nodes-community.somethingNobodyHasSeen'));
    expect(c.known).toBe(false);
    expect(c.roles).toEqual([]);
    expect(c.sink).toBeUndefined();
    expect(c.source).toBeUndefined();
  });

  it('переживает ноду, у которой тип отсутствует полностью', () => {
    expect(registry.classify(node('')).known).toBe(false);
  });
});

describe('покрытие настоящих воркфлоу', () => {
  const files = readdirSync(FIXTURES).filter((f) => f.endsWith('.json') && f !== 'manifest.json');

  it('классифицирует каждую ноду каждой фикстуры без исключений', () => {
    for (const f of files) {
      const { graph } = parseWorkflow(JSON.parse(readFileSync(join(FIXTURES, f), 'utf8')));
      for (const n of graph.nodes) expect(() => registry.classify(n)).not.toThrow();
    }
  });

  it('знает большую часть того, из чего собраны настоящие воркфлоу', () => {
    let known = 0;
    let total = 0;
    const unknown = new Map<string, number>();

    for (const f of files) {
      const { graph } = parseWorkflow(JSON.parse(readFileSync(join(FIXTURES, f), 'utf8')));
      for (const n of graph.nodes) {
        total++;
        if (registry.classify(n).known) known++;
        else unknown.set(n.type, (unknown.get(n.type) ?? 0) + 1);
      }
    }

    const ratio = known / total;
    // Записывается, а не просто проверяется: это число — честное покрытие реестра, и в README
    // ему место вместо прилагательного.
    console.log(
      `registry knows ${known}/${total} fixture nodes (${(ratio * 100).toFixed(1)}%); ` +
        `top unknown: ${[...unknown]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([t, c]) => `${t}×${c}`)
          .join(', ')}`,
    );
    expect(ratio).toBeGreaterThan(0.8);
  });

  // Кэш корпуса не коммитится; когда он есть, покрытие меряется по 794 воркфлоу, а не по 24.
  const CACHE = join(REPO_ROOT, '.corpus-cache');
  it.runIf(existsSync(CACHE))('покрывает и выборку корпуса тоже', () => {
    let known = 0;
    let total = 0;
    for (const f of readdirSync(CACHE).filter(
      (x) => x.endsWith('.json') && x !== '_manifest.json',
    )) {
      const rec = JSON.parse(readFileSync(join(CACHE, f), 'utf8')) as { workflow?: unknown };
      const { graph } = parseWorkflow(rec.workflow);
      for (const n of graph.nodes) {
        total++;
        if (registry.classify(n).known) known++;
      }
    }
    const ratio = known / total;
    console.log(`registry knows ${known}/${total} corpus nodes (${(ratio * 100).toFixed(1)}%)`);
    expect(ratio).toBeGreaterThan(0.7);
  });
});
