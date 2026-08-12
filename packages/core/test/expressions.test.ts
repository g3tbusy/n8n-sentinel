import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  findExpressions,
  isExpression,
  parseExpression,
  readString,
} from '../src/expressions/parse.js';
import { dangerousConstructs, urlControl } from '../src/expressions/position.js';
import { loadSensitiveParams } from '../src/rules/load.js';
import { defaultRules } from '../src/rules/default-rules.js';
import type { NodeDefaults, RuleFile } from '../src/rules/types.js';
import { parse as parseYaml } from 'yaml';

const CORE = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = defaultRules();

const kinds = (raw: string): string[] => parseExpression(raw).refs.map((r) => r.kind);

describe('распознавание выражения', () => {
  it('понимает ведущий `=` так же, как n8n', () => {
    expect(isExpression('={{ $json.x }}')).toBe(true);
    expect(isExpression('https://example.com/{{ notAnExpression }}')).toBe(false);
    expect(isExpression('plain text')).toBe(false);
    expect(isExpression(42)).toBe(false);
  });

  it('делает одно исключение — для значения, которое пишет модель', () => {
    // В библиотеке 189 параметров `query` несут `{{ }}` без `=`; 17 из них читают
    // `{{ $fromAI(…) }}`. Строго говоря, это литеральный текст, но `$fromAI` как литеральный
    // текст бессмыслен, а находка, которую это скрывает, — худшая из существующих.
    expect(isExpression("{{ $fromAI('sql_query') }}")).toBe(true);
    expect(kinds("{{ $fromAI('sql_query') }}")).toContain('fromAI');
  });
});

describe('поиск подстановок', () => {
  it('считает скобки вместо ленивого сопоставления', () => {
    // Ленивое `.*?\}\}` заканчивает это выражение прямо внутри литерала объекта.
    const parsed = parseExpression('={{ $json.items.map(i => ({ id: i.id })) }}');
    expect(parsed.interpolations).toHaveLength(1);
    expect(parsed.interpolations[0]?.text).toBe(' $json.items.map(i => ({ id: i.id })) ');
  });

  it('перешагивает скобки внутри строк в кавычках', () => {
    const parsed = parseExpression('={{ $json.a + "}}" }}');
    expect(parsed.interpolations).toHaveLength(1);
  });

  it('записывает то, что стоит перед каждой подстановкой', () => {
    const parsed = parseExpression('=https://api.example.com/v1/{{ $json.id }}/detail');
    expect(parsed.interpolations[0]?.before).toBe('https://api.example.com/v1/');
  });

  it('переживает выражение с несошедшимися скобками не зависая', () => {
    expect(() => parseExpression('={{ $json.x')).not.toThrow();
    expect(parseExpression('={{ $json.x').interpolations).toEqual([]);
  });
});

describe('что читает выражение', () => {
  it.each([
    ['={{ $json.a }}', 'json'],
    ['={{ $input.first().json.a }}', 'json'],
    ['={{ $env.API_KEY }}', 'env'],
    ['={{ $vars.region }}', 'vars'],
    ['={{ $secrets.vault.key }}', 'secrets'],
    ['={{ $now.toISO() }}', 'runtime'],
    ["={{ $fromAI('email') }}", 'fromAI'],
  ])('читает %s как %s', (raw, kind) => {
    expect(kinds(raw)).toContain(kind);
  });

  it.each([
    ["={{ $('Webhook').item.json.body }}", 'Webhook'],
    ['={{ $node["Webhook"].json.body }}', 'Webhook'],
    ['={{ $items("Webhook")[0].json.body }}', 'Webhook'],
  ])('называет ноду в %s', (raw, node) => {
    const ref = parseExpression(raw).refs.find((r) => r.kind === 'node');
    expect(ref?.node).toBe(node);
  });

  it('записывает единственное поле, которое читает ссылка', () => {
    // Именно это отличает захардкоженный базовый URL в ноде Set от тела запроса, лежащего
    // рядом в выводе той же ноды.
    expect(parseExpression("={{ $('Config').json.BASE_URL }}").refs[0]?.field).toBe('BASE_URL');
    expect(parseExpression('={{ $node["Config"].json["BASE_URL"] }}').refs[0]?.field).toBe(
      'BASE_URL',
    );
    expect(parseExpression("={{ $('Config').item.json.BASE_URL }}").refs[0]?.field).toBe(
      'BASE_URL',
    );
    expect(parseExpression("={{ $('Config').all() }}").refs[0]?.field).toBeUndefined();
  });

  it('оставляет вычисляемое имя ноды безымянным, а не гадает', () => {
    const ref = parseExpression("={{ $('Step ' + $json.n).json.x }}").refs.find(
      (r) => r.kind === 'node',
    );
    expect(ref?.node).toBeUndefined();
  });
});

describe('какую часть URL решает выражение', () => {
  it.each([
    ['={{ $json.url }}', 'full'],
    ['={{ $json.protocol }}://example.com/x', 'full'],
    ['=https://{{ $json.host }}/x', 'host'],
    ['=https://api.example.com/v1/{{ $json.id }}', 'path'],
    ['=https://api.example.com/v1?q={{ $json.q }}', 'query'],
    ['=https://api.example.com/v1/fixed', 'none'],
  ])('%s → %s', (raw, expected) => {
    expect(urlControl(parseExpression(raw))).toBe(expected);
  });

  it('видит хост, склеенный внутри скобок', () => {
    // Если читать только то, что стоит перед `{{`, это назовут свободным выбором хоста. Всё
    // наоборот: хост — литерал, на один символ дальше внутрь.
    expect(urlControl(parseExpression("={{ 'https://api.example.com/v1/' + $json.id }}"))).toBe(
      'path',
    );
  });
});

describe('обход объекта параметров ноды', () => {
  it('добирается до выражений, вложенных через массивы', () => {
    const found = findExpressions({
      url: '=https://x/{{ $json.a }}',
      headerParameters: { parameters: [{ name: 'X', value: '={{ $json.b }}' }] },
      method: 'POST',
    });
    expect(found.map((f) => f.path).sort()).toEqual(['headerParameters.parameters[].value', 'url']);
  });

  it('читает обычную строку обратно по пути', () => {
    expect(readString({ jsCode: 'return items' }, 'jsCode')).toBe('return items');
    expect(readString({ a: { b: 'c' } }, 'a.b')).toBe('c');
    expect(readString({}, 'missing')).toBeUndefined();
  });
});

describe('конструкции, превращающие строку в выполнение', () => {
  it('замечает те, которые стоит заметить', () => {
    expect(dangerousConstructs('const f = new Function(src); f()')).toContain('new Function(');
    expect(dangerousConstructs("require('child_process').execSync(cmd)")).toContain(
      'child_process',
    );
  });

  it('молчит об обычном коде', () => {
    expect(dangerousConstructs('return $input.all().map((i) => i.json)')).toEqual([]);
  });
});

// Та же гарантия, что и у nodes.yaml: правило, называющее то, чего у n8n нет, — мёртвый код,
// выглядящий покрытием.
describe('целостность sensitive-params.yaml', () => {
  const file = loadSensitiveParams(
    readFileSync(join(CORE, 'rules', 'sensitive-params.yaml'), 'utf8'),
  );
  const defaults = JSON.parse(
    readFileSync(join(CORE, 'rules', 'node-defaults.json'), 'utf8'),
  ) as NodeDefaults;
  const nodeRules = parseYaml(readFileSync(join(CORE, 'rules', 'nodes.yaml'), 'utf8')) as RuleFile;
  const classified = new Set(nodeRules.nodes.map((n) => n.type));

  it('называет только существующие типы нод', () => {
    const unknown = rules.sensitiveParams
      .types()
      // `executeCommand` есть в реестре, но нет в каталоге: свежие образы n8n приходят без
      // него, хотя воркфлоу на него ссылаются. Существующим считается любой из двух источников.
      .filter((type) => defaults.nodes[type] === undefined && !classified.has(type));
    expect(unknown).toEqual([]);
  });

  it('не объявляет параметр дважды с двумя значениями', () => {
    for (const type of rules.sensitiveParams.types()) {
      const seen = new Map<string, string>();
      for (const rule of file.params) {
        if (!rule.types.includes(type)) continue;
        for (const path of rule.paths) {
          const previous = seen.get(path);
          expect(previous ?? rule.kind, `${type} ${path}`).toBe(rule.kind);
          seen.set(path, rule.kind);
        }
      }
    }
  });

  it('не считает поисковую строку SQL-запросом', () => {
    // Шесть параметров `query` в корпусе принадлежат поисковым инструментам. Правило,
    // ключуемое по одному имени параметра, показало бы каждый из них как SQL-инъекцию.
    expect(rules.sensitiveParams.kindOf('n8n-nodes-base.postgres', 'query')).toBe('sql');
    expect(rules.sensitiveParams.kindOf('@tavily/n8n-nodes-tavily.tavilyTool', 'query')).toBe(
      undefined,
    );
  });
});
