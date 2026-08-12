import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { AI_CONNECTION_TYPES, isAiConnectionType, MAIN_CONNECTION } from '../src/n8n-format.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const FIXTURES = join(REPO_ROOT, 'fixtures', 'real');

interface Manifest {
  fixtureCount: number;
  distinctNodeTypes: number;
  featuresCovered: string[];
  featuresUncovered: string[];
  fixtures: {
    file: string;
    templateId: number;
    name: string;
    nodeCount: number;
    features: string[];
  }[];
}

const manifest = JSON.parse(readFileSync(join(FIXTURES, 'manifest.json'), 'utf8')) as Manifest;

const readFixture = (file: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, file), 'utf8')) as Record<string, unknown>;

describe('корпус фикстур', () => {
  it('содержит все файлы, заявленные манифестом, и ничего протухшего', () => {
    const onDisk = readdirSync(FIXTURES)
      .filter((f) => f.endsWith('.json') && f !== 'manifest.json')
      .sort();
    const claimed = manifest.fixtures.map((f) => f.file).sort();
    expect(onDisk).toEqual(claimed);
  });

  it('держит минимум 20 настоящих воркфлоу, как требует фаза 0', () => {
    expect(manifest.fixtures.length).toBeGreaterThanOrEqual(20);
  });

  it('разбирает каждую фикстуру в воркфлоу с нодами', () => {
    for (const f of manifest.fixtures) {
      const wf = readFixture(f.file);
      expect(Array.isArray(wf.nodes), `${f.file} has a nodes array`).toBe(true);
      expect((wf.nodes as unknown[]).length, `${f.file} is non-empty`).toBeGreaterThan(0);
    }
  });

  it('покрывает каждый признак, который предложил корпус', () => {
    expect(manifest.featuresUncovered).toEqual([]);
  });
});

describe('покрытие типов связей', () => {
  // Фаза 1 обязана справляться с каждым из них; если набор фикстур однажды потеряет один,
  // парсер продолжит проходить свои тесты, молча оставаясь непроверенным.
  const required = [MAIN_CONNECTION, ...AI_CONNECTION_TYPES];

  it.each(required)('задействует тип связи %s', (type) => {
    expect(manifest.featuresCovered).toContain(`conn:${type}`);
  });

  it('даёт достаточно типов нод для реестра фазы 2', () => {
    expect(manifest.distinctNodeTypes).toBeGreaterThanOrEqual(40);
  });
});

describe('структурные краевые случаи представлены', () => {
  const required = [
    'struct:cycle',
    'struct:disconnectedNode',
    'struct:disabledNode',
    'struct:pinData',
    'struct:multiOutput',
    'struct:selfLoop',
    'struct:danglingTarget',
    'struct:nonNameConnectionKey',
    'boundary:executeWorkflow',
    'boundary:toolWorkflow',
    'gate:sendAndWait',
    'expr:$json',
    "expr:$('Node')",
  ];

  it.each(required)('имеет фикстуру с %s', (tag) => {
    expect(manifest.featuresCovered).toContain(tag);
  });
});

describe('isAiConnectionType', () => {
  it.each(AI_CONNECTION_TYPES)('узнаёт %s', (type) => {
    expect(isAiConnectionType(type)).toBe(true);
  });

  it('узнаёт типы ai_*, которых не существовало на момент написания', () => {
    expect(isAiConnectionType('ai_somethingNewIn2027')).toBe(true);
  });

  it('не считает main и произвольные строки AI-связями', () => {
    expect(isAiConnectionType('main')).toBe(false);
    expect(isAiConnectionType('output')).toBe(false);
    expect(isAiConnectionType('')).toBe(false);
  });
});

// Документация формата делает конкретные утверждения о конкретных файлах. Эти тесты
// существуют, чтобы утверждения не протухли: если фикстуру перегенерируют и доказательство
// уедет, docs/n8n-json-format.md станет неверным, и CI об этом скажет.
describe('задокументированные утверждения о формате (docs/n8n-json-format.md)', () => {
  it('§2 ключует connections по имени ноды, а не по id', () => {
    const wf = readFixture('04722-gmail-ai-email-manager.json');
    const nodes = wf.nodes as { id?: string; name?: string }[];
    const names = new Set(nodes.map((n) => n.name));
    const ids = new Set(nodes.map((n) => n.id));
    const keys = Object.keys(wf.connections as object);

    expect(keys.length).toBeGreaterThan(0);
    expect(keys.every((k) => names.has(k))).toBe(true);
    expect(keys.some((k) => ids.has(k))).toBe(false);
  });

  it('§5 хранит рёбра ai_* от sub-ноды к агенту — обратно потоку данных', () => {
    const wf = readFixture('05819-build-an-interactive-ai-agent-with-chat-interfac.json');
    const nodes = wf.nodes as { name: string; type: string }[];
    const typeOf = new Map(nodes.map((n) => [n.name, n.type]));
    const conns = wf.connections as Record<string, Record<string, unknown>>;

    const toolEdges: { from: string; to: string }[] = [];
    for (const [source, byType] of Object.entries(conns)) {
      for (const [ctype, slots] of Object.entries(byType)) {
        if (ctype !== 'ai_tool') continue;
        for (const slot of slots as unknown[]) {
          for (const endpoint of slot as { node: string }[]) {
            toolEdges.push({ from: source, to: endpoint.node });
          }
        }
      }
    }

    expect(toolEdges.length).toBeGreaterThan(0);
    // Каждое ребро ai_tool указывает НА агента: агент — цель, и никогда не источник.
    for (const e of toolEdges) {
      expect(typeOf.get(e.to)).toBe('@n8n/n8n-nodes-langchain.agent');
      expect(typeOf.get(e.from)).not.toBe('@n8n/n8n-nodes-langchain.agent');
    }
  });

  it('§6.1 содержит ключ связи, не соответствующий ни одной ноде (мохибейк)', () => {
    const wf = readFixture('04600-ai-content-generation-for-auto-service-automate-.json');
    const names = new Set((wf.nodes as { name: string }[]).map((n) => n.name));
    const orphanKeys = Object.keys(wf.connections as object).filter((k) => !names.has(k));

    expect(orphanKeys).toContain(
      'When clicking \u0432\u0402\u0098Execute workflow\u0432\u0402\u2122',
    );
    expect(names).toContain('When clicking Execute workflow');
  });

  it('§6.2 содержит связь, целящуюся в удалённую ноду', () => {
    const wf = readFixture('05805-create-youtube-shorts-scripts-from-video-links-w.json');
    const names = new Set((wf.nodes as { name: string }[]).map((n) => n.name));
    const conns = wf.connections as Record<string, Record<string, unknown>>;

    const dangling = new Set<string>();
    for (const byType of Object.values(conns)) {
      for (const slots of Object.values(byType)) {
        for (const slot of (slots as unknown[]) ?? []) {
          for (const endpoint of (slot as { node?: string }[]) ?? []) {
            if (endpoint?.node && !names.has(endpoint.node)) dangling.add(endpoint.node);
          }
        }
      }
    }
    expect([...dangling]).toContain('Edit Fields');
  });

  it('§6.3 содержит воркфлоу, чьи слоты не являются массивами слотов', () => {
    const wf = readFixture('06686-track-expenses-from-receipt-photos-with-telegram.json');
    const conns = wf.connections as Record<string, Record<string, unknown>>;

    const block = conns['Telegram Bot (Webhook)'];
    expect(block).toBeDefined();
    expect(Object.keys(block!)).toContain('output');

    const slots = block!.output as unknown[];
    expect(Array.isArray(slots)).toBe(true);
    // Корректный документ вложен на уровень глубже: slots[0] сам был бы массивом.
    expect(Array.isArray(slots[0])).toBe(false);
    expect(slots[0]).toHaveProperty('node');
  });
});
