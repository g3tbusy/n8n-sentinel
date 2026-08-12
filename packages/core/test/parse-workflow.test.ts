import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseWorkflow } from '../src/parser/parse-workflow.js';
import type { GraphEdge } from '../src/graph/types.js';

const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  'fixtures',
  'real',
);
const fixture = (file: string): unknown => JSON.parse(readFileSync(join(FIXTURES, file), 'utf8'));

/** Минимальный корректный воркфлоу, чтобы каждый тест говорил только о своём. */
function wf(
  nodes: { name: string; type?: string; disabled?: boolean }[],
  connections: Record<string, Record<string, unknown>>,
  extra: Record<string, unknown> = {},
): unknown {
  return {
    name: 'test',
    nodes: nodes.map((n, i) => ({
      id: `id-${i}`,
      name: n.name,
      type: n.type ?? 'n8n-nodes-base.noOp',
      typeVersion: 1,
      position: [0, 0],
      parameters: {},
      ...(n.disabled === true ? { disabled: true } : {}),
    })),
    connections,
    ...extra,
  };
}

const main = (target: string, slot = 0): Record<string, unknown> => ({
  main: slotsWith(target, slot),
});

function slotsWith(target: string, slot: number): unknown[][] {
  const slots: unknown[][] = [];
  for (let i = 0; i < slot; i++) slots.push([]);
  slots.push([{ node: target, type: 'main', index: 0 }]);
  return slots;
}

const edge = (edges: readonly GraphEdge[], from: string, to: string): GraphEdge | undefined =>
  edges.find((e) => e.from === from && e.to === to);

describe('parseWorkflow — корректный ввод', () => {
  it('строит ноды и ребро main', () => {
    const { graph, warnings } = parseWorkflow(wf([{ name: 'A' }, { name: 'B' }], { A: main('B') }));

    expect(warnings).toEqual([]);
    expect(graph.size).toBe(2);
    expect(graph.node('A')?.type).toBe('n8n-nodes-base.noOp');
    expect(graph.edges).toHaveLength(1);
    expect(graph.edges[0]).toMatchObject({
      from: 'A',
      to: 'B',
      kind: 'data',
      connectionType: 'main',
      slot: 0,
      derived: false,
    });
  });

  it('сохраняет номер слота, чтобы ветки if/switch оставались различимыми', () => {
    const { graph } = parseWorkflow(
      wf([{ name: 'If' }, { name: 'T' }, { name: 'F' }], {
        If: {
          main: [[{ node: 'T', type: 'main', index: 0 }], [{ node: 'F', type: 'main', index: 0 }]],
        },
      }),
    );

    expect(edge(graph.edges, 'If', 'T')?.slot).toBe(0);
    expect(edge(graph.edges, 'If', 'F')?.slot).toBe(1);
  });

  it('считает слот null неиспользуемым выходным портом, а не ошибкой', () => {
    const { graph, warnings } = parseWorkflow(
      wf([{ name: 'A' }, { name: 'B' }], {
        A: { main: [null, [{ node: 'B', type: 'main', index: 0 }]] },
      }),
    );

    expect(warnings).toEqual([]);
    expect(edge(graph.edges, 'A', 'B')?.slot).toBe(1);
  });

  it('записывает pinData и флаги disabled, ничего с ними не делая', () => {
    const { graph } = parseWorkflow(
      wf([{ name: 'A' }, { name: 'B', disabled: true }], { A: main('B') }, { pinData: { A: [] } }),
    );

    expect(graph.node('A')?.hasPinnedData).toBe(true);
    expect(graph.node('B')?.hasPinnedData).toBe(false);
    expect(graph.node('B')?.disabled).toBe(true);
    // По-прежнему на месте и по-прежнему подключено: bypassDisabled — отдельный явный шаг.
    expect(graph.edges).toHaveLength(1);
  });
});

describe('parseWorkflow — нормализация AI-связей (docs §5)', () => {
  const agentWorkflow = wf(
    [
      { name: 'Chat', type: '@n8n/n8n-nodes-langchain.chatTrigger' },
      { name: 'Agent', type: '@n8n/n8n-nodes-langchain.agent' },
      { name: 'Model', type: '@n8n/n8n-nodes-langchain.lmChatOpenAi' },
      { name: 'SendMail', type: 'n8n-nodes-base.gmailTool' },
    ],
    {
      Chat: main('Agent'),
      // Оба хранятся как sub-нода → агент, ровно так, как их пишет n8n.
      Model: { ai_languageModel: [[{ node: 'Agent', type: 'ai_languageModel', index: 0 }]] },
      SendMail: { ai_tool: [[{ node: 'Agent', type: 'ai_tool', index: 0 }]] },
    },
  );

  it('превращает одну хранимую связь ai_tool в два ребра', () => {
    const { graph } = parseWorkflow(agentWorkflow);
    const toolEdges = graph.edges.filter((e) => e.connectionType === 'ai_tool');
    expect(toolEdges).toHaveLength(2);
  });

  it('сохраняет инструмент → агент как ребро return, прочитанное из документа', () => {
    const { graph } = parseWorkflow(agentWorkflow);
    expect(edge(graph.edges, 'SendMail', 'Agent')).toMatchObject({
      kind: 'return',
      derived: false,
    });
  });

  it('выводит агент → инструмент — ребро, по которому идёт prompt injection', () => {
    const { graph } = parseWorkflow(agentWorkflow);
    // Этой стрелки нет ни в одном документе и ни на одном холсте; без неё нет и пути от
    // недоверенного триггера до побочного эффекта, который совершает инструмент.
    expect(edge(graph.edges, 'Agent', 'SendMail')).toMatchObject({
      kind: 'invocation',
      derived: true,
    });
  });

  it('оставляет остальные связи ai_* указывающими на родителя', () => {
    const { graph } = parseWorkflow(agentWorkflow);
    expect(edge(graph.edges, 'Model', 'Agent')).toMatchObject({
      kind: 'attachment',
      derived: false,
    });
    expect(edge(graph.edges, 'Agent', 'Model')).toBeUndefined();
  });

  it('справляется с типами ai_*, придуманными после написания этого кода', () => {
    const { graph, warnings } = parseWorkflow(
      wf([{ name: 'Sub' }, { name: 'Parent' }], {
        Sub: { ai_somethingNew: [[{ node: 'Parent', type: 'ai_somethingNew', index: 0 }]] },
      }),
    );

    expect(warnings).toEqual([]);
    expect(edge(graph.edges, 'Sub', 'Parent')?.kind).toBe('attachment');
  });
});

describe('parseWorkflow — кривой ввод никогда не роняет исключение', () => {
  it.each([
    ['null', null],
    ['a string', 'not a workflow'],
    ['a number', 42],
    ['an array', [1, 2, 3]],
    ['an empty object', {}],
    ['nodes as an object', { nodes: {} }],
  ])('survives %s', (_label, input) => {
    const result = parseWorkflow(input);
    expect(result.graph.size).toBe(0);
    expect(result.warnings.some((w) => w.code === 'not_a_workflow')).toBe(true);
  });

  it('выбрасывает ноды, на которые нельзя сослаться, и говорит об этом', () => {
    const { graph, warnings } = parseWorkflow({
      nodes: [{ id: '1', type: 'n8n-nodes-base.noOp' }, 'garbage', null],
      connections: {},
    });

    expect(graph.size).toBe(0);
    expect(warnings.filter((w) => w.code === 'node_without_name')).toHaveLength(3);
  });

  it('оставляет первую из двух нод с одинаковым именем', () => {
    const { graph, warnings } = parseWorkflow(
      wf(
        [
          { name: 'A', type: 'first' },
          { name: 'A', type: 'second' },
        ],
        {},
      ),
    );

    expect(graph.size).toBe(1);
    expect(graph.node('A')?.type).toBe('first');
    expect(warnings.some((w) => w.code === 'duplicate_node_name')).toBe(true);
  });

  it('помечает ноду без типа, но оставляет её в графе', () => {
    const { graph, warnings } = parseWorkflow({
      nodes: [{ name: 'A' }],
      connections: {},
    });

    expect(graph.size).toBe(1);
    expect(graph.node('A')?.type).toBe('');
    expect(warnings.some((w) => w.code === 'node_without_type')).toBe(true);
  });

  it('считает неизвестный тип связи потоком данных и предупреждает', () => {
    const { graph, warnings } = parseWorkflow(
      wf([{ name: 'A' }, { name: 'B' }], {
        A: { output: [[{ node: 'B', type: 'main', index: 0 }]] },
      }),
    );

    expect(edge(graph.edges, 'A', 'B')?.kind).toBe('data');
    expect(warnings.some((w) => w.code === 'unknown_connection_type')).toBe(true);
  });
});

// Все четыре дефекта, описанные в docs §6, живут в настоящих фикстурах. Каждый обязан давать
// конкретное предупреждение и пригодный граф — не исключение и не молчаливую пустоту.
describe('parseWorkflow — настоящие дефекты из docs §6', () => {
  it('§6.1 сообщает о мохибейк-ключе связи и разбирает остальное', () => {
    const { graph, warnings } = parseWorkflow(
      fixture('04600-ai-content-generation-for-auto-service-automate-.json'),
    );

    const unknownSource = warnings.filter((w) => w.code === 'unknown_connection_source');
    expect(unknownSource).toHaveLength(1);
    // Расписано словами, потому что две кодовые точки не отображаются: ключ — это байты UTF-8
    // символов ‘ и ’, прочитанные как cp1251, а U+0098 — невидимый управляющий символ.
    expect(unknownSource[0]?.at).toBe(
      'When clicking \u0432\u0402\u0098Execute workflow\u0432\u0402\u2122',
    );

    // Воркфлоу по-прежнему пригоден для анализа: потеряны только связи одной ноды.
    expect(graph.size).toBeGreaterThan(40);
    expect(graph.edges.length).toBeGreaterThan(0);
  });

  it('§6.2 выбрасывает рёбра к удалённой ноде, а не разыменовывает их', () => {
    const { graph, warnings } = parseWorkflow(
      fixture('05805-create-youtube-shorts-scripts-from-video-links-w.json'),
    );

    expect(warnings.some((w) => w.code === 'unknown_connection_target')).toBe(true);
    expect(warnings.some((w) => w.code === 'unknown_connection_source')).toBe(true);
    expect(graph.has('Edit Fields')).toBe(false);
    expect(graph.edges.every((e) => e.from !== 'Edit Fields' && e.to !== 'Edit Fields')).toBe(true);
  });

  it('§6.3 сообщает о слотах неверной формы, не гадая о замысле', () => {
    const { graph, warnings } = parseWorkflow(
      fixture('06686-track-expenses-from-receipt-photos-with-telegram.json'),
    );

    const malformed = warnings.filter((w) => w.code === 'malformed_connections');
    expect(malformed.length).toBeGreaterThan(0);
    expect(malformed[0]?.message).toContain('должен быть массивом концов связи');

    // Ноды выживают; граф просто остаётся без рёбер, и это честный ответ.
    expect(graph.size).toBe(5);
    expect(graph.edges).toHaveLength(0);
  });

  it('§6.4 находит изолированные ноды, игнорируя стикеры', () => {
    const { graph } = parseWorkflow(
      fixture('05819-build-an-interactive-ai-agent-with-chat-interfac.json'),
    );

    const isolated = graph.isolatedNodes();
    expect(isolated.every((n) => n.type !== 'n8n-nodes-base.stickyNote')).toBe(true);
    expect(graph.nodes.some((n) => n.type === 'n8n-nodes-base.stickyNote')).toBe(true);
  });
});
