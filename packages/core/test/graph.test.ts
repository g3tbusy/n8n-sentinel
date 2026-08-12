import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseWorkflow } from '../src/parser/parse-workflow.js';
import { WorkflowGraph } from '../src/graph/graph.js';
import { bypassDisabled } from '../src/graph/disabled.js';
import { findPaths, hasCycle, nodesOnCycles, reachableFrom } from '../src/graph/traverse.js';
import type { GraphEdge, GraphNode } from '../src/graph/types.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const FIXTURES = join(REPO_ROOT, 'fixtures', 'real');
const manifest = JSON.parse(readFileSync(join(FIXTURES, 'manifest.json'), 'utf8')) as {
  fixtures: { file: string; name: string; nodeCount: number; features: string[] }[];
};
const load = (file: string): unknown => JSON.parse(readFileSync(join(FIXTURES, file), 'utf8'));

/** Строит граф напрямую, минуя парсер, чтобы тесты обходов сами задавали нужную форму. */
function graphOf(
  nodes: { name: string; disabled?: boolean; type?: string }[],
  edges: { from: string; to: string; kind?: GraphEdge['kind'] }[],
): WorkflowGraph {
  const graphNodes: GraphNode[] = nodes.map((n) => ({
    name: n.name,
    type: n.type ?? 'n8n-nodes-base.noOp',
    typeVersion: 1,
    disabled: n.disabled === true,
    parameters: {},
    credentials: {},
    hasPinnedData: false,
    raw: { name: n.name },
  }));
  const graphEdges: GraphEdge[] = edges.map((e) => ({
    from: e.from,
    to: e.to,
    kind: e.kind ?? 'data',
    connectionType: e.kind === undefined || e.kind === 'data' ? 'main' : 'ai_tool',
    slot: 0,
    index: 0,
    derived: false,
  }));
  return new WorkflowGraph('test', graphNodes, graphEdges);
}

const names = (paths: GraphEdge[][], start: string): string[] =>
  paths.map((p) => [start, ...p.map((e) => e.to)].join(' → '));

describe('reachableFrom', () => {
  it('идёт вперёд транзитивно', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'B' }, { name: 'C' }, { name: 'D' }],
      [
        { from: 'A', to: 'B' },
        { from: 'B', to: 'C' },
      ],
    );
    expect([...reachableFrom(g, 'A')].sort()).toEqual(['B', 'C']);
    expect([...reachableFrom(g, 'D')]).toEqual([]);
  });

  it('идёт назад, когда попросили', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'B' }, { name: 'C' }],
      [
        { from: 'A', to: 'B' },
        { from: 'B', to: 'C' },
      ],
    );
    expect([...reachableFrom(g, 'C', { backwards: true })].sort()).toEqual(['A', 'B']);
  });

  it('идёт только по запрошенным видам рёбер', () => {
    const g = graphOf(
      [{ name: 'Agent' }, { name: 'Tool' }, { name: 'Model' }],
      [
        { from: 'Agent', to: 'Tool', kind: 'invocation' },
        { from: 'Model', to: 'Agent', kind: 'attachment' },
      ],
    );
    expect([...reachableFrom(g, 'Agent', { kinds: ['invocation'] })]).toEqual(['Tool']);
    expect([...reachableFrom(g, 'Agent', { kinds: ['data'] })]).toEqual([]);
  });

  it('возвращает пустое множество для ноды, которой нет в графе', () => {
    expect([...reachableFrom(graphOf([{ name: 'A' }], []), 'nope')]).toEqual([]);
  });

  it('завершается на цикле и сообщает, что старт достижим из самого себя', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'B' }],
      [
        { from: 'A', to: 'B' },
        { from: 'B', to: 'A' },
      ],
    );
    expect([...reachableFrom(g, 'A')].sort()).toEqual(['A', 'B']);
  });

  it('завершается на петле в себя', () => {
    const g = graphOf([{ name: 'Loop' }], [{ from: 'Loop', to: 'Loop' }]);
    expect([...reachableFrom(g, 'Loop')]).toEqual(['Loop']);
  });
});

describe('findPaths', () => {
  it('возвращает полную трассу рёбер, а не только концы', () => {
    const g = graphOf(
      [{ name: 'Webhook' }, { name: 'Agent' }, { name: 'Send' }],
      [
        { from: 'Webhook', to: 'Agent' },
        { from: 'Agent', to: 'Send' },
      ],
    );
    const paths = findPaths(g, 'Webhook', (n) => n === 'Send');
    expect(names(paths, 'Webhook')).toEqual(['Webhook → Agent → Send']);
  });

  it('находит каждый отдельный маршрут, когда граф ветвится', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'L' }, { name: 'R' }, { name: 'Z' }],
      [
        { from: 'A', to: 'L' },
        { from: 'A', to: 'R' },
        { from: 'L', to: 'Z' },
        { from: 'R', to: 'Z' },
      ],
    );
    expect(
      names(
        findPaths(g, 'A', (n) => n === 'Z'),
        'A',
      ).sort(),
    ).toEqual(['A → L → Z', 'A → R → Z']);
  });

  it('не зацикливается, когда цель стоит за циклом', () => {
    // Loop Over Items кормит сам себя и потом продолжает в sink — форма, на которой зависает
    // наивный поиск путей.
    const g = graphOf(
      [{ name: 'Trigger' }, { name: 'Loop' }, { name: 'Send' }],
      [
        { from: 'Trigger', to: 'Loop' },
        { from: 'Loop', to: 'Loop' },
        { from: 'Loop', to: 'Send' },
      ],
    );
    expect(
      names(
        findPaths(g, 'Trigger', (n) => n === 'Send'),
        'Trigger',
      ),
    ).toEqual(['Trigger → Loop → Send']);
  });

  it('соблюдает лимит путей при комбинаторном ветвлении', () => {
    // Пять ромбов подряд: 2^5 = 32 различных маршрута.
    const nodes = [{ name: 'S' }, { name: 'E' }];
    const edges: { from: string; to: string }[] = [];
    let prev = 'S';
    for (let i = 0; i < 5; i++) {
      const a = `a${i}`;
      const b = `b${i}`;
      const j = `j${i}`;
      nodes.push({ name: a }, { name: b }, { name: j });
      edges.push(
        { from: prev, to: a },
        { from: prev, to: b },
        { from: a, to: j },
        { from: b, to: j },
      );
      prev = j;
    }
    edges.push({ from: prev, to: 'E' });

    const g = graphOf(nodes, edges);
    expect(findPaths(g, 'S', (n) => n === 'E')).toHaveLength(32);
    expect(findPaths(g, 'S', (n) => n === 'E', { limit: 5 })).toHaveLength(5);
  });

  it('останавливается на первой цели, а не показывает более длинные маршруты сквозь неё', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'Sink1' }, { name: 'Sink2' }],
      [
        { from: 'A', to: 'Sink1' },
        { from: 'Sink1', to: 'Sink2' },
      ],
    );
    const isSink = (n: string): boolean => n.startsWith('Sink');
    expect(names(findPaths(g, 'A', isSink), 'A')).toEqual(['A → Sink1']);
  });
});

describe('обнаружение циклов', () => {
  it('находит ноды на петле и не трогает остальные', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'B' }, { name: 'C' }, { name: 'Tail' }],
      [
        { from: 'A', to: 'B' },
        { from: 'B', to: 'C' },
        { from: 'C', to: 'A' },
        { from: 'C', to: 'Tail' },
      ],
    );
    expect(hasCycle(g)).toBe(true);
    expect([...nodesOnCycles(g)].sort()).toEqual(['A', 'B', 'C']);
  });

  it('не сообщает о цикле для простой цепочки', () => {
    const g = graphOf([{ name: 'A' }, { name: 'B' }], [{ from: 'A', to: 'B' }]);
    expect(hasCycle(g)).toBe(false);
  });
});

describe('bypassDisabled', () => {
  it('вырезает выключенную ноду и перекидывает связи в обход', () => {
    // n8n выполняет это как Webhook → Send: выключенная нода пропускает данные насквозь.
    const g = graphOf(
      [{ name: 'Webhook' }, { name: 'Set', disabled: true }, { name: 'Send' }],
      [
        { from: 'Webhook', to: 'Set' },
        { from: 'Set', to: 'Send' },
      ],
    );
    const live = bypassDisabled(g);

    expect(live.has('Set')).toBe(false);
    expect(live.edges).toHaveLength(1);
    expect(live.edges[0]).toMatchObject({ from: 'Webhook', to: 'Send', derived: true });
  });

  it('перекидывает через цепочку подряд идущих выключенных нод', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'X', disabled: true }, { name: 'Y', disabled: true }, { name: 'B' }],
      [
        { from: 'A', to: 'X' },
        { from: 'X', to: 'Y' },
        { from: 'Y', to: 'B' },
      ],
    );
    const live = bypassDisabled(g);
    expect(live.edges).toHaveLength(1);
    expect(live.edges[0]).toMatchObject({ from: 'A', to: 'B' });
  });

  it('завершается, когда выключенные ноды образуют петлю', () => {
    const g = graphOf(
      [{ name: 'A' }, { name: 'X', disabled: true }, { name: 'Y', disabled: true }],
      [
        { from: 'A', to: 'X' },
        { from: 'X', to: 'Y' },
        { from: 'Y', to: 'X' },
      ],
    );
    const live = bypassDisabled(g);
    expect(live.size).toBe(1);
    expect(live.edges).toHaveLength(0);
  });

  it('выбрасывает выключенный инструмент, а не пропускает сквозь него', () => {
    // У агента, чей инструмент выключен, этого инструмента нет — передавать нечего, в отличие
    // от выключенной ноды посреди цепочки данных.
    const g = graphOf(
      [{ name: 'Agent' }, { name: 'Tool', disabled: true }],
      [
        { from: 'Tool', to: 'Agent', kind: 'return' },
        { from: 'Agent', to: 'Tool', kind: 'invocation' },
      ],
    );
    const live = bypassDisabled(g);
    expect(live.size).toBe(1);
    expect(live.edges).toHaveLength(0);
  });

  it('возвращает тот же граф, когда ничего не выключено', () => {
    const g = graphOf([{ name: 'A' }, { name: 'B' }], [{ from: 'A', to: 'B' }]);
    expect(bypassDisabled(g)).toBe(g);
  });
});

// DoD фазы 1: корректный граф на каждой фикстуре. Эти тесты гоняют парсер по настоящему
// корпусу, а не по формам, подобранным так, чтобы парсер хорошо выглядел.
describe('каждая настоящая фикстура', () => {
  const parsed = manifest.fixtures.map((f) => ({ meta: f, result: parseWorkflow(load(f.file)) }));

  it.each(parsed)('строит граф для $meta.file', ({ meta, result }) => {
    // Стикеры тоже ноды, поэтому число нод должно точно совпадать с документом — кроме тех
    // мест, где задокументированный дефект не даёт ноду выбросить.
    expect(result.graph.size).toBe(meta.nodeCount);
    expect(result.graph.nodes.every((n) => n.name.length > 0)).toBe(true);
  });

  it('никогда не даёт ребра к ноде, которой нет в графе, или от неё', () => {
    for (const { meta, result } of parsed) {
      for (const e of result.graph.edges) {
        expect(result.graph.has(e.from), `${meta.file}: edge from ${e.from}`).toBe(true);
        expect(result.graph.has(e.to), `${meta.file}: edge to ${e.to}`).toBe(true);
      }
    }
  });

  it('даёт рёбра для всех, кроме единственной фикстуры с неразбираемыми связями', () => {
    const edgeless = parsed.filter((p) => p.result.graph.edges.length === 0);
    expect(edgeless.map((p) => p.meta.file)).toEqual([
      '06686-track-expenses-from-receipt-photos-with-telegram.json',
    ]);
  });

  it('предупреждает только там, где есть задокументированный дефект', () => {
    const noisy = parsed.filter((p) => p.result.warnings.length > 0).map((p) => p.meta.file);
    expect(noisy.sort()).toEqual([
      '04600-ai-content-generation-for-auto-service-automate-.json',
      '05805-create-youtube-shorts-scripts-from-video-links-w.json',
      '06686-track-expenses-from-receipt-photos-with-telegram.json',
    ]);
  });

  it('выводит ребро invocation везде, где инструмент подключён к агенту', () => {
    for (const { meta, result } of parsed) {
      if (!meta.features.includes('conn:ai_tool')) continue;
      const returns = result.graph.edges.filter((e) => e.kind === 'return');
      const invocations = result.graph.edges.filter((e) => e.kind === 'invocation');
      expect(invocations, `${meta.file}`).toHaveLength(returns.length);
      expect(invocations.length).toBeGreaterThan(0);
    }
  });

  it('обходит фикстуру из 244 нод не зависая', () => {
    const big = parsed.find((p) => p.meta.nodeCount === 244);
    expect(big).toBeDefined();
    const graph = big!.result.graph;

    const started = performance.now();
    for (const node of graph.nodes) reachableFrom(graph, node.name);
    hasCycle(graph);
    const elapsed = performance.now() - started;

    expect(elapsed).toBeLessThan(2000);
  });

  it('находит циклы ровно в тех фикстурах, которые манифест пометил цикличными', () => {
    for (const { meta, result } of parsed) {
      const expected = meta.features.includes('struct:cycle');
      // Манифест смотрел только на рёбра main; ограничиваем проверку так же.
      expect(hasCycle(result.graph, { kinds: ['data'] }), meta.file).toBe(expected);
    }
  });
});
