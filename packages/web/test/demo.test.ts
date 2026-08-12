import { describe, expect, it } from 'vitest';
import { analyseWorkflow } from '@n8n-sentinel/core/browser';
import { DEMOS } from '../src/demo.js';
import { buildModel, edgeKey, routeCount } from '../src/model.js';
import { bundledRules } from '../src/rules.js';

/**
 * Примеры и есть аргумент.
 *
 * Каждый лежит в списке, потому что показывает нечто конкретное, и подпись под ним говорит
 * что именно. Если фикстуру подменят или анализ передумает, падают эти тесты, а не страница
 * тихо утверждает то, что уже неправда.
 */

const analyse = (json: string) => analyseWorkflow(JSON.parse(json), bundledRules());
const demo = (id: string) => {
  const found = DEMOS.find((item) => item.id === id);
  if (found === undefined) throw new Error(`no demo ${id}`);
  return found;
};

describe('примеры', () => {
  it('все разбираются и анализируются', () => {
    for (const item of DEMOS) {
      const result = analyse(item.json);
      expect(result.graph.nodes.length, item.id).toBeGreaterThan(0);
    }
  });

  it('открываются на каноническом случае: письмо доходит до инструмента, который шлёт письма', () => {
    expect(DEMOS[0]?.id).toBe('04057');
    const model = buildModel(analyse(demo('04057').json));
    const worst = model.findings[0]?.finding;

    expect(worst?.rule).toBe('INDIRECT_PROMPT_INJECTION');
    expect(worst?.severity).toBe('critical');
    expect(worst?.agent).toBeDefined();
    // Путь заканчивается на инструменте, который вызывает агент, и добирается туда по ребру,
    // которого на холсте n8n не нарисовано. Этот выведенный шаг и есть причина существования
    // находки.
    expect(worst?.trace.some((step) => step.derived)).toBe(true);
  });

  it('включают случай, где на пути стоит человек, и он не critical', () => {
    const model = buildModel(analyse(demo('13216').json));
    expect(model.counts.critical).toBe(0);
  });

  it('включают документ, который n8n сам отказывается импортировать, и переживают его', () => {
    const result = analyse(demo('05805').json);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.graph.nodes.length).toBeGreaterThan(0);
  });

  it('включают агента со множеством инструментов: находка на действие, а не на маршрут', () => {
    const model = buildModel(analyse(demo('14008').json));
    const injections = model.findings.filter(
      (view) => view.finding.rule === 'INDIRECT_PROMPT_INJECTION',
    );
    const sinks = new Set(injections.map((view) => view.finding.sink.node));
    expect(injections.length).toBe(sinks.size);
  });
});

describe('модель за страницей', () => {
  const model = buildModel(analyse(demo('04057').json));

  it('ставит худшую находку первой', () => {
    const ranks = model.findings.map((view) => view.finding.severity);
    expect(ranks).toEqual([...ranks].sort((a, b) => order(a) - order(b)));
  });

  it('ключует каждый шаг трассы так же, как нарисованный граф ключует свои рёбра', () => {
    const drawn = new Set(model.result.graph.edges.map(edgeKey));
    for (const view of model.findings) {
      for (const key of view.edges) expect(drawn.has(key), key).toBe(true);
    }
  });

  it('вешает значки на оба конца пути и ни на что между ними', () => {
    const worst = model.findings[0];
    expect(worst).toBeDefined();
    if (worst === undefined) return;
    expect(model.worstByNode.get(worst.finding.source.node)).toBe(worst.finding.severity);
    expect(model.worstByNode.get(worst.finding.sink.node)).toBe(worst.finding.severity);
    const middle = [...worst.nodes].filter(
      (name) => name !== worst.finding.source.node && name !== worst.finding.sink.node,
    );
    for (const name of middle) expect(model.worstByNode.has(name)).toBe(false);
  });

  it('считает маршруты, не перебирая агента до смерти', () => {
    const worst = model.findings[0]?.finding;
    expect(worst).toBeDefined();
    if (worst === undefined) return;
    expect(routeCount(model.result.graph, worst)).toBeGreaterThanOrEqual(1);
    expect(routeCount(model.result.graph, worst)).toBeLessThanOrEqual(4);
  });
});

const order = (severity: string): number => ['critical', 'high', 'medium', 'low'].indexOf(severity);
