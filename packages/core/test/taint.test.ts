import { describe, expect, it } from 'vitest';
import { parseWorkflow } from '../src/parser/parse-workflow.js';
import { bypassDisabled } from '../src/graph/disabled.js';
import { defaultRegistry } from '../src/rules/default-rules.js';
import { analyseTaint } from '../src/taint/engine.js';
import type { TaintAnalysis } from '../src/taint/engine.js';
import { endOf, nodesOf } from '../src/taint/types.js';
import { T, workflow } from './build-workflow.js';
import type { Edge, NodeSpec } from './build-workflow.js';

const registry = defaultRegistry();

const taintOf = (nodes: Record<string, string | NodeSpec>, edges: readonly Edge[]): TaintAnalysis =>
  analyseTaint(bypassDisabled(parseWorkflow(workflow(nodes, edges)).graph), registry);

const sendAndWait = { type: T.telegram, parameters: { operation: 'sendAndWait' } };

describe('распространение по видам рёбер', () => {
  it('переносит taint по рёбрам data', () => {
    const taint = taintOf({ Hook: T.webhook, Shape: T.set, Mail: T.emailSend }, [
      ['Hook', 'Shape'],
      ['Shape', 'Mail'],
    ]);
    expect(taint.isTainted('Mail')).toBe(true);
  });

  it('переносит taint из агента в его инструмент по ребру, которого n8n не хранит', () => {
    // `ai_tool` записан как инструмент → агент. Направление агент → инструмент выведено, и
    // именно по нему вставленная инструкция добирается до побочного эффекта.
    const taint = taintOf({ Hook: T.webhook, Agent: T.agent, Mail: T.gmailTool }, [
      ['Hook', 'Agent'],
      ['Mail', 'Agent', 'ai_tool'],
    ]);
    expect(taint.front('Agent').reached.has('Mail')).toBe(true);

    const walk = taint.front('Agent').walkTo('Mail');
    expect(walk?.steps.map((s) => s.kind)).toEqual(['invocation']);
    expect(walk?.usesDerivedEdge).toBe(true);
  });

  it('переносит taint из инструмента обратно в вызвавшего его агента', () => {
    // Отравленный результат поиска или враждебный ответ MCP попадает в контекст агента.
    const taint = taintOf({ Search: 'n8n-nodes-base.httpRequestTool', Agent: T.agent }, [
      ['Search', 'Agent', 'ai_tool'],
    ]);
    expect(
      taint
        .front('Search')
        .walkTo('Agent')
        ?.steps.map((s) => s.kind),
    ).toEqual(['return']);
  });

  it('переносит taint из sub-ноды в ноду, к которой она подключена', () => {
    const taint = taintOf(
      { Memory: '@n8n/n8n-nodes-langchain.memoryBufferWindow', Agent: T.agent },
      [['Memory', 'Agent', 'ai_memory']],
    );
    expect(
      taint
        .front('Memory')
        .walkTo('Agent')
        ?.steps.map((s) => s.kind),
    ).toEqual(['attachment']);
  });

  it('пропускает сквозь ноду, для которой нет правила, а не останавливается на ней', () => {
    // Неизвестная нода сообщества куда вероятнее передаст вход дальше, чем проглотит его.
    // Остановка объявила бы воркфлоу чистым лишь потому, что в нём есть неклассифицированная
    // нода.
    const taint = taintOf(
      { Hook: T.webhook, Mystery: 'n8n-nodes-community.whoKnows', Mail: T.emailSend },
      [
        ['Hook', 'Mystery'],
        ['Mystery', 'Mail'],
      ],
    );
    expect(taint.classify('Mystery')?.known).toBe(false);
    expect(taint.isTainted('Mail')).toBe(true);
  });
});

describe('гейты', () => {
  it('останавливается на сильном гейте, но сам гейт помечает достигнутым', () => {
    const taint = taintOf({ Hook: T.webhook, Approve: sendAndWait, Mail: T.emailSend }, [
      ['Hook', 'Approve'],
      ['Approve', 'Mail'],
    ]);
    const front = taint.front('Hook');
    expect(front.reached.has('Approve')).toBe(true);
    expect(front.reached.has('Mail')).toBe(false);
  });

  it('проходит слабый гейт и записывает его в маршрут', () => {
    const taint = taintOf({ Hook: T.webhook, Check: T.if, Mail: T.emailSend }, [
      ['Hook', 'Check'],
      ['Check', 'Mail'],
    ]);
    const front = taint.front('Hook');
    expect(front.reached.has('Mail')).toBe(true);
    expect(front.walkTo('Mail')?.weakGates).toEqual(['Check']);
  });

  it('отделяет достижимое вообще без гейтов от остального', () => {
    // Оба маршрута существуют; решение о severity вправе опираться на множество без гейтов.
    const taint = taintOf(
      { Hook: T.webhook, Check: T.if, Direct: T.set, Gated: T.emailSend, Open: T.telegram },
      [
        ['Hook', 'Check'],
        ['Check', 'Gated'],
        ['Hook', 'Direct'],
        ['Direct', 'Open'],
      ],
    );
    const front = taint.front('Hook');
    expect(front.reached.has('Gated')).toBe(true);
    expect(front.ungated.has('Gated')).toBe(false);
    expect(front.ungated.has('Open')).toBe(true);
  });

  it('предпочитает маршрут без гейтов, когда до ноды можно дойти обоими путями', () => {
    const taint = taintOf({ Hook: T.webhook, Check: T.if, Long: T.set, Mail: T.emailSend }, [
      ['Hook', 'Check'],
      ['Check', 'Mail'],
      ['Hook', 'Long'],
      ['Long', 'Mail'],
    ]);
    const walk = taint.front('Hook').walkTo('Mail');
    // Маршрут с гейтом на шаг короче. Показывать его рядом с severity, посчитанной без
    // гейтов, читалось бы как противоречие, поэтому проход идёт по тому маршруту, по которому
    // severity и решалась.
    expect(walk?.weakGates).toEqual([]);
    expect(nodesOf(walk!)).toEqual(['Hook', 'Long', 'Mail']);
  });

  it('не считает выключенный шаг подтверждения гейтом', () => {
    // Выключенная нода не выполняется; n8n передаёт её вход сразу следующей. Оставить её в
    // графе значило бы выдумать преграду, которой нет.
    const taint = taintOf(
      {
        Hook: T.webhook,
        Approve: { ...sendAndWait, disabled: true },
        Mail: T.emailSend,
      },
      [
        ['Hook', 'Approve'],
        ['Approve', 'Mail'],
      ],
    );
    expect(taint.isTainted('Mail')).toBe(true);
  });
});

describe('проходы', () => {
  it('завершается на цикле и показывает кратчайший маршрут', () => {
    const taint = taintOf({ Hook: T.webhook, A: T.set, B: T.set, Mail: T.emailSend }, [
      ['Hook', 'A'],
      ['A', 'B'],
      ['B', 'A'],
      ['B', 'Mail'],
    ]);
    const walk = taint.front('Hook').walkTo('Mail');
    expect(nodesOf(walk!)).toEqual(['Hook', 'A', 'B', 'Mail']);
    expect(endOf(walk!)).toBe('Mail');
  });

  it('ничего не возвращает для ноды, до которой taint не доходит', () => {
    const taint = taintOf({ Hook: T.webhook, Lonely: T.emailSend }, []);
    expect(taint.front('Hook').walkTo('Lonely')).toBeUndefined();
    expect(taint.isTainted('Lonely')).toBe(false);
  });

  it('не находит источников в воркфлоу, который читает только часы', () => {
    const taint = taintOf({ Clock: 'n8n-nodes-base.scheduleTrigger', Mail: T.emailSend }, [
      ['Clock', 'Mail'],
    ]);
    expect(taint.sources).toEqual([]);
    expect(taint.isTainted('Mail')).toBe(false);
  });
});
