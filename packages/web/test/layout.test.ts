import { describe, expect, it } from 'vitest';
import { parseWorkflow } from '@n8n-sentinel/core/browser';
import { GRID, NODE_SIZE, SUB_NODE_SIZE, boundsOf, layout } from '../src/layout.js';

/**
 * Раскладка принадлежит автору везде, где автор её задал.
 */

const workflow = (nodes: unknown[], connections: unknown = {}): unknown => ({
  name: 'test',
  nodes,
  connections,
});

const node = (name: string, type: string, position?: [number, number]): unknown => ({
  name,
  type,
  typeVersion: 1,
  parameters: {},
  ...(position === undefined ? {} : { position }),
});

function graphOf(document_: unknown) {
  return parseWorkflow(document_).graph;
}

describe('раскладка', () => {
  it('использует позиции, которые несёт документ', () => {
    const graph = graphOf(
      workflow([
        node('A', 'n8n-nodes-base.set', [320, 160]),
        node('B', 'n8n-nodes-base.set', [544, 160]),
      ]),
    );
    const placed = layout(graph);

    expect(placed.byName.get('A')).toMatchObject({ x: 320, y: 160, w: NODE_SIZE, h: NODE_SIZE });
    expect(placed.byName.get('B')?.x).toBe(544);
    expect(placed.invented).toEqual([]);
  });

  it('выдумывает раскладку слева направо, когда документ их не несёт', () => {
    const graph = graphOf(
      workflow(
        [
          node('Trigger', 'n8n-nodes-base.webhook'),
          node('Middle', 'n8n-nodes-base.set'),
          node('End', 'n8n-nodes-base.slack'),
        ],
        {
          Trigger: { main: [[{ node: 'Middle', type: 'main', index: 0 }]] },
          Middle: { main: [[{ node: 'End', type: 'main', index: 0 }]] },
        },
      ),
    );
    const placed = layout(graph);

    const x = (name: string): number => placed.byName.get(name)?.x ?? NaN;
    expect(x('Trigger')).toBeLessThan(x('Middle'));
    expect(x('Middle')).toBeLessThan(x('End'));
    expect(placed.invented).toHaveLength(3);
  });

  it('не двигает ноды с позицией, когда у других её нет', () => {
    const graph = graphOf(
      workflow([
        node('Placed', 'n8n-nodes-base.set', [100, 100]),
        node('Loose', 'n8n-nodes-base.set'),
      ]),
    );
    const placed = layout(graph);

    expect(placed.byName.get('Placed')).toMatchObject({ x: 100, y: 100 });
    expect(placed.byName.get('Loose')?.y).toBeGreaterThan(100 + NODE_SIZE);
    expect(placed.invented).toEqual(['Loose']);
  });

  it('скругляет триггер слева и уменьшает AI-sub-ноду', () => {
    const graph = graphOf(
      workflow(
        [
          node('When chat message received', '@n8n/n8n-nodes-langchain.chatTrigger', [0, 0]),
          node('AI Agent', '@n8n/n8n-nodes-langchain.agent', [224, 0]),
          node('OpenAI Chat Model', '@n8n/n8n-nodes-langchain.lmChatOpenAi', [224, 224]),
        ],
        {
          'When chat message received': { main: [[{ node: 'AI Agent', type: 'main', index: 0 }]] },
          'OpenAI Chat Model': {
            ai_languageModel: [[{ node: 'AI Agent', type: 'ai_languageModel', index: 0 }]],
          },
        },
      ),
    );
    const placed = layout(graph);

    expect(placed.byName.get('When chat message received')?.shape).toBe('trigger');
    expect(placed.byName.get('AI Agent')?.shape).toBe('node');
    expect(placed.byName.get('OpenAI Chat Model')).toMatchObject({
      shape: 'sub',
      w: SUB_NODE_SIZE,
    });
  });

  it('даёт стикеру тот размер, который он объявляет', () => {
    const graph = graphOf(
      workflow([
        {
          name: 'Note',
          type: 'n8n-nodes-base.stickyNote',
          typeVersion: 1,
          position: [0, 0],
          parameters: { content: '## Read me', width: 420, height: 260 },
        },
      ]),
    );
    const placed = layout(graph).byName.get('Note');

    expect(placed).toMatchObject({ shape: 'sticky', w: 420, h: 260 });
  });

  it('меряет холст по тому, что ноды действительно занимают', () => {
    const graph = graphOf(
      workflow([
        node('A', 'n8n-nodes-base.set', [0, 0]),
        node('B', 'n8n-nodes-base.set', [10 * GRID, 4 * GRID]),
      ]),
    );
    expect(boundsOf(layout(graph).placed)).toEqual({
      minX: 0,
      minY: 0,
      maxX: 10 * GRID + NODE_SIZE,
      maxY: 4 * GRID + NODE_SIZE,
    });
  });

  it('переживает воркфлоу, замкнутый в петлю', () => {
    const graph = graphOf(
      workflow([node('A', 'n8n-nodes-base.set'), node('B', 'n8n-nodes-base.set')], {
        A: { main: [[{ node: 'B', type: 'main', index: 0 }]] },
        B: { main: [[{ node: 'A', type: 'main', index: 0 }]] },
      }),
    );
    expect(layout(graph).placed).toHaveLength(2);
  });
});
