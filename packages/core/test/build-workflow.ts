/**
 * Строит документы воркфлоу n8n для тестов.
 *
 * Тесты идут через настоящий парсер, а не собирают `WorkflowGraph` напрямую, чтобы
 * тестируемое видело рёбра нормализованными так же, как у настоящего документа: связь
 * `ai_tool`, записанная здесь, превращается в пару `return`/`invocation`, а не в то, что
 * предположил автор теста.
 */

export interface NodeSpec {
  readonly type: string;
  readonly parameters?: Record<string, unknown>;
  readonly disabled?: boolean;
}

export type Edge = readonly [from: string, to: string, connectionType?: string];

export function workflow(
  nodes: Record<string, string | NodeSpec>,
  edges: readonly Edge[],
  name = 'test workflow',
): unknown {
  const connections: Record<
    string,
    Record<string, { node: string; type: string; index: number }[][]>
  > = {};

  for (const [from, to, connectionType = 'main'] of edges) {
    const byType = (connections[from] ??= {});
    const slots = (byType[connectionType] ??= [[]]);
    const slot = (slots[0] ??= []);
    slot.push({ node: to, type: connectionType, index: 0 });
  }

  return {
    name,
    nodes: Object.entries(nodes).map(([nodeName, spec], i) => {
      const s: NodeSpec = typeof spec === 'string' ? { type: spec } : spec;
      return {
        id: `id-${i}`,
        name: nodeName,
        type: s.type,
        typeVersion: 1,
        position: [i * 200, 0],
        parameters: s.parameters ?? {},
        ...(s.disabled === true ? { disabled: true } : {}),
      };
    }),
    connections,
  };
}

/** Частые типы нод, названные по тому, что они значат для сканера, а не для n8n. */
export const T = {
  webhook: 'n8n-nodes-base.webhook',
  chatTrigger: '@n8n/n8n-nodes-langchain.chatTrigger',
  gmailTrigger: 'n8n-nodes-base.gmailTrigger',
  agent: '@n8n/n8n-nodes-langchain.agent',
  chain: '@n8n/n8n-nodes-langchain.chainLlm',
  model: '@n8n/n8n-nodes-langchain.lmChatOpenAi',
  set: 'n8n-nodes-base.set',
  if: 'n8n-nodes-base.if',
  emailSend: 'n8n-nodes-base.emailSend',
  gmailTool: 'n8n-nodes-base.gmailTool',
  telegram: 'n8n-nodes-base.telegram',
  postgres: 'n8n-nodes-base.postgres',
  toolWorkflow: '@n8n/n8n-nodes-langchain.toolWorkflow',
  noOp: 'n8n-nodes-base.noOp',
  schedule: 'n8n-nodes-base.scheduleTrigger',
  http: 'n8n-nodes-base.httpRequest',
  httpTool: 'n8n-nodes-base.httpRequestTool',
  command: 'n8n-nodes-base.executeCommand',
  code: 'n8n-nodes-base.code',
} as const;

/** Нода Set с константами — форма, которой воркфлоу корпуса держат конфигурацию. */
export const config = (values: Record<string, string>): NodeSpec => ({
  type: T.set,
  parameters: {
    assignments: {
      assignments: Object.entries(values).map(([name, value], i) => ({
        id: `a${i}`,
        name,
        value,
        type: 'string',
      })),
    },
  },
});
