import { isAiConnectionType, MAIN_CONNECTION } from '../n8n-format.js';
import type { RawNode } from '../n8n-format.js';
import { WorkflowGraph } from '../graph/graph.js';
import type { GraphEdge, GraphNode } from '../graph/types.js';
import { warn } from './warnings.js';
import type { ParseWarning } from './warnings.js';

export interface ParseResult {
  /** Есть всегда. Пустой, когда разобрать вход не удалось вовсе. */
  readonly graph: WorkflowGraph;
  readonly warnings: readonly ParseWarning[];
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Превращает документ воркфлоу n8n в граф, чьи рёбра говорят, куда идут данные.
 *
 * Никогда не бросает исключение, что бы ему ни передали. Как всплывают проблемы — см.
 * `ParseWarningCode`.
 */
export function parseWorkflow(input: unknown): ParseResult {
  const warnings: ParseWarning[] = [];

  if (!isRecord(input)) {
    warnings.push(warn('not_a_workflow', `Ожидался объект, получено: ${describe(input)}`));
    return { graph: new WorkflowGraph('', [], []), warnings };
  }

  const name = typeof input.name === 'string' ? input.name : '';

  if (!Array.isArray(input.nodes)) {
    warnings.push(
      warn('not_a_workflow', `Ожидалось, что "nodes" — массив, получено: ${describe(input.nodes)}`),
    );
    return { graph: new WorkflowGraph(name, [], []), warnings };
  }

  const pinned = isRecord(input.pinData) ? new Set(Object.keys(input.pinData)) : new Set<string>();
  const nodes = readNodes(input.nodes, pinned, warnings);
  const known = new Set(nodes.map((n) => n.name));
  const edges = readConnections(input.connections, known, warnings);

  return { graph: new WorkflowGraph(name, nodes, edges), warnings };
}

function readNodes(raw: unknown[], pinned: Set<string>, warnings: ParseWarning[]): GraphNode[] {
  const nodes: GraphNode[] = [];
  const seen = new Set<string>();

  for (const [i, entry] of raw.entries()) {
    if (!isRecord(entry)) {
      warnings.push(warn('node_without_name', `nodes[${i}] — это ${describe(entry)}, а не нода`));
      continue;
    }
    const node = entry as RawNode;

    // На ноду без имени `connections` сослаться не может, поэтому участвовать в путях она не
    // способна. Выбросить её — единственный непротиворечивый вариант.
    if (typeof node.name !== 'string' || node.name === '') {
      warnings.push(warn('node_without_name', `У nodes[${i}] нет пригодного "name"; выброшена`));
      continue;
    }
    if (seen.has(node.name)) {
      warnings.push(
        warn(
          'duplicate_node_name',
          `Две ноды называются «${node.name}»; оставлена первая`,
          node.name,
        ),
      );
      continue;
    }
    seen.add(node.name);

    if (typeof node.type !== 'string' || node.type === '') {
      warnings.push(warn('node_without_type', `У ноды «${node.name}» нет "type"`, node.name));
    }

    nodes.push({
      name: node.name,
      type: typeof node.type === 'string' ? node.type : '',
      typeVersion: typeof node.typeVersion === 'number' ? node.typeVersion : undefined,
      disabled: node.disabled === true,
      parameters: isRecord(node.parameters) ? node.parameters : {},
      credentials: isRecord(node.credentials) ? node.credentials : {},
      hasPinnedData: pinned.has(node.name),
      raw: node,
    });
  }
  return nodes;
}

function readConnections(
  raw: unknown,
  known: ReadonlySet<string>,
  warnings: ParseWarning[],
): GraphEdge[] {
  const edges: GraphEdge[] = [];
  if (raw === undefined || raw === null) return edges;

  if (!isRecord(raw)) {
    warnings.push(
      warn('malformed_connections', `"connections" — это ${describe(raw)}, а не объект`),
    );
    return edges;
  }

  for (const [source, byType] of Object.entries(raw)) {
    // docs §6.1: ключ может оказаться мохибейком или называть переименованную ноду.
    if (!known.has(source)) {
      warnings.push(
        warn(
          'unknown_connection_source',
          `Источник связи «${source}» не соответствует ни одной ноде; его связи игнорируются`,
          source,
        ),
      );
      continue;
    }
    if (!isRecord(byType)) {
      warnings.push(
        warn('malformed_connections', `Связи «${source}» — это ${describe(byType)}`, source),
      );
      continue;
    }

    for (const [connectionType, slots] of Object.entries(byType)) {
      if (!Array.isArray(slots)) {
        warnings.push(
          warn(
            'malformed_connections',
            `«${source}».${connectionType} должен быть массивом слотов, получено: ${describe(slots)}`,
            source,
          ),
        );
        continue;
      }

      for (const [slotIndex, slot] of slots.entries()) {
        // Неиспользуемый выходной порт между двумя используемыми хранится как null. Это норма.
        if (slot === null || slot === undefined) continue;

        // docs §6.3: некоторые документы кладут концы связей прямо в список слотов, на
        // уровень выше нужного. n8n сам такие отвергает, поэтому и мы не гадаем о замысле.
        if (!Array.isArray(slot)) {
          warnings.push(
            warn(
              'malformed_connections',
              `«${source}».${connectionType}[${slotIndex}] должен быть массивом концов связи, получено: ${describe(slot)}`,
              source,
            ),
          );
          continue;
        }

        for (const endpoint of slot) {
          if (!isRecord(endpoint) || typeof endpoint.node !== 'string') {
            warnings.push(
              warn(
                'malformed_connections',
                `«${source}».${connectionType}[${slotIndex}] содержит ${describe(endpoint)} там, где ожидался конец связи`,
                source,
              ),
            );
            continue;
          }
          const target = endpoint.node;

          // docs §6.2: рёбра, пережившие ноду, на которую указывают.
          if (!known.has(target)) {
            warnings.push(
              warn(
                'unknown_connection_target',
                `«${source}».${connectionType} указывает на «${target}», которого не существует`,
                source,
              ),
            );
            continue;
          }

          const inputIndex = typeof endpoint.index === 'number' ? endpoint.index : 0;
          edges.push(...normalise(source, target, connectionType, slotIndex, inputIndex, warnings));
        }
      }
    }
  }
  return edges;
}

/**
 * Решает, что хранимая связь означает для потока данных.
 *
 * Это сердце фазы 1. Хранимое направление — это схема проводки, и для AI-связей оно либо
 * обратно тому, куда на самом деле идут данные, либо описывает только половину пути.
 */
function normalise(
  source: string,
  target: string,
  connectionType: string,
  slot: number,
  index: number,
  warnings: ParseWarning[],
): GraphEdge[] {
  const base = { connectionType, slot, index } as const;

  if (connectionType === MAIN_CONNECTION) {
    return [{ ...base, from: source, to: target, kind: 'data', derived: false }];
  }

  if (connectionType === 'ai_tool') {
    // Хранится как инструмент → агент. Оба направления настоящие, и опасное — выведенное:
    // именно так (возможно, отравленный) контекст агента доходит до побочного эффекта.
    return [
      { ...base, from: source, to: target, kind: 'return', derived: false },
      { ...base, from: target, to: source, kind: 'invocation', derived: true },
    ];
  }

  if (isAiConnectionType(connectionType)) {
    // Любой другой тип ai_* подключает sub-ноду, чей вывод кормит родителя: ответ модели,
    // история из памяти, текст из загрузчика документов. Хранимое направление верное.
    return [{ ...base, from: source, to: target, kind: 'attachment', derived: false }];
  }

  // Что-то вроде ключа `output` из docs §6.3. Кто-то нарисовал стрелку; считаем её потоком
  // данных, чтобы путь не потерялся молча, но говорим об этом.
  warnings.push(
    warn(
      'unknown_connection_type',
      `Неизвестный тип связи «${connectionType}» из «${source}»; считается потоком данных`,
      source,
    ),
  );
  return [{ ...base, from: source, to: target, kind: 'data', derived: false }];
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'массив';
  return `${typeof v}`;
}
