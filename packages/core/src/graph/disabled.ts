import { WorkflowGraph } from './graph.js';
import type { GraphEdge } from './types.js';

/**
 * Убирает выключенные ноды, перекидывая связи в обход них.
 *
 * Выключенная нода остаётся в документе и остаётся подключённой, но не выполняется: n8n
 * передаёт её вход сразу тому, что шло следом. То есть `Webhook → [выключенный Set] → Send
 * Email` на самом деле работает как `Webhook → Send Email`. Считать выключенную ноду стеной
 * значило бы молча объявить такой воркфлоу безопасным; считать её обычной нодой значило бы
 * приписать побочный эффект тому, что никогда не выполняется. Верно ни то ни другое — её надо
 * вырезать.
 *
 * Перекидываются только рёбра `data`. Выключенная sub-нода не пропускает ничего насквозь:
 * у агента, чей инструмент выключен, этого инструмента просто нет, поэтому такие рёбра
 * исчезают вместе с нодой.
 */
export function bypassDisabled(graph: WorkflowGraph): WorkflowGraph {
  const disabled = new Set(graph.nodes.filter((n) => n.disabled).map((n) => n.name));
  if (disabled.size === 0) return graph;

  const kept = graph.nodes.filter((n) => !n.disabled);
  const edges: GraphEdge[] = [];
  const seen = new Set<string>();

  const push = (edge: GraphEdge): void => {
    // Склеено по символу, которого не может быть в имени ноды. С пробелом
    // `A -> "B C"` и `"A B" -> C` схлопнулись бы в один ключ, и настоящее ребро потерялось бы.
    const key = [edge.from, edge.to, edge.kind, edge.connectionType, edge.slot, edge.index].join(
      '\u0000',
    );
    if (seen.has(key)) return;
    seen.add(key);
    edges.push(edge);
  };

  for (const edge of graph.edges) {
    if (!disabled.has(edge.from) && !disabled.has(edge.to)) {
      push(edge);
      continue;
    }
    // Ребро, входящее в выключенную ноду, становится ребром к тому, кому эта нода передала бы
    // дальше. Рёбра, *выходящие* из выключенной ноды, покрываются той же перекладкой.
    if (!disabled.has(edge.from) && disabled.has(edge.to) && edge.kind === 'data') {
      for (const target of liveSuccessors(graph, edge.to, disabled)) {
        push({ ...edge, to: target, derived: true });
      }
    }
  }

  return new WorkflowGraph(graph.name, kept, edges);
}

/**
 * Идёт вперёд по рёбрам `data` через цепочку выключенных нод до первых включённых.
 *
 * С защитой от циклов: выключенная нода внутри петли иначе водила бы обход вечно.
 */
function liveSuccessors(
  graph: WorkflowGraph,
  from: string,
  disabled: ReadonlySet<string>,
): Set<string> {
  const live = new Set<string>();
  const visited = new Set<string>([from]);
  const stack = [from];

  while (stack.length > 0) {
    const current = stack.pop() as string;
    for (const edge of graph.outgoing(current)) {
      if (edge.kind !== 'data') continue;
      if (!disabled.has(edge.to)) {
        live.add(edge.to);
        continue;
      }
      if (visited.has(edge.to)) continue;
      visited.add(edge.to);
      stack.push(edge.to);
    }
  }
  return live;
}
