import type { WorkflowGraph } from './graph.js';
import type { EdgeKind, GraphEdge } from './types.js';

export interface TraversalOptions {
  /** Идти только по этим видам рёбер. По умолчанию — по всем. */
  readonly kinds?: readonly EdgeKind[];
  /** Идти по рёбрам назад, от получателей к источникам. */
  readonly backwards?: boolean;
}

/**
 * Все обходы итеративные, с явным стеком.
 *
 * В воркфлоу бывают петли — `splitInBatches` заворачивает свой выход себе же на вход, и у 237
 * из 794 воркфлоу выборки где-то есть цикл, — поэтому рекурсивный обход либо зависает, либо
 * рвёт стек. Самая большая фикстура — 244 ноды; прогон по корпусу должен переживать куда
 * худшее и без того, и без другого.
 */

function follow(graph: WorkflowGraph, node: string, opts: TraversalOptions): readonly GraphEdge[] {
  const edges = opts.backwards ? graph.incoming(node) : graph.outgoing(node);
  if (!opts.kinds) return edges;
  const allowed = opts.kinds;
  return edges.filter((e) => allowed.includes(e.kind));
}

const other = (edge: GraphEdge, opts: TraversalOptions): string =>
  opts.backwards ? edge.from : edge.to;

/**
 * Все ноды, достижимые из `start`, не считая самого `start` — если только к нему не ведёт цикл.
 */
export function reachableFrom(
  graph: WorkflowGraph,
  start: string,
  opts: TraversalOptions = {},
): Set<string> {
  const seen = new Set<string>();
  if (!graph.has(start)) return seen;

  const stack: string[] = [start];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    for (const edge of follow(graph, current, opts)) {
      const next = other(edge, opts);
      if (seen.has(next)) continue;
      seen.add(next);
      stack.push(next);
    }
  }
  return seen;
}

/**
 * Перечисляет простые пути от `start` до любой ноды, удовлетворяющей `isTarget`.
 *
 * Пути простые — нода встречается не больше одного раза, — и именно это заставляет обход
 * завершаться на графах с циклами. Для отчёта по безопасности это к тому же правильный ответ:
 * повторение петли никуда нового не приводит, а трасса, трижды заходящая в `Loop Over Items`,
 * перед человеком является шумом.
 *
 * `limit` ограничивает число возвращаемых путей; ветвление через агента с дюжиной
 * инструментов делает настоящее количество экспоненциальным, а отчёт всё равно показывает
 * единицы.
 */
export function findPaths(
  graph: WorkflowGraph,
  start: string,
  isTarget: (node: string) => boolean,
  opts: TraversalOptions & { readonly limit?: number } = {},
): GraphEdge[][] {
  const limit = opts.limit ?? 32;
  const found: GraphEdge[][] = [];
  if (!graph.has(start) || limit <= 0) return found;

  const path: GraphEdge[] = [];
  const onPath = new Set<string>([start]);

  // Явный стек итераторов: так обход остаётся итеративным и при этом умеет откатываться и
  // снимать пометку в `onPath` в нужный момент.
  const stack: { node: string; edges: readonly GraphEdge[]; i: number }[] = [
    { node: start, edges: follow(graph, start, opts), i: 0 },
  ];

  while (stack.length > 0 && found.length < limit) {
    const frame = stack[stack.length - 1] as (typeof stack)[number];

    if (frame.i >= frame.edges.length) {
      stack.pop();
      const last = path.pop();
      if (last) onPath.delete(other(last, opts));
      continue;
    }

    const edge = frame.edges[frame.i++] as GraphEdge;
    const next = other(edge, opts);
    if (onPath.has(next)) continue;

    path.push(edge);
    onPath.add(next);

    if (isTarget(next)) {
      found.push([...path]);
      // Не спускаемся дальше цели: путь подлиннее, проходящий сквозь неё, не скажет читателю
      // ничего, чего не сказал короткий.
      path.pop();
      onPath.delete(next);
      continue;
    }

    stack.push({ node: next, edges: follow(graph, next, opts), i: 0 });
  }
  return found;
}

/** Ноды, лежащие хотя бы на одном цикле. */
export function nodesOnCycles(graph: WorkflowGraph, opts: TraversalOptions = {}): Set<string> {
  const onCycle = new Set<string>();
  for (const node of graph.nodes) {
    // Нода лежит на цикле ровно тогда, когда она достижима из самой себя.
    if (reachableFrom(graph, node.name, opts).has(node.name)) onCycle.add(node.name);
  }
  return onCycle;
}

export function hasCycle(graph: WorkflowGraph, opts: TraversalOptions = {}): boolean {
  for (const node of graph.nodes) {
    if (reachableFrom(graph, node.name, opts).has(node.name)) return true;
  }
  return false;
}
