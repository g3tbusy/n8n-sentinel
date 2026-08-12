import { bySeverity, findPaths, rank } from '@n8n-sentinel/core/browser';
import type {
  AnalysisResult,
  Finding,
  GraphEdge,
  Severity,
  TraceStep,
  WorkflowGraph,
} from '@n8n-sentinel/core/browser';

/**
 * Всё, что странице нужно знать о результате, посчитанное один раз.
 *
 * Держится отдельно от отрисовки, чтобы это можно было тестировать без браузера и чтобы две
 * вещи, которые рисует страница, — холст и список — смотрели на одни и те же множества, а не
 * каждая решала сама, что значит «на пути».
 */

export interface FindingView {
  readonly finding: Finding;
  /** Устойчив в пределах одного анализа: связывает строку списка с подсвеченным путём. */
  readonly id: string;
  readonly nodes: ReadonlySet<string>;
  readonly edges: ReadonlySet<string>;
}

export interface Model {
  readonly result: AnalysisResult;
  readonly findings: readonly FindingView[];
  /** Худшая severity, касающаяся каждой ноды, — для значков, видимых до всякого выделения. */
  readonly worstByNode: ReadonlyMap<string, Severity>;
  readonly counts: Readonly<Record<Severity, number>>;
}

/** Определяет ребро так, чтобы трасса и нарисованный граф понимали это одинаково. */
export function edgeKey(edge: Pick<GraphEdge, 'from' | 'to' | 'kind'>): string {
  return `${edge.from}→${edge.to}→${edge.kind}`;
}

function nodesOf(trace: readonly TraceStep[]): Set<string> {
  const names = new Set<string>();
  for (const step of trace) {
    names.add(step.from);
    names.add(step.to);
  }
  return names;
}

export function buildModel(result: AnalysisResult): Model {
  const findings = [...result.findings]
    .map((finding, index) => ({
      finding,
      id: `f${index}`,
      nodes: nodesOf(finding.trace),
      edges: new Set(finding.trace.map(edgeKey)),
    }))
    .sort((a, b) => bySeverity(a.finding.severity, b.finding.severity));

  const worstByNode = new Map<string, Severity>();
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const view of findings) {
    counts[view.finding.severity] += 1;
    // Значки только на концах. Если каждая нода длинной трассы носит красную точку, это
    // говорит «здесь горит всё», тогда как утверждение — про то, где путь начинается и куда
    // приходит; остальная часть пути на то и подсвечивается.
    for (const name of [view.finding.source.node, view.finding.sink.node]) {
      const current = worstByNode.get(name);
      if (current === undefined || rank(view.finding.severity) > rank(current)) {
        worstByNode.set(name, view.finding.severity);
      }
    }
  }

  return { result, findings, worstByNode, counts };
}

/**
 * Какими ещё способами те же данные попадают из этого источника в это действие.
 *
 * Находка несёт один маршрут — свидетеля, которого сохранил движок. Читателю, решающему,
 * верить ли ей, важно знать, случайность ли этот путь одной связи или форма всего воркфлоу.
 * Ограничение низкое: у агента с дюжиной инструментов маршрутов экспоненциально много, и
 * ответ «минимум четыре» полезен ровно так же, как точное число.
 */
export function routeCount(graph: WorkflowGraph, finding: Finding, limit = 4): number {
  return findPaths(graph, finding.source.node, (name) => name === finding.sink.node, { limit })
    .length;
}
