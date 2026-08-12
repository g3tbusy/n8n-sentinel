import { bypassDisabled } from './graph/disabled.js';
import type { WorkflowGraph } from './graph/graph.js';
import { parseWorkflow } from './parser/parse-workflow.js';
import type { ParseWarning } from './parser/warnings.js';
import type { Rules } from './rules/load.js';
import { runCheckers } from './checkers/index.js';
import type { Finding } from './checkers/types.js';
import { analyseTaint } from './taint/engine.js';
import type { TaintAnalysis } from './taint/engine.js';

export interface AnalysisResult {
  readonly workflow: string;
  readonly findings: readonly Finding[];
  readonly warnings: readonly ParseWarning[];
  /** Граф, к которому относятся findings: выключенные ноды из него уже вырезаны. */
  readonly graph: WorkflowGraph;
  readonly taint: TaintAnalysis;
}

/**
 * Просканировать один документ воркфлоу.
 *
 * Правила приходят параметром, а не берутся по умолчанию, чтобы этот модуль не трогал
 * файловую систему: визуализатор фазы 7 гоняет тот же анализ в браузере на правилах,
 * вшитых строками. Вызывающие на Node передают `defaultRules()`.
 *
 * Выключенные ноды вырезаются до всякого анализа. Выключенная нода не выполняется, но n8n
 * всё равно пропускает данные сквозь неё, поэтому оставить её значило бы либо выдумать
 * преграду, которой нет, либо приписать действие ноде, которая никогда не отрабатывает.
 */
export function analyseWorkflow(input: unknown, rules: Rules): AnalysisResult {
  const { graph, warnings } = parseWorkflow(input);
  return { ...analyseGraph(bypassDisabled(graph), rules), warnings };
}

/** Для вызывающих, у которых граф уже есть, — для визуализатора и для тестов. */
export function analyseGraph(graph: WorkflowGraph, rules: Rules): Omit<AnalysisResult, 'warnings'> {
  const taint = analyseTaint(graph, rules.registry);
  const findings = runCheckers({ taint, params: rules.sensitiveParams });
  return { workflow: graph.name, findings, graph, taint };
}
