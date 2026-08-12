/**
 * Всё, что анализ отдаёт наружу и что работает где угодно, включая браузер.
 *
 * Это вшивает в себя визуализатор. Здесь весь `index.ts`, кроме того, что читает файлы:
 * вызывающий передаёт правила текстом и сам собирает `Rules`. Rollup не умеет вытрясти
 * `node:fs` из модуля, который вычисляет путь во время импорта, поэтому разделение сделано
 * отдельной точкой входа, а не надеждой на tree-shaking, — а `test/browser.test.ts` обходит
 * импорты от этого файла и доказывает, что ни один встроенный модуль `node:` недостижим.
 */

export * from './n8n-format.js';

export { WorkflowGraph } from './graph/graph.js';
export type { EdgeKind, GraphEdge, GraphNode } from './graph/types.js';
export { bypassDisabled } from './graph/disabled.js';
export { findPaths, hasCycle, nodesOnCycles, reachableFrom } from './graph/traverse.js';
export type { TraversalOptions } from './graph/traverse.js';

export { parseWorkflow } from './parser/parse-workflow.js';
export type { ParseResult } from './parser/parse-workflow.js';
export type { ParseWarning, ParseWarningCode } from './parser/warnings.js';

export { analyseTaint, TaintAnalysis } from './taint/engine.js';
export { endOf, nodesOf } from './taint/types.js';
export type { TaintFront, TaintSource, TaintWalk } from './taint/types.js';

export {
  CHECKERS,
  expressionRce,
  expressionSqli,
  expressionSsrf,
  indirectPromptInjection,
  missingHumanApproval,
  overbroadToolAccess,
  runCheckers,
  secretExfilRisk,
  ungatedSideEffect,
} from './checkers/index.js';
export type { CheckerContext, ResolvedRef } from './checkers/context.js';

export { findExpressions, isExpression, parseExpression, readString } from './expressions/parse.js';
export type {
  ExpressionRef,
  FoundExpression,
  Interpolation,
  ParsedExpression,
  RefKind,
} from './expressions/parse.js';
export { dangerousConstructs, urlControl } from './expressions/position.js';
export type { UrlControl } from './expressions/position.js';
export { SensitiveParams } from './expressions/sensitive.js';
export type { ParamKind, SensitiveParamFile } from './expressions/sensitive.js';
export { bySeverity, cap, lower, rank } from './checkers/severity.js';
export type { Checker } from './checkers/index.js';
export type { Confidence, Finding, RuleId, Severity, TraceStep } from './checkers/types.js';

export {
  atOrAbove,
  JSON_REPORT_VERSION,
  locateNode,
  renderHuman,
  renderJson,
  renderSarif,
  summarise,
} from './report/index.js';
export type {
  HumanOptions,
  ScanReport,
  ScannedFile,
  SourceRegion,
  Summary,
  ToolInfo,
} from './report/index.js';

export { analyseGraph, analyseWorkflow } from './analyse.js';
export type { AnalysisResult } from './analyse.js';

export { NodeRegistry } from './rules/registry.js';
export { loadRules, loadSensitiveParams } from './rules/load.js';
export type { Rules } from './rules/load.js';
export type {
  Classification,
  NodeDefaults,
  NodeRole,
  ResolvedParameters,
  RuleEntry,
  RuleFile,
  SanitizerInfo,
  SanitizerKind,
  SideEffect,
  SinkInfo,
  SourceInfo,
  TrustLevel,
} from './rules/types.js';
