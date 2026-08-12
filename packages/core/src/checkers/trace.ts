import type { GraphEdge } from '../graph/types.js';
import type { TaintWalk } from '../taint/types.js';
import type { TraceStep } from './types.js';

export const toTraceStep = (e: GraphEdge): TraceStep => ({
  from: e.from,
  to: e.to,
  kind: e.kind,
  derived: e.derived,
});

export const traceOf = (...walks: readonly (TaintWalk | undefined)[]): TraceStep[] =>
  walks.flatMap((w) => (w ? w.steps.map(toTraceStep) : []));

export const dedupe = (names: readonly string[]): string[] => [...new Set(names)];

/** `«a», «b» и «c»` — для предложения, а не для списка. */
export const list = (names: readonly string[], fallback = 'проверку'): string => {
  if (names.length === 0) return fallback;
  const quoted = names.map((n) => `«${n}»`);
  if (quoted.length === 1) return quoted[0] as string;
  return `${quoted.slice(0, -1).join(', ')} и ${quoted[quoted.length - 1] as string}`;
};
