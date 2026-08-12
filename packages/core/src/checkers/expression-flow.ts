import type { GraphNode } from '../graph/types.js';
import type { ParsedExpression } from '../expressions/parse.js';
import type { ParamKind } from '../expressions/sensitive.js';
import { untrustedRefs } from './context.js';
import type { CheckerContext, ResolvedRef } from './context.js';

/**
 * Один чувствительный параметр вместе с недоверенными данными, которые в него попадают.
 *
 * Общий для трёх правил о выражениях: они отличаются тем, что значит позиция, а не тем, как
 * она находится. URL решает, куда уйдёт запрос; `query` решает, что выполнит база; `command`
 * решает, что выполнит хост.
 */
export interface SensitiveHit {
  readonly node: GraphNode;
  readonly kind: ParamKind;
  readonly path: string;
  readonly parsed: ParsedExpression;
  /** Непустой по построению — попадание без недоверенных данных не возвращается. */
  readonly untrusted: readonly ResolvedRef[];
}

export function sensitiveHits(ctx: CheckerContext, kinds: readonly ParamKind[]): SensitiveHit[] {
  const hits: SensitiveHit[] = [];

  for (const node of ctx.taint.graph.nodes) {
    for (const { kind, found } of ctx.params.expressionsIn(node)) {
      if (!kinds.includes(kind)) continue;

      const untrusted = untrustedRefs(ctx, node, found.parsed.refs);
      if (untrusted.length === 0) continue;

      hits.push({ node, kind, path: found.path, parsed: found.parsed, untrusted });
    }
  }
  return hits;
}

/** Ссылка, которая читается хуже всех: вокруг неё и пишется находка. */
export const worstRef = (hit: SensitiveHit): ResolvedRef =>
  [...hit.untrusted].sort(
    (a, b) => rank(b.source.trust) - rank(a.source.trust) || preference(a) - preference(b),
  )[0] as ResolvedRef;

const rank = (trust: ResolvedRef['source']['trust']): number =>
  trust === 'untrusted-public' ? 3 : trust === 'untrusted-external' ? 2 : 1;

/**
 * Сначала `$fromAI`, потом именованная нода, потом собственный вход ноды.
 *
 * Модель, которая прямо пишет значение, — это и самое сильное утверждение, и самая короткая
 * фраза; `$json` — самое расплывчатое, потому что говорит лишь, что данные пришли откуда-то
 * сверху.
 */
const preference = (r: ResolvedRef): number =>
  r.ref.kind === 'fromAI' ? 0 : r.ref.kind === 'node' ? 1 : 2;

/** Как недоверенное значение попало в этот параметр — словами. */
export function describeRef(r: ResolvedRef): string {
  switch (r.ref.kind) {
    case 'fromAI':
      return `модель, управляющая «${r.via}», пишет это значение напрямую (\`$fromAI\`)`;
    case 'node':
      return `в него подставляется \`${r.ref.text}\` — вывод ноды «${r.via}»`;
    default:
      return `в него подставляется \`$json\` — данные, приходящие в «${r.via}»`;
  }
}
