import { missingHumanApproval, overbroadToolAccess } from './agent-authority.js';
import type { CheckerContext } from './context.js';
import { expressionRce } from './expression-rce.js';
import { expressionSqli } from './expression-sqli.js';
import { expressionSsrf } from './expression-ssrf.js';
import { indirectPromptInjection } from './indirect-prompt-injection.js';
import { secretExfilRisk } from './secret-exfil-risk.js';
import { bySeverity } from './severity.js';
import { ungatedSideEffect } from './ungated-side-effect.js';
import type { Finding, RuleId } from './types.js';

export interface Checker {
  readonly id: RuleId;
  run(ctx: CheckerContext): Finding[];
}

/**
 * Все чекеры, худшие первыми — в том порядке, в котором с ними должен встретиться читатель.
 *
 * Чекер получает готовый анализ и возвращает findings. Сам по графу он никогда не ходит:
 * правила распространения — какие рёбра переносят taint, где режут гейты, какой источник
 * называть — решаются в одном месте, чтобы правило, добавленное позже, не смогло втихую
 * разойтись с уже написанными.
 *
 * Там, где два правила описали бы одну и ту же схему, побеждает более конкретное, а второе
 * отступает. `UNGATED_SIDE_EFFECT` пропускает всё, до чего дотягивается открытый агент, а два
 * правила о полномочиях агента пропускают агентов, до которых уже доходит недоверенный ввод.
 * Иначе получится отчёт, который говорит одно и то же трижды тремя голосами.
 */
export const CHECKERS: readonly Checker[] = [
  { id: 'INDIRECT_PROMPT_INJECTION', run: indirectPromptInjection },
  { id: 'EXPRESSION_RCE', run: expressionRce },
  { id: 'EXPRESSION_SQLI', run: expressionSqli },
  { id: 'EXPRESSION_SSRF', run: expressionSsrf },
  { id: 'SECRET_EXFIL_RISK', run: secretExfilRisk },
  { id: 'UNGATED_SIDE_EFFECT', run: ungatedSideEffect },
  { id: 'MISSING_HUMAN_APPROVAL', run: missingHumanApproval },
  { id: 'OVERBROAD_TOOL_ACCESS', run: overbroadToolAccess },
];

export function runCheckers(ctx: CheckerContext): Finding[] {
  const findings = CHECKERS.flatMap((c) => c.run(ctx));
  // Сначала самое серьёзное, дальше устойчиво по именам правила и нод, чтобы два прогона по
  // одному документу давали побайтово одинаковый вывод и разница в корпусе что-то значила.
  return findings.sort(
    (a, b) =>
      bySeverity(a.severity, b.severity) ||
      a.rule.localeCompare(b.rule) ||
      a.sink.node.localeCompare(b.sink.node) ||
      a.source.node.localeCompare(b.source.node),
  );
}

export { missingHumanApproval, overbroadToolAccess } from './agent-authority.js';
export { expressionRce } from './expression-rce.js';
export { expressionSqli } from './expression-sqli.js';
export { expressionSsrf } from './expression-ssrf.js';
export { indirectPromptInjection } from './indirect-prompt-injection.js';
export { secretExfilRisk } from './secret-exfil-risk.js';
export { ungatedSideEffect } from './ungated-side-effect.js';
export { bySeverity, cap, lower, rank } from './severity.js';
export type { CheckerContext, ResolvedRef } from './context.js';
export type { Confidence, Finding, RuleId, Severity, TraceStep } from './types.js';
