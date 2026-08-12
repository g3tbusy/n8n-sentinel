import type { EdgeKind } from '../graph/types.js';
import type { SideEffect, TrustLevel } from '../rules/types.js';

/**
 * Идентификаторы правил. Фаза 3 реализует первое; остальные объявлены здесь, потому что от
 * этого набора отталкиваются и репортер, и SARIF-писатель, и исследование корпуса, — а
 * правило, появляющееся на середине конвейера, это правило, которое никто не посчитал.
 *
 * Значения остаются английскими намеренно: это идентификаторы, они уезжают в SARIF и в
 * GitHub Security, и перевод сломал бы совместимость.
 */
export type RuleId =
  | 'INDIRECT_PROMPT_INJECTION'
  | 'UNGATED_SIDE_EFFECT'
  | 'EXPRESSION_SSRF'
  | 'EXPRESSION_SQLI'
  | 'EXPRESSION_RCE'
  | 'SECRET_EXFIL_RISK'
  | 'MISSING_HUMAN_APPROVAL'
  | 'OVERBROAD_TOOL_ACCESS';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Confidence =
  /** Путь есть в документе, и оба его конца классифицированы. */
  | 'firm'
  /** Путь уходит за пределы видимости анализа — sink-и вложенного воркфлоу сюда не входят. */
  | 'uncertain';

export interface TraceStep {
  readonly from: string;
  readonly to: string;
  readonly kind: EdgeKind;
  /** Истина для ребра, созданного нормализацией. На холсте n8n оно не нарисовано. */
  readonly derived: boolean;
}

export interface Finding {
  readonly rule: RuleId;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly workflow: string;
  /** Одна строка, для списка. */
  readonly title: string;
  /** Рассуждение — для читателя, который хочет знать, на каком основании это утверждается. */
  readonly detail: string;
  /**
   * Что с этим делать в этом конкретном воркфлоу.
   *
   * Отдельно от `detail`, потому что их читают в разные моменты и разные люди. Находка,
   * которая безупречно объясняет себя и на этом останавливается, оставляет читателя
   * придумывать починку самостоятельно — и вот тогда в задачу пишут «добавить валидацию», и
   * не происходит ничего.
   */
  readonly remediation: string;
  readonly source: { readonly node: string; readonly trust: TrustLevel };
  /** Нода, превращающая текст в действие, если такая есть. */
  readonly agent: string | undefined;
  readonly sink: {
    readonly node: string;
    readonly effect: SideEffect | undefined;
    readonly irreversible: boolean;
  };
  /** От источника до sink, по порядку. `trace[0].from` — это нода-источник. */
  readonly trace: readonly TraceStep[];
  /** Слабые гейты, через которые проходит трасса. Записаны независимо от того, снизили ли severity. */
  readonly weakGates: readonly string[];
  /** Другие источники, доходящие до того же агента, свёрнутые в эту находку. */
  readonly otherSources: readonly string[];
  readonly notes: readonly string[];
}
