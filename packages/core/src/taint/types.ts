import type { GraphEdge } from '../graph/types.js';
import type { TrustLevel } from '../rules/types.js';

/** Нода, приносящая данные извне, и насколько это «извне» далеко. */
export interface TaintSource {
  readonly node: string;
  readonly trust: TrustLevel;
}

/**
 * Один проход от начальной ноды до ноды, куда дошёл taint, ребро за ребром.
 *
 * Находка без этого — утверждение без доказательства: читатель смотрит на холст и должен
 * иметь возможность пройти тем же маршрутом, что и анализатор.
 */
export interface TaintWalk {
  readonly from: string;
  /** Рёбра по порядку. Проход заканчивается в `to` последнего из них. */
  readonly steps: readonly GraphEdge[];
  /** Ноды слабых гейтов, через которые проходит именно этот маршрут: вошли и вышли. */
  readonly weakGates: readonly string[];
  /** Истина, когда проход использует хотя бы одно ребро, которое парсер вывел, а не прочитал. */
  readonly usesDerivedEdge: boolean;
}

/** Куда taint добирается из одной начальной ноды и каким образом. */
export interface TaintFront {
  readonly from: string;
  /** Все ноды, куда доходит taint. Слабые гейты его не останавливают, сильные — да. */
  readonly reached: ReadonlySet<string>;
  /**
   * Ноды, до которых taint доходит, не проходя ни через один слабый гейт.
   *
   * Держится отдельно от `reached`, потому что вопрос, который задаёт решение о severity,
   * двоичный — есть ли маршрут, на котором вообще ничего не стоит? — и ответ вторым проходом
   * точен, тогда как разглядывание одного выбранного маршрута — нет.
   */
  readonly ungated: ReadonlySet<string>;
  /**
   * Проход до `node`, по возможности такой, который не пересекает ни одного слабого гейта.
   * `undefined`, когда taint туда не доходит.
   */
  walkTo(node: string): TaintWalk | undefined;
}

/** Последняя нода прохода. */
export const endOf = (walk: TaintWalk): string =>
  walk.steps.length === 0 ? walk.from : (walk.steps[walk.steps.length - 1] as GraphEdge).to;

/** Имена нод вдоль прохода, включая начальную, — то, что печатает отчёт. */
export const nodesOf = (walk: TaintWalk): string[] => [walk.from, ...walk.steps.map((e) => e.to)];
