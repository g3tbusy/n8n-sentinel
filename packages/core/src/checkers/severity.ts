import type { Severity } from './types.js';

/**
 * Severity как полосы с арифметикой, а не как оценка по формуле.
 *
 * Взвешенная оценка поставила бы число там, где ничего не измерено — насколько именно
 * обратимый sink лучше необратимого? — и это число потом цитировали бы так, будто его
 * измерили. Полосы и записанное правило «снимаем одну за каждое смягчающее обстоятельство»
 * говорят ровно столько, сколько известно на самом деле. Рассуждение по каждому правилу —
 * в docs/scoring.md.
 */
const ORDER = ['low', 'medium', 'high', 'critical'] as const;

export function rank(severity: Severity): number {
  return ORDER.indexOf(severity);
}

/** На одну полосу вниз за шаг, но не ниже `low`. */
export function lower(severity: Severity, bands = 1): Severity {
  const index = Math.max(0, rank(severity) - bands);
  return ORDER[index] as Severity;
}

export function cap(severity: Severity, ceiling: Severity): Severity {
  return rank(severity) > rank(ceiling) ? ceiling : severity;
}

/** Сначала самое серьёзное — в этом порядке отчёт перечисляет findings. */
export function bySeverity(a: Severity, b: Severity): number {
  return rank(b) - rank(a);
}
