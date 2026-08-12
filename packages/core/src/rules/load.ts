import { parse as parseYaml } from 'yaml';
import type { NodeRegistry } from './registry.js';
import type { SensitiveParams, SensitiveParamFile } from '../expressions/sensitive.js';
import type { RuleFile } from './types.js';

/**
 * Разбор двух файлов правил из текста, который вызывающий уже держит.
 *
 * Здесь ничто не трогает файловую систему, и ничто не должно начать: визуализатор гоняет
 * этот же код в браузере на правилах, вшитых строками, и один импорт `node:fs` где угодно в
 * достижимом графе ломает сборку. Чтение поставляемых файлов правил с диска живёт по
 * соседству, в `default-rules.ts`, который браузерная точка входа никогда не импортирует.
 * Разделение стережёт `test/browser.test.ts`.
 */

export function loadRules(yamlText: string): RuleFile {
  const parsed = parseYaml(yamlText) as unknown;
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Array.isArray((parsed as { nodes?: unknown }).nodes)
  ) {
    throw new Error('Файл правил должен быть объектом с массивом "nodes"');
  }
  return parsed as RuleFile;
}

export function loadSensitiveParams(yamlText: string): SensitiveParamFile {
  const parsed = parseYaml(yamlText) as unknown;
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Array.isArray((parsed as { params?: unknown }).params)
  ) {
    throw new Error('Файл чувствительных параметров должен быть объектом с массивом "params"');
  }
  return parsed as SensitiveParamFile;
}

/** Всё, что нужно анализу, чтобы вызывающий передавал одну вещь, а не три. */
export interface Rules {
  readonly registry: NodeRegistry;
  readonly sensitiveParams: SensitiveParams;
}
