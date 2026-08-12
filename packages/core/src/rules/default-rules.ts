import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { NodeRegistry } from './registry.js';
import { SensitiveParams } from '../expressions/sensitive.js';
import { loadRules, loadSensitiveParams } from './load.js';
import type { Rules } from './load.js';
import type { NodeDefaults } from './types.js';

/**
 * Набор правил, поставляемый с пакетом и прочитанный с диска.
 *
 * Это единственный модуль анализа, который открывает файл, и он сознательно сделан листом:
 * `browser.ts` его не импортирует, поэтому в сборке визуализатора `node:fs` не появляется.
 * Те, кто не может читать файлы, собирают `Rules` сами из `loadRules` и текста, который у
 * них есть.
 */

const RULES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'rules');

let cachedRules: Rules | undefined;

/** Набор правил, поставляемый с пакетом. Разбирается один раз. */
export function defaultRules(): Rules {
  if (!cachedRules) {
    const nodes = loadRules(readFileSync(join(RULES_DIR, 'nodes.yaml'), 'utf8'));
    const defaults = JSON.parse(
      readFileSync(join(RULES_DIR, 'node-defaults.json'), 'utf8'),
    ) as NodeDefaults;
    cachedRules = {
      registry: new NodeRegistry(nodes, defaults),
      sensitiveParams: new SensitiveParams(
        loadSensitiveParams(readFileSync(join(RULES_DIR, 'sensitive-params.yaml'), 'utf8')),
      ),
    };
  }
  return cachedRules;
}

export const defaultRegistry = (): NodeRegistry => defaultRules().registry;
