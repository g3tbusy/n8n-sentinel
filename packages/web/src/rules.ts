import {
  NodeRegistry,
  SensitiveParams,
  loadRules,
  loadSensitiveParams,
} from '@n8n-sentinel/core/browser';
import type { NodeDefaults, Rules } from '@n8n-sentinel/core/browser';

import nodesYaml from '../../core/rules/nodes.yaml?raw';
import sensitiveParamsYaml from '../../core/rules/sensitive-params.yaml?raw';
import nodeDefaultsJson from '../../core/rules/node-defaults.json?raw';

/**
 * Поставляемые правила, вшитые текстом.
 *
 * Те же три файла, которые CLI читает с диска, байт в байт: страница не должна расходиться с
 * командной строкой в том, что делает нода Gmail. Импортируются строками, а не модулями,
 * чтобы разбор происходил здесь и теми же загрузчиками, а обработка JSON в Vite не стала
 * втихую второй его реализацией.
 */

let cached: Rules | undefined;

export function bundledRules(): Rules {
  if (cached === undefined) {
    cached = {
      registry: new NodeRegistry(
        loadRules(nodesYaml),
        JSON.parse(nodeDefaultsJson) as NodeDefaults,
      ),
      sensitiveParams: new SensitiveParams(loadSensitiveParams(sensitiveParamsYaml)),
    };
  }
  return cached;
}
