import { describe, expect, it } from 'vitest';
import type { GraphNode } from '@n8n-sentinel/core/browser';
import { defaultRules } from '../../core/src/rules/default-rules.js';
import { bundledRules } from '../src/rules.js';

/**
 * Страница и командная строка обязаны совпадать.
 *
 * Они грузят одни и те же три файла разными путями — один с диска, другой вшитым текстом, — и
 * визуализатор, который втихую классифицирует ноду Gmail не так, как сканер, был бы хуже, чем
 * отсутствие визуализатора: каждое расхождение читалось бы как ошибка анализа, а не сборки.
 */

const gmail: GraphNode = {
  name: 'Gmail',
  type: 'n8n-nodes-base.gmail',
  typeVersion: 2.1,
  disabled: false,
  parameters: {},
  credentials: {},
  hasPinnedData: false,
  raw: { name: 'Gmail', type: 'n8n-nodes-base.gmail' },
};

describe('вшитые правила', () => {
  const bundled = bundledRules();
  const fromDisk = defaultRules();

  it('классифицируют одни и те же типы нод', () => {
    expect(bundled.registry.types()).toEqual(fromDisk.registry.types());
  });

  it('одинаково разрешают параметры, которые n8n не сохраняет', () => {
    // Операция по умолчанию у Gmail — `send`, и она отсутствует у 2895 из 3695 нод Gmail в
    // библиотеке. Если бы вшитых дефолтов не было, здесь вернулся бы undefined, и страница
    // молча перестала бы находить большинство почтовых sink-ов.
    expect(bundled.registry.resolve(gmail).operation).toBe(
      fromDisk.registry.resolve(gmail).operation,
    );
    expect(bundled.registry.classify(gmail)).toEqual(fromDisk.registry.classify(gmail));
  });

  it('разбираются один раз и переиспользуются', () => {
    expect(bundledRules()).toBe(bundled);
  });
});
