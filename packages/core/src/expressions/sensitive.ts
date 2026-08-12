import type { GraphNode } from '../graph/types.js';
import { findExpressions, readString } from './parse.js';
import type { FoundExpression } from './parse.js';

/** Что решает содержимое параметра. По одному на каждую позицию инъекции, достойную имени. */
export type ParamKind = 'url' | 'egress-payload' | 'sql' | 'command' | 'code';

export interface SensitiveParamRule {
  readonly kind: ParamKind;
  readonly paths: readonly string[];
  readonly types: readonly string[];
}

export interface SensitiveParamFile {
  readonly params: readonly SensitiveParamRule[];
}

/**
 * Смотрит, какие параметры ноды являются позициями инъекции.
 *
 * По типу ноды, а не по имени параметра: `query` у ноды Postgres — это SQL, а `query` у
 * поискового инструмента Tavily — это поисковый запрос. Шесть параметров `query` в корпусе
 * относятся ко второму виду, и правило по одному имени показало бы их как SQL-инъекцию.
 */
export class SensitiveParams {
  readonly #byType: ReadonlyMap<string, ReadonlyMap<string, ParamKind>>;

  constructor(file: SensitiveParamFile) {
    const byType = new Map<string, Map<string, ParamKind>>();
    for (const rule of file.params) {
      for (const type of rule.types) {
        let paths = byType.get(type);
        if (!paths) {
          paths = new Map<string, ParamKind>();
          byType.set(type, paths);
        }
        for (const path of rule.paths) paths.set(path, rule.kind);
      }
    }
    this.#byType = byType;
  }

  /** Все типы нод, упомянутые хоть каким-то правилом; тест целостности сверяет их с n8n. */
  types(): readonly string[] {
    return [...this.#byType.keys()];
  }

  kindOf(nodeType: string, path: string): ParamKind | undefined {
    return this.#byType.get(nodeType)?.get(path);
  }

  /** Выражения этой ноды, попадающие туда, где содержимое решает, что произойдёт. */
  expressionsIn(node: GraphNode): { kind: ParamKind; found: FoundExpression }[] {
    const paths = this.#byType.get(node.type);
    if (!paths) return [];

    const hits: { kind: ParamKind; found: FoundExpression }[] = [];
    for (const found of findExpressions(node.parameters)) {
      const kind = paths.get(found.path);
      if (kind !== undefined && kind !== 'code') hits.push({ kind, found });
    }
    return hits;
  }

  /**
   * Тела кода, прочитанные как текст.
   *
   * `jsCode` у ноды Code — не выражение, а JavaScript, который сам читает `$json`, поэтому в
   * `expressionsIn` он никогда не попадает и его приходится доставать напрямую.
   */
  codeIn(node: GraphNode): { path: string; code: string }[] {
    const paths = this.#byType.get(node.type);
    if (!paths) return [];

    const bodies: { path: string; code: string }[] = [];
    for (const [path, kind] of paths) {
      if (kind !== 'code') continue;
      const code = readString(node.parameters, path);
      if (code !== undefined && code !== '') bodies.push({ path, code });
    }
    return bodies;
  }
}
