import type { WorkflowGraph } from '../graph/graph.js';
import type { GraphEdge } from '../graph/types.js';
import type { NodeRegistry } from '../rules/registry.js';
import type { Classification, TrustLevel } from '../rules/types.js';
import type { TaintFront, TaintSource, TaintWalk } from './types.js';

/**
 * Распространение taint по разобранному воркфлоу.
 *
 * Форму этого модуля определяют две вещи.
 *
 * **Taint идёт по проходам, а не по простым путям.** Нода может встретиться дважды — агент
 * отдаёт инструменту данные и читает результат обратно, — и это настоящий поток, а не
 * артефакт. Поэтому достижимость считается обычным поиском в ширину, а маршрут-свидетель
 * восстанавливается потом; перечисление путей было бы экспоненциальным по числу инструментов
 * агента и отвечало бы на вопрос, которого никто не задавал.
 *
 * **Taint переносят рёбра всех видов.** `data` и `return` — очевидно. `invocation` — потому
 * что агент составляет аргументы инструмента из того, что лежит у него в контексте, ради чего
 * это выведенное ребро и существует. `attachment` — потому что вывод sub-ноды (ответ модели,
 * память, загруженный документ) оказывается внутри родителя. Виды рёбер нужны здесь ради
 * трассы: читатель, глядя на холст, стрелки `invocation` там не найдёт, поэтому проход обязан
 * сказать, какие рёбра выведены.
 */
export class TaintAnalysis {
  readonly graph: WorkflowGraph;
  readonly sources: readonly TaintSource[];

  readonly #classes: ReadonlyMap<string, Classification>;
  readonly #fronts = new Map<string, TaintFront>();
  #taintedCache: Set<string> | undefined;

  constructor(graph: WorkflowGraph, registry: NodeRegistry) {
    this.graph = graph;

    const classes = new Map<string, Classification>();
    const sources: TaintSource[] = [];
    for (const node of graph.nodes) {
      const c = registry.classify(node);
      classes.set(node.name, c);
      if (c.source) sources.push({ node: node.name, trust: c.source.trust });
    }
    this.#classes = classes;
    this.sources = sources;
  }

  classify(node: string): Classification | undefined {
    return this.#classes.get(node);
  }

  /** Истина для ноды, которая режет taint насмерть: человек одобрил то, что через неё прошло. */
  isStrongGate(node: string): boolean {
    return this.#classes.get(node)?.sanitizer?.strength === 'strong';
  }

  /** Истина для ноды, которая ограничивает проходящее, но никто не подтверждает, что это значит. */
  isWeakGate(node: string): boolean {
    return this.#classes.get(node)?.sanitizer?.strength === 'weak';
  }

  /** Куда добирается taint из `start`. Считается один раз на начальную ноду. */
  front(start: string): TaintFront {
    const cached = this.#fronts.get(start);
    if (cached) return cached;
    const built = this.#propagate(start);
    this.#fronts.set(start, built);
    return built;
  }

  /** Ноды, до которых доходит taint хоть какого-нибудь источника. */
  tainted(): ReadonlySet<string> {
    if (!this.#taintedCache) {
      const all = new Set<string>();
      for (const s of this.sources) {
        all.add(s.node);
        for (const n of this.front(s.node).reached) all.add(n);
      }
      this.#taintedCache = all;
    }
    return this.#taintedCache;
  }

  isTainted(node: string): boolean {
    return this.tainted().has(node);
  }

  /**
   * Источники, чей taint доходит до `node`, худшие первыми.
   *
   * Ведёт уровень доверия, потому что именно из него выводится severity. Остальное — подача:
   * триггер рассказывает историю лучше, чем инструмент, который агент вызвал двумя шагами
   * раньше, а описывают они один и тот же достижимый поток. Каждый чекер берёт точку входа из
   * этого списка, поэтому две находки об одной ноде не могут разойтись в том, откуда пришли
   * данные.
   */
  sourcesReaching(node: string): readonly TaintSource[] {
    const isEntry = (name: string): boolean => this.graph.incoming(name).length === 0;
    return this.sources
      .filter((s) => s.node !== node && this.front(s.node).reached.has(node))
      .sort(
        (a, b) =>
          trustRank(b.trust) - trustRank(a.trust) ||
          Number(isEntry(b.node)) - Number(isEntry(a.node)) ||
          a.node.localeCompare(b.node),
      );
  }

  /**
   * Поиск в ширину из `start`, дважды: один раз пропуская слабые гейты, другой — отказываясь
   * из них выходить. Оба прохода останавливаются на сильных гейтах.
   *
   * Второй проход и делает ответ на вопрос «есть ли маршрут, на котором вообще нет гейтов»
   * точным, а не свойством того маршрута, который случайно нашёлся первым.
   */
  #propagate(start: string): TaintFront {
    const open = this.#walkFrom(start, false);
    const strict = this.#walkFrom(start, true);

    const walkTo = (node: string): TaintWalk | undefined => {
      // Предпочитаем маршрут без гейтов, если он есть: именно им воспользовался бы атакующий,
      // а маршрут с гейтом рядом с severity «гейтов нет» читался бы как ошибка.
      const via = strict.pred.has(node) ? strict.pred : open.pred;
      if (node !== start && !via.has(node)) return undefined;

      const steps: GraphEdge[] = [];
      let cursor = node;
      const guard = new Set<string>();
      while (cursor !== start) {
        const edge = via.get(cursor);
        if (!edge || guard.has(cursor)) break;
        guard.add(cursor);
        steps.push(edge);
        cursor = edge.from;
      }
      steps.reverse();

      const weakGates = steps.map((e) => e.from).filter((n) => n !== start && this.isWeakGate(n));

      return {
        from: start,
        steps,
        weakGates,
        usesDerivedEdge: steps.some((e) => e.derived),
      };
    };

    return { from: start, reached: open.reached, ungated: strict.reached, walkTo };
  }

  #walkFrom(
    start: string,
    stopAtWeakGates: boolean,
  ): { reached: Set<string>; pred: Map<string, GraphEdge> } {
    const reached = new Set<string>();
    const pred = new Map<string, GraphEdge>();
    if (!this.graph.has(start)) return { reached, pred };

    // Очередь, а не стек: тогда первый найденный проход до ноды оказывается и самым коротким,
    // и трассы остаются читаемыми, а не блуждают по всему воркфлоу.
    const queue: string[] = [start];
    const seen = new Set<string>([start]);

    for (let head = 0; head < queue.length; head++) {
      const current = queue[head] as string;

      // Taint сюда приходит, но отсюда не выходит. Человек посмотрел и сказал «да».
      if (this.isStrongGate(current)) continue;
      // Начальная нода — исключение: измеряется как раз проход *из* слабого гейта, и поиск,
      // начинающийся на нём, иначе не вернул бы вообще ничего.
      if (stopAtWeakGates && current !== start && this.isWeakGate(current)) continue;

      for (const edge of this.graph.outgoing(current)) {
        reached.add(edge.to);
        if (seen.has(edge.to)) continue;
        seen.add(edge.to);
        pred.set(edge.to, edge);
        queue.push(edge.to);
      }
    }
    return { reached, pred };
  }
}

/** Сколько атакующему нужно контролировать, чтобы это написать. Используется везде, где ранжируются источники. */
export const trustRank = (trust: TrustLevel): number =>
  trust === 'untrusted-public' ? 3 : trust === 'untrusted-external' ? 2 : 1;

export function analyseTaint(graph: WorkflowGraph, registry: NodeRegistry): TaintAnalysis {
  return new TaintAnalysis(graph, registry);
}
