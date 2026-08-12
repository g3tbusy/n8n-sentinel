import type { GraphEdge, GraphNode } from './types.js';

/**
 * Разобранный воркфлоу: ноды адресуются по имени, у рёбер уже понятно, что они значат для
 * потока данных.
 *
 * Смежность посчитана заранее в обе стороны, потому что каждый следующий анализ ходит по
 * графу многократно и потому что чекеру, объясняющему находку, идти назад от sink приходится
 * не реже, чем вперёд от источника.
 */
export class WorkflowGraph {
  readonly name: string;
  readonly nodes: readonly GraphNode[];
  readonly edges: readonly GraphEdge[];

  readonly #byName: ReadonlyMap<string, GraphNode>;
  readonly #out: ReadonlyMap<string, GraphEdge[]>;
  readonly #in: ReadonlyMap<string, GraphEdge[]>;

  constructor(name: string, nodes: readonly GraphNode[], edges: readonly GraphEdge[]) {
    this.name = name;
    this.nodes = nodes;
    this.edges = edges;

    const byName = new Map<string, GraphNode>();
    for (const n of nodes) byName.set(n.name, n);
    this.#byName = byName;

    const out = new Map<string, GraphEdge[]>();
    const inc = new Map<string, GraphEdge[]>();
    for (const n of nodes) {
      out.set(n.name, []);
      inc.set(n.name, []);
    }
    for (const e of edges) {
      out.get(e.from)?.push(e);
      inc.get(e.to)?.push(e);
    }
    this.#out = out;
    this.#in = inc;
  }

  get size(): number {
    return this.nodes.length;
  }

  has(name: string): boolean {
    return this.#byName.has(name);
  }

  node(name: string): GraphNode | undefined {
    return this.#byName.get(name);
  }

  /** Рёбра, выходящие из `name`. Для неизвестных нод — пустой массив: undefined не возвращается. */
  outgoing(name: string): readonly GraphEdge[] {
    return this.#out.get(name) ?? EMPTY;
  }

  /** Рёбра, входящие в `name`. */
  incoming(name: string): readonly GraphEdge[] {
    return this.#in.get(name) ?? EMPTY;
  }

  /**
   * Ноды, у которых нет рёбер ни в одну сторону.
   *
   * Стикеры — это комментарии на холсте, и они изолированы всегда, поэтому исключены: если
   * их считать, почти любой воркфлоу выглядел бы набитым сиротами.
   */
  isolatedNodes(): readonly GraphNode[] {
    return this.nodes.filter(
      (n) =>
        n.type !== 'n8n-nodes-base.stickyNote' &&
        this.outgoing(n.name).length === 0 &&
        this.incoming(n.name).length === 0,
    );
  }
}

const EMPTY: readonly GraphEdge[] = Object.freeze([]);
