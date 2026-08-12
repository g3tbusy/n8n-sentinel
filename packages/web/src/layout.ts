import type { GraphNode, WorkflowGraph } from '@n8n-sentinel/core/browser';

/**
 * Где рисовать каждую ноду.
 *
 * Документ это уже говорит. n8n хранит `position` у каждой ноды, поэтому честная раскладка —
 * та, которую расставил автор: читатель может положить эту страницу рядом с редактором и
 * сверить находку с холстом, который знает. Выдумывать раскладку там, где она есть, значило
 * бы превращать каждую трассу в спор о том, тот ли это вообще воркфлоу.
 *
 * Размеры ниже измерены, а не угаданы: 69,7% из 768 позиций нод в `fixtures/real` кратны 16
 * против 52% для 20, значит сетка редактора — 16, а медианный промежуток между двумя
 * связанными нодами — 224, то есть четырнадцать клеток: две ширины ноды и зазор. Сама нода —
 * шесть клеток в квадрате.
 */

export const GRID = 16;
export const NODE_SIZE = 6 * GRID;
export const SUB_NODE_SIZE = 4.5 * GRID;
export const STICKY_DEFAULT = { width: 240, height: 160 };

/** Используется, только когда документ не даёт собственных позиций. */
export const FALLBACK_LANE = 14 * GRID;
export const FALLBACK_ROW = 10 * GRID;

export type NodeShape =
  /** Скруглена слева — так n8n рисует всё, с чего начинается запуск. */
  | 'trigger'
  /** Обычная квадратная нода. */
  | 'node'
  /** Модель, память, инструмент или парсер, подвешенные к AI-ноде: меньше и рисуются под ней. */
  | 'sub'
  /** Комментарий на холсте. К анализу отношения не имеет, но входит в то, что видит автор. */
  | 'sticky';

export interface Placed {
  readonly node: GraphNode;
  readonly x: number;
  readonly y: number;
  readonly w: number;
  readonly h: number;
  readonly shape: NodeShape;
}

export interface Bounds {
  readonly minX: number;
  readonly minY: number;
  readonly maxX: number;
  readonly maxY: number;
}

export interface Layout {
  readonly placed: readonly Placed[];
  readonly byName: ReadonlyMap<string, Placed>;
  readonly bounds: Bounds;
  /** Ноды, которым документ не дал пригодной позиции, так что раскладка её выдумала. */
  readonly invented: readonly string[];
}

const STICKY_TYPE = 'n8n-nodes-base.stickyNote';

/**
 * n8n даёт ноде скруглённую форму триггера, когда её описание объявляет группу trigger, — а
 * этого в документе воркфлоу нет. Зато есть имя: каждый тип триггера в корпусе заканчивается
 * на `Trigger`, плюс четыре исторических, которые нет.
 */
const TRIGGER_TYPE = /(?:Trigger|\.(?:webhook|start|cron|interval))$/i;

function isTrigger(node: GraphNode, graph: WorkflowGraph): boolean {
  if (!TRIGGER_TYPE.test(node.type)) return false;
  return !graph.incoming(node.name).some((edge) => edge.kind === 'data');
}

/** Sub-нода это та, что кормит AI-ноду, а не передаёт элементы дальше по потоку. */
function isSubNode(node: GraphNode, graph: WorkflowGraph): boolean {
  return graph
    .outgoing(node.name)
    .some((edge) => edge.kind === 'attachment' || edge.kind === 'return');
}

function shapeOf(node: GraphNode, graph: WorkflowGraph): NodeShape {
  if (node.type === STICKY_TYPE) return 'sticky';
  if (isTrigger(node, graph)) return 'trigger';
  if (isSubNode(node, graph)) return 'sub';
  return 'node';
}

function sizeOf(node: GraphNode, shape: NodeShape): { w: number; h: number } {
  if (shape === 'sticky') {
    const height = node.parameters['height'];
    const width = node.parameters['width'];
    return {
      w: typeof width === 'number' && width > 0 ? width : STICKY_DEFAULT.width,
      h: typeof height === 'number' && height > 0 ? height : STICKY_DEFAULT.height,
    };
  }
  const side = shape === 'sub' ? SUB_NODE_SIZE : NODE_SIZE;
  return { w: side, h: side };
}

function storedPosition(node: GraphNode): { x: number; y: number } | undefined {
  const position = node.raw.position;
  if (!Array.isArray(position) || position.length < 2) return undefined;
  const [x, y] = position;
  if (typeof x !== 'number' || typeof y !== 'number') return undefined;
  if (!Number.isFinite(x) || !Number.isFinite(y)) return undefined;
  return { x, y };
}

/**
 * Глубина от нод, с которых начинается запуск, — только по потоку элементов.
 *
 * Релаксация, а не топологическая сортировка: у 237 из 794 воркфлоу выборки есть цикл, а
 * сортировке его некуда деть. Каждый проход способен только сдвинуть ноду правее, а число
 * проходов ограничено, поэтому петля устаканивается, а не крутится.
 */
function depths(graph: WorkflowGraph): Map<string, number> {
  const depth = new Map<string, number>(graph.nodes.map((node) => [node.name, 0]));
  const dataEdges = graph.edges.filter((edge) => edge.kind === 'data');

  for (let pass = 0; pass < graph.nodes.length; pass += 1) {
    let moved = false;
    for (const edge of dataEdges) {
      const from = depth.get(edge.from);
      const to = depth.get(edge.to);
      if (from === undefined || to === undefined) continue;
      if (to < from + 1) {
        depth.set(edge.to, from + 1);
        moved = true;
      }
    }
    if (!moved) break;
  }
  return depth;
}

/** Раскладка «колонка на глубину» — для документов, в которых позиций нет вовсе. */
function invent(
  graph: WorkflowGraph,
  shapes: ReadonlyMap<string, NodeShape>,
): Map<string, { x: number; y: number }> {
  const depth = depths(graph);
  const rows = new Map<number, number>();
  const positions = new Map<string, { x: number; y: number }>();

  // Sub-ноды идут под то, что они кормят, поэтому размещаются после родителя.
  const ordered = [...graph.nodes].sort((a, b) => {
    const aSub = shapes.get(a.name) === 'sub' ? 1 : 0;
    const bSub = shapes.get(b.name) === 'sub' ? 1 : 0;
    return aSub - bSub || (depth.get(a.name) ?? 0) - (depth.get(b.name) ?? 0);
  });

  for (const node of ordered) {
    if (shapes.get(node.name) === 'sub') {
      const parent = graph
        .outgoing(node.name)
        .find((edge) => edge.kind === 'attachment' || edge.kind === 'return');
      const at = parent === undefined ? undefined : positions.get(parent.to);
      if (at !== undefined) {
        const siblings = graph
          .incoming(parent?.to ?? '')
          .filter((edge) => edge.kind === 'attachment' || edge.kind === 'return')
          .map((edge) => edge.from);
        const index = Math.max(0, siblings.indexOf(node.name));
        positions.set(node.name, {
          x: at.x + index * (SUB_NODE_SIZE + GRID) - (NODE_SIZE - SUB_NODE_SIZE) / 2,
          y: at.y + NODE_SIZE + 3 * GRID,
        });
        continue;
      }
    }

    const column = depth.get(node.name) ?? 0;
    const row = rows.get(column) ?? 0;
    rows.set(column, row + 1);
    positions.set(node.name, { x: column * FALLBACK_LANE, y: row * FALLBACK_ROW });
  }
  return positions;
}

export function layout(graph: WorkflowGraph): Layout {
  const shapes = new Map(graph.nodes.map((node) => [node.name, shapeOf(node, graph)]));
  const stored = new Map<string, { x: number; y: number }>();
  for (const node of graph.nodes) {
    const at = storedPosition(node);
    if (at !== undefined) stored.set(node.name, at);
  }

  const invented: string[] = [];
  let fallback: Map<string, { x: number; y: number }> | undefined;

  if (stored.size < graph.nodes.length) {
    fallback = invent(graph, shapes);
    if (stored.size > 0) {
      // Часть позиций настоящие. Оставляем их, а остальное опускаем ниже, чтобы ничто
      // расставленное автором не сдвинулось и ничто выдуманное не легло сверху.
      const bottom = Math.max(...[...stored.values()].map((at) => at.y)) + NODE_SIZE + 4 * GRID;
      for (const [name, at] of fallback) fallback.set(name, { x: at.x, y: at.y + bottom });
    }
  }

  const placed: Placed[] = [];
  for (const node of graph.nodes) {
    const shape = shapes.get(node.name) ?? 'node';
    const at = stored.get(node.name) ?? fallback?.get(node.name) ?? { x: 0, y: 0 };
    if (!stored.has(node.name)) invented.push(node.name);
    placed.push({ node, ...at, ...sizeOf(node, shape), shape });
  }

  // Стикеры — мебель холста, и рисуются позади всего остального.
  placed.sort((a, b) => (a.shape === 'sticky' ? 0 : 1) - (b.shape === 'sticky' ? 0 : 1));

  return {
    placed,
    byName: new Map(placed.map((item) => [item.node.name, item])),
    bounds: boundsOf(placed),
    invented,
  };
}

export function boundsOf(placed: readonly Placed[]): Bounds {
  if (placed.length === 0) return { minX: 0, minY: 0, maxX: NODE_SIZE, maxY: NODE_SIZE };
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const item of placed) {
    minX = Math.min(minX, item.x);
    minY = Math.min(minY, item.y);
    maxX = Math.max(maxX, item.x + item.w);
    maxY = Math.max(maxY, item.y + item.h);
  }
  return { minX, minY, maxX, maxY };
}
