import type { GraphEdge, TaintAnalysis } from '@n8n-sentinel/core/browser';
import {
  attachmentCurve,
  bottomPort,
  dataCurve,
  inPort,
  outPort,
  selfLoopCurve,
  topPort,
} from './geometry.js';
import type { Curve } from './geometry.js';
import { boundsOf, layout } from './layout.js';
import type { Layout } from './layout.js';
import { edgeKey } from './model.js';
import type { FindingView, Model } from './model.js';

/**
 * Воркфлоу, нарисованный так, каким его последний раз видел автор.
 *
 * Здесь всё определяют два правила. Холст показывает то же, что показывает n8n: те же
 * позиции, то же направление движения, те же связи, — потому что находка это утверждение о
 * воркфлоу самого читателя, и его должно быть можно сверить с редактором. Всё, что добавляет
 * анализ, рисуется *поверх* и явно нашим: выведенная стрелка агент → инструмент, подсветка
 * пути, значки severity. Смешать одно с другим значило бы сделать страницу авторитетом в
 * том, что делает n8n, — а она им не является.
 */

const SVG_NS = 'http://www.w3.org/2000/svg';
const MIN_SCALE = 0.1;
const MAX_SCALE = 2;
const FIT_PADDING = 72;

type Attrs = Record<string, string | number>;

function el<K extends keyof SVGElementTagNameMap>(
  name: K,
  attrs: Attrs = {},
  classes = '',
): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  if (classes !== '') node.setAttribute('class', classes);
  return node;
}

/** Прямоугольник со скруглением по каждому углу отдельно, чтобы триггер был круглым слева. */
function roundedRect(x: number, y: number, w: number, h: number, r: number[]): string {
  const [tl = 0, tr = 0, br = 0, bl = 0] = r;
  return [
    `M${x + tl} ${y}`,
    `H${x + w - tr}`,
    tr > 0 ? `A${tr} ${tr} 0 0 1 ${x + w} ${y + tr}` : '',
    `V${y + h - br}`,
    br > 0 ? `A${br} ${br} 0 0 1 ${x + w - br} ${y + h}` : '',
    `H${x + bl}`,
    bl > 0 ? `A${bl} ${bl} 0 0 1 ${x} ${y + h - bl}` : '',
    `V${y + tl}`,
    tl > 0 ? `A${tl} ${tl} 0 0 1 ${x + tl} ${y}` : '',
    'Z',
  ].join('');
}

/** Две буквы из типа ноды: `httpRequest` → HR, `gmail` → GM. */
export function monogram(type: string): string {
  const last = type.split('.').pop() ?? type;
  const bare = last.replace(/Tool$/, '');
  const words = bare.split(/(?=[A-Z])|[_-]/).filter((word) => word.length > 0);
  const first = words[0] ?? bare;
  const second = words[1];
  const letters =
    second === undefined ? first.slice(0, 2) : `${first.slice(0, 1)}${second.slice(0, 1)}`;
  return letters.toUpperCase() || '?';
}

export function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

/** Чем анализ считает ноду — в виде имени класса. По порядку: побеждает сильнейшее утверждение. */
function roleOf(name: string, taint: TaintAnalysis): string {
  const classification = taint.classify(name);
  if (classification === undefined) return 'role-unknown';
  if (classification.invokesTools) return 'role-agent';
  if (taint.isStrongGate(name)) return 'role-gate-strong';
  if (classification.sink !== undefined) return 'role-sink';
  if (classification.source !== undefined) return 'role-source';
  if (taint.isWeakGate(name)) return 'role-gate';
  if (classification.llm) return 'role-llm';
  if (!classification.known) return 'role-unknown';
  return 'role-plain';
}

interface View {
  scale: number;
  x: number;
  y: number;
}

export interface CanvasOptions {
  readonly onSelectNode?: (name: string | null) => void;
}

export class Canvas {
  readonly #svg: SVGSVGElement;
  readonly #pattern: SVGPatternElement;
  readonly #viewport: SVGGElement;
  readonly #layers: Record<'stickies' | 'edges' | 'nodes' | 'overlay', SVGGElement>;
  readonly #options: CanvasOptions;

  #view: View = { scale: 1, x: 0, y: 0 };
  #layout: Layout | undefined;
  #model: Model | undefined;
  #curves = new Map<string, Curve>();

  constructor(svg: SVGSVGElement, options: CanvasOptions = {}) {
    this.#svg = svg;
    this.#options = options;

    const defs = el('defs');
    this.#pattern = el('pattern', {
      id: 'canvas-dots',
      width: 16,
      height: 16,
      patternUnits: 'userSpaceOnUse',
    });
    this.#pattern.append(el('circle', { cx: 1, cy: 1, r: 1 }, 'dot'));
    defs.append(this.#pattern, arrowMarker('arrow'), arrowMarker('arrow-hot'));

    const backdrop = el('rect', {
      x: 0,
      y: 0,
      width: '100%',
      height: '100%',
      fill: 'url(#canvas-dots)',
    });

    this.#viewport = el('g', {}, 'viewport');
    this.#layers = {
      stickies: el('g', {}, 'layer-stickies'),
      edges: el('g', {}, 'layer-edges'),
      nodes: el('g', {}, 'layer-nodes'),
      overlay: el('g', {}, 'layer-overlay'),
    };
    this.#viewport.append(
      this.#layers.stickies,
      this.#layers.edges,
      this.#layers.nodes,
      this.#layers.overlay,
    );
    svg.append(defs, backdrop, this.#viewport);

    this.#bindPointer();
  }

  render(model: Model): void {
    this.#model = model;
    this.#layout = layout(model.result.graph);
    this.#curves = new Map();

    for (const layer of Object.values(this.#layers)) layer.replaceChildren();
    this.#drawStickies();
    this.#drawEdges();
    this.#drawNodes();
    this.highlight(null);
    this.fit();
  }

  clear(): void {
    this.#model = undefined;
    this.#layout = undefined;
    for (const layer of Object.values(this.#layers)) layer.replaceChildren();
  }

  // ---------------------------------------------------------------- отрисовка

  #drawStickies(): void {
    for (const placed of this.#layout?.placed ?? []) {
      if (placed.shape !== 'sticky') continue;
      const group = el('g', {}, 'sticky');
      group.append(
        el('rect', { x: placed.x, y: placed.y, width: placed.w, height: placed.h, rx: 8 }),
      );
      const content = placed.node.parameters['content'];
      if (typeof content === 'string') {
        const lines = content
          .split('\n')
          .map((line) => line.replace(/^#+\s*/, '').trim())
          .filter((line) => line.length > 0)
          .slice(0, Math.max(1, Math.floor((placed.h - 16) / 18)));
        lines.forEach((line, index) => {
          const text = el('text', { x: placed.x + 12, y: placed.y + 26 + index * 18 });
          text.textContent = truncate(line, Math.max(8, Math.floor(placed.w / 7)));
          group.append(text);
        });
      }
      this.#layers.stickies.append(group);
    }
  }

  #drawEdges(): void {
    const layoutNow = this.#layout;
    const graph = this.#model?.result.graph;
    if (layoutNow === undefined || graph === undefined) return;

    const outputs = new Map<string, number>();
    const inputs = new Map<string, number>();
    for (const edge of graph.edges) {
      if (edge.kind !== 'data') continue;
      outputs.set(edge.from, Math.max(outputs.get(edge.from) ?? 0, edge.slot + 1));
      inputs.set(edge.to, Math.max(inputs.get(edge.to) ?? 0, edge.index + 1));
    }

    for (const edge of graph.edges) {
      // Ребро агент → инструмент наше, а не n8n. Оно рисуется, когда его использует путь, в
      // слое поверх и с подписью — и никогда не подмешивается в картину того, что показывает
      // редактор.
      if (edge.kind === 'invocation') continue;

      const curve = this.#curveFor(edge, outputs, inputs);
      if (curve === undefined) continue;
      this.#curves.set(edgeKey(edge), curve);

      const path = el(
        'path',
        { d: curve.d, 'marker-end': 'url(#arrow)' },
        `edge kind-${edge.kind}`,
      );
      path.dataset['key'] = edgeKey(edge);
      this.#layers.edges.append(path);
    }
  }

  #curveFor(
    edge: GraphEdge,
    outputs: ReadonlyMap<string, number>,
    inputs: ReadonlyMap<string, number>,
  ): Curve | undefined {
    const from = this.#layout?.byName.get(edge.from);
    const to = this.#layout?.byName.get(edge.to);
    if (from === undefined || to === undefined) return undefined;

    if (edge.from === edge.to) return selfLoopCurve(from);
    if (edge.kind === 'data') {
      return dataCurve(
        outPort(from, edge.slot, outputs.get(edge.from) ?? 1),
        inPort(to, edge.index, inputs.get(edge.to) ?? 1),
      );
    }
    // Sub-нода в AI-ноду, которую она кормит: вверх от её верхнего края в низ родителя.
    return attachmentCurve(topPort(from), bottomPort(to, from));
  }

  #drawNodes(): void {
    const model = this.#model;
    if (model === undefined) return;

    for (const placed of this.#layout?.placed ?? []) {
      if (placed.shape === 'sticky') continue;
      const name = placed.node.name;
      const group = el('g', {}, `node ${roleOf(name, model.result.taint)} shape-${placed.shape}`);
      group.dataset['name'] = name;
      group.setAttribute('tabindex', '0');
      group.setAttribute('role', 'button');

      const radius = placed.shape === 'trigger' ? [8, 12, 12, 8] : [12, 12, 12, 12];
      if (placed.shape === 'trigger') {
        radius[0] = placed.h / 2;
        radius[3] = placed.h / 2;
      }
      group.append(
        el('path', { d: roundedRect(placed.x, placed.y, placed.w, placed.h, radius) }, 'node-body'),
      );

      const mark = el(
        'text',
        { x: placed.x + placed.w / 2, y: placed.y + placed.h / 2 },
        'node-monogram',
      );
      mark.textContent = monogram(placed.node.type);
      group.append(mark);

      if (placed.node.disabled) {
        group.classList.add('is-disabled');
      }

      const label = el(
        'text',
        { x: placed.x + placed.w / 2, y: placed.y + placed.h + 18 },
        'node-label',
      );
      // Sub-ноды стоят плечом к плечу под родителем, поэтому их подписи получают ту ширину,
      // которая у них есть на самом деле, а не ширину обычной ноды.
      label.textContent = truncate(name, placed.shape === 'sub' ? 13 : 22);
      group.append(label);

      const worst = model.worstByNode.get(name);
      if (worst !== undefined) {
        group.append(
          el(
            'circle',
            { cx: placed.x + placed.w - 6, cy: placed.y + 6, r: 6 },
            `node-badge severity-${worst}`,
          ),
        );
      }

      const title = el('title');
      title.textContent = `${name}\n${placed.node.type}`;
      group.append(title);

      group.addEventListener('click', (event) => {
        event.stopPropagation();
        this.#options.onSelectNode?.(name);
      });
      group.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          this.#options.onSelectNode?.(name);
        }
      });

      this.#layers.nodes.append(group);
    }
  }

  // ------------------------------------------------------------- подсветка

  highlight(view: FindingView | null): void {
    this.#layers.overlay.replaceChildren();
    this.#svg.classList.toggle('has-selection', view !== null);

    for (const node of this.#layers.nodes.children) {
      const name = (node as SVGGElement).dataset['name'] ?? '';
      node.classList.toggle('is-hot', view?.nodes.has(name) === true);
      node.classList.toggle(
        'is-end',
        view !== null && (view.finding.source.node === name || view.finding.sink.node === name),
      );
    }

    for (const path of this.#layers.edges.children) {
      const key = (path as SVGPathElement).dataset['key'] ?? '';
      path.classList.toggle('is-hot', view?.edges.has(key) === true);
    }

    if (view === null) return;

    const severity = `severity-${view.finding.severity}`;
    for (const step of view.finding.trace) {
      const key = edgeKey(step);
      let curve = this.#curves.get(key);

      if (step.derived) {
        // На холсте этого нет, а читатель пойдёт искать именно там. Рисуется как наше:
        // пунктиром, со стрелкой в сторону инструмента, с подписью.
        curve = this.#derivedCurve(step.from, step.to);
        if (curve === undefined) continue;
        this.#layers.overlay.append(
          el(
            'path',
            { d: curve.d, 'marker-end': 'url(#arrow-hot)' },
            `overlay-edge is-derived ${severity}`,
          ),
        );
        const label = el('text', { x: curve.mid.x, y: curve.mid.y - 6 }, 'overlay-label');
        label.textContent = 'выведено: этот вызывает агент';
        this.#layers.overlay.append(label);
        continue;
      }

      if (curve === undefined) continue;
      this.#layers.overlay.append(
        el('path', { d: curve.d }, `overlay-edge is-flowing ${severity}`),
      );
    }
  }

  #derivedCurve(from: string, to: string): Curve | undefined {
    const parent = this.#layout?.byName.get(from);
    const tool = this.#layout?.byName.get(to);
    if (parent === undefined || tool === undefined) return undefined;
    return attachmentCurve(bottomPort(parent, tool), topPort(tool));
  }

  // ------------------------------------------------------------ управление видом

  fit(): void {
    const box = this.#svg.getBoundingClientRect();
    const all = this.#layout?.placed ?? [];
    // Стикеры часто в несколько раз больше графа, который поясняют, и подгонка под них
    // сжимает ноды в точки. Рисоваться они продолжают — просто не имеют права голоса.
    const nodes = all.filter((item) => item.shape !== 'sticky');
    const placed = nodes.length > 0 ? nodes : all;
    if (placed.length === 0 || box.width === 0) return;

    const bounds = boundsOf(placed);
    const width = Math.max(bounds.maxX - bounds.minX, 1);
    // Подписи стоят под нодами; оставляем место, чтобы нижний ряд не обрезался.
    const height = Math.max(bounds.maxY - bounds.minY + 28, 1);
    // Пропорционально, иначе телефон тратит треть экрана на поля.
    const pad = Math.min(FIT_PADDING, box.width * 0.06, box.height * 0.06);
    const scale = Math.min(
      MAX_SCALE,
      Math.max(MIN_SCALE, Math.min((box.width - pad * 2) / width, (box.height - pad * 2) / height)),
    );
    this.#apply({
      scale,
      x: (box.width - width * scale) / 2 - bounds.minX * scale,
      y: (box.height - height * scale) / 2 - bounds.minY * scale,
    });
  }

  zoomBy(factor: number): void {
    const box = this.#svg.getBoundingClientRect();
    this.#zoomAround(box.width / 2, box.height / 2, factor);
  }

  /** Центрирует ноду, не меняя масштаб, чтобы читатель не терял ориентиров. */
  focus(name: string): void {
    const placed = this.#layout?.byName.get(name);
    const box = this.#svg.getBoundingClientRect();
    if (placed === undefined || box.width === 0) return;
    const { scale } = this.#view;
    this.#apply({
      scale,
      x: box.width / 2 - (placed.x + placed.w / 2) * scale,
      y: box.height / 2 - (placed.y + placed.h / 2) * scale,
    });
    const group = this.#layers.nodes.querySelector(`[data-name="${cssEscape(name)}"]`);
    group?.classList.add('is-focused');
    globalThis.setTimeout(() => group?.classList.remove('is-focused'), 900);
  }

  #zoomAround(px: number, py: number, factor: number): void {
    const { scale, x, y } = this.#view;
    const next = Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale * factor));
    const ratio = next / scale;
    this.#apply({ scale: next, x: px - (px - x) * ratio, y: py - (py - y) * ratio });
  }

  #apply(view: View): void {
    this.#view = view;
    this.#viewport.setAttribute('transform', `translate(${view.x} ${view.y}) scale(${view.scale})`);
    this.#pattern.setAttribute(
      'patternTransform',
      `translate(${view.x} ${view.y}) scale(${view.scale})`,
    );
  }

  #bindPointer(): void {
    let dragging: { id: number; x: number; y: number } | undefined;

    this.#svg.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      dragging = { id: event.pointerId, x: event.clientX, y: event.clientY };
      this.#svg.setPointerCapture(event.pointerId);
      this.#svg.classList.add('is-panning');
    });

    this.#svg.addEventListener('pointermove', (event) => {
      if (dragging === undefined || dragging.id !== event.pointerId) return;
      const dx = event.clientX - dragging.x;
      const dy = event.clientY - dragging.y;
      dragging = { id: event.pointerId, x: event.clientX, y: event.clientY };
      this.#apply({ ...this.#view, x: this.#view.x + dx, y: this.#view.y + dy });
    });

    const stop = (event: PointerEvent): void => {
      if (dragging?.id !== event.pointerId) return;
      dragging = undefined;
      this.#svg.classList.remove('is-panning');
    };
    this.#svg.addEventListener('pointerup', stop);
    this.#svg.addEventListener('pointercancel', stop);

    this.#svg.addEventListener('click', (event) => {
      if (event.target === this.#svg || (event.target as Element).tagName === 'rect') {
        this.#options.onSelectNode?.(null);
      }
    });

    this.#svg.addEventListener(
      'wheel',
      (event) => {
        event.preventDefault();
        const box = this.#svg.getBoundingClientRect();
        const factor = Math.exp(-event.deltaY * 0.0015);
        this.#zoomAround(event.clientX - box.left, event.clientY - box.top, factor);
      },
      { passive: false },
    );
  }
}

function arrowMarker(id: string): SVGMarkerElement {
  const marker = el('marker', {
    id,
    viewBox: '0 0 10 10',
    refX: 9,
    refY: 5,
    markerWidth: 5,
    markerHeight: 5,
    orient: 'auto-start-reverse',
  });
  marker.append(el('path', { d: 'M0 1L9 5L0 9z' }));
  return marker;
}

/** В именах нод достаточно часто встречаются кавычки и скобки, чтобы это влияло на селектор. */
function cssEscape(value: string): string {
  const escape = (CSS as { escape?: (value: string) => string }).escape;
  return escape === undefined ? value.replace(/["\\]/g, '\\$&') : escape(value);
}
