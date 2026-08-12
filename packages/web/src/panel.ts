import type { Finding, ParseWarning, Severity, TraceStep } from '@n8n-sentinel/core/browser';
import { routeCount } from './model.js';
import type { FindingView, Model } from './model.js';

/**
 * Список рядом с холстом.
 *
 * Всё строится через `textContent` и никогда через `innerHTML`. Страница отрисовывает строки,
 * пришедшие из чьего-то воркфлоу: имена нод, промпты, стикеры, URL, который атакующий
 * положил в письмо, — и сканер, выполняющий то, что он сканирует, был бы плохой шуткой.
 */

const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

type Attrs = { readonly class?: string; readonly text?: string; readonly title?: string };

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: readonly Node[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (attrs.class !== undefined) node.className = attrs.class;
  if (attrs.text !== undefined) node.textContent = attrs.text;
  if (attrs.title !== undefined) node.title = attrs.title;
  node.append(...children);
  return node;
}

export interface PanelOptions {
  readonly onSelect: (view: FindingView | null) => void;
  readonly onFocusNode: (name: string) => void;
}

export class Panel {
  readonly #root: HTMLElement;
  readonly #options: PanelOptions;
  #model: Model | undefined;
  #selected: string | undefined;

  constructor(root: HTMLElement, options: PanelOptions) {
    this.#root = root;
    this.#options = options;
  }

  render(model: Model): void {
    this.#model = model;
    this.#selected = undefined;
    this.#draw();
  }

  /**
   * `scroll` выключен, когда находку выбрала сама страница. Прокрутка при загрузке оставляет
   * читателя посреди объяснения к тому, названия чего ему ещё не сказали.
   */
  select(id: string | undefined, options: { readonly scroll?: boolean } = {}): void {
    this.#selected = id;
    this.#draw();
    if (id !== undefined && options.scroll === true) {
      this.#root
        .querySelector(`[data-finding="${id}"]`)
        ?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }

  get selectedId(): string | undefined {
    return this.#selected;
  }

  clear(): void {
    this.#model = undefined;
    this.#selected = undefined;
    this.#root.replaceChildren();
  }

  #draw(): void {
    const model = this.#model;
    if (model === undefined) return;

    const sections: Node[] = [this.#summary(model)];

    if (model.result.warnings.length > 0) sections.push(warnings(model.result.warnings));

    if (model.findings.length === 0) {
      sections.push(
        h('div', { class: 'panel-clean' }, [
          h('h2', { text: 'Ничего не найдено' }),
          h('p', {
            text:
              'Ни один путь в этом воркфлоу не ведёт данные извне до действия — либо каждый ' +
              'из них проходит через то, что его останавливает.',
          }),
        ]),
      );
    } else {
      sections.push(this.#list(model));
    }

    this.#root.replaceChildren(...sections);
  }

  #summary(model: Model): HTMLElement {
    const counts = SEVERITIES.filter((severity) => model.counts[severity] > 0).map((severity) =>
      h('span', { class: `count severity-${severity}` }, [
        h('b', { text: String(model.counts[severity]) }),
        h('span', { text: severity }),
      ]),
    );

    const nodes = model.result.graph.nodes.length;
    return h('header', { class: 'panel-head' }, [
      h('div', { class: 'counts' }, counts.length > 0 ? counts : [h('span', { text: 'чисто' })]),
      h('p', {
        class: 'panel-sub',
        text: `нод: ${nodes}, связей: ${model.result.graph.edges.length}`,
      }),
    ]);
  }

  #list(model: Model): HTMLElement {
    const list = h('ol', { class: 'findings' });

    for (const view of model.findings) {
      const { finding } = view;
      const open = this.#selected === view.id;

      const row = h('li', { class: `finding${open ? ' is-open' : ''}` });
      row.dataset['finding'] = view.id;

      const button = h('button', { class: 'finding-head' }, [
        h('span', { class: `chip severity-${finding.severity}`, text: finding.severity }),
        h('span', { class: 'finding-rule', text: finding.rule }),
        ...(finding.confidence === 'uncertain'
          ? [
              h('span', {
                class: 'chip muted',
                text: 'не прослежено',
                title: 'Путь уходит за пределы того, что видит этот анализ.',
              }),
            ]
          : []),
        h('span', { class: 'finding-title', text: finding.title }),
      ]);
      button.type = 'button';
      button.addEventListener('click', () => {
        this.#options.onSelect(open ? null : view);
      });

      row.append(button);
      if (open) row.append(this.#detail(model, view));
      list.append(row);
    }
    return list;
  }

  #detail(model: Model, view: FindingView): HTMLElement {
    const { finding } = view;
    const parts: Node[] = [
      h('p', { class: 'detail-text', text: finding.detail }),
      h('div', { class: 'remediation' }, [
        h('h3', { text: 'Что делать' }),
        h('p', { text: finding.remediation }),
      ]),
      h('div', { class: 'trace' }, [h('h3', { text: 'Путь' }), this.#traceChain(finding)]),
    ];

    const facts: string[] = [];
    if (finding.weakGates.length > 0) {
      facts.push(
        `Проходит через ${finding.weakGates.join(', ')} — это гейт, только если он проверяет заражённое значение, поэтому severity снижается, но не снимается.`,
      );
    }
    if (finding.otherSources.length > 0) {
      const shown = finding.otherSources.slice(0, 4).join(', ');
      const rest = finding.otherSources.length - 4;
      facts.push(
        `До того же места доходят ещё источники (${finding.otherSources.length}): ${shown}${rest > 0 ? `, и ещё ${rest}` : ''}.`,
      );
    }
    for (const note of finding.notes) facts.push(note);

    const routes = routeCount(model.result.graph, finding);
    if (routes > 1) {
      facts.push(
        `От этого источника до этого действия ведут ${routes >= 4 ? 'минимум четыре' : String(routes)} разных маршрута.`,
      );
    }

    if (facts.length > 0) {
      parts.push(
        h(
          'ul',
          { class: 'facts' },
          facts.map((fact) => h('li', { text: fact })),
        ),
      );
    }

    return h('div', { class: 'finding-detail' }, parts);
  }

  #traceChain(finding: Finding): HTMLElement {
    const chain = h('div', { class: 'chain' });
    const names = [finding.trace[0]?.from ?? finding.source.node];
    for (const step of finding.trace) names.push(step.to);

    names.forEach((name, index) => {
      if (index > 0) {
        const step = finding.trace[index - 1] as TraceStep;
        chain.append(
          h('span', {
            class: `arrow kind-${step.kind}${step.derived ? ' is-derived' : ''}`,
            text: step.derived ? '⇢' : '→',
            title: step.derived
              ? `${step.kind}: выведено парсером, на холсте n8n не нарисовано`
              : step.kind,
          }),
        );
      }
      const chip = h('button', { class: 'node-chip', text: name });
      chip.type = 'button';
      if (name === finding.source.node) chip.classList.add('is-source');
      if (name === finding.sink.node) chip.classList.add('is-sink');
      if (name === finding.agent) chip.classList.add('is-agent');
      chip.addEventListener('click', () => this.#options.onFocusNode(name));
      chain.append(chip);
    });

    return chain;
  }
}

function warnings(list: readonly ParseWarning[]): HTMLElement {
  return h('div', { class: 'warnings' }, [
    h('h3', { text: `Что не так с документом (${list.length})` }),
    h(
      'ul',
      {},
      list.map((warning) => h('li', { text: `${warning.code}: ${warning.message}` })),
    ),
  ]);
}
