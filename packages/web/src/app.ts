import { analyseWorkflow } from '@n8n-sentinel/core/browser';
import { Canvas } from './canvas.js';
import { DEMOS } from './demo.js';
import { buildModel } from './model.js';
import type { FindingView, Model } from './model.js';
import { Panel } from './panel.js';
import { bundledRules } from './rules.js';

/**
 * Проводка: принять документ, проанализировать его и удерживать холст и список в согласии о
 * том, что выбрано.
 *
 * Ничто здесь не ходит в сеть, а собранной странице выдаётся Content-Security-Policy, который
 * отказал бы, если бы она попыталась. В этом смысл всей затеи ровно в той же мере, что и в
 * анализе: люди не станут вставлять в чужой веб-сервис воркфлоу, где лежат названия их
 * доступов, адреса их клиентов и их промпты, — и не должны.
 */

function need<T extends Element>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`missing element #${id}`);
  // `getElementById` типизирован как HTMLElement, а <svg> им не является. Идентификатор
  // лежит в странице по соседству; если однажды не будет — исключение выше назовёт какой.
  return element as unknown as T;
}

export function start(): void {
  const stage = need<HTMLElement>('stage');
  const empty = need<HTMLElement>('empty');
  const dropzone = need<HTMLElement>('dropzone');
  const workflowName = need<HTMLElement>('workflow-name');
  const workflowMeta = need<HTMLElement>('workflow-meta');
  const fileInput = need<HTMLInputElement>('file');
  const demoSelect = need<HTMLSelectElement>('demo');

  let model: Model | undefined;

  const canvas = new Canvas(need<SVGSVGElement>('canvas'), {
    onSelectNode: (name) => {
      if (name === null) {
        select(null);
        return;
      }
      const touching = model?.findings.find(
        (view) => view.finding.source.node === name || view.finding.sink.node === name,
      );
      select(touching ?? model?.findings.find((view) => view.nodes.has(name)) ?? null);
    },
  });

  const panel = new Panel(need<HTMLElement>('panel'), {
    onSelect: (view) => select(view),
    onFocusNode: (name) => canvas.focus(name),
  });

  function select(view: FindingView | null, scroll = true): void {
    panel.select(view?.id, { scroll });
    canvas.highlight(view);
  }

  function show(document_: unknown, label: string, note: string): void {
    const result = analyseWorkflow(document_, bundledRules());
    model = buildModel(result);

    workflowName.textContent = result.workflow === '' ? label : result.workflow;
    workflowMeta.textContent = note;
    empty.hidden = true;
    stage.classList.remove('has-error');

    canvas.render(model);
    panel.render(model);

    // Приземляемся на худший путь, а не на серый граф. Странице есть что сказать о воркфлоу
    // ровно одну вещь, и заставлять читателя её искать значит потратить единственный момент,
    // когда он точно смотрит. Escape или клик по холсту снимают выделение.
    const worst = model.findings[0];
    if (worst !== undefined) select(worst, false);
  }

  function fail(message: string): void {
    model = undefined;
    canvas.clear();
    panel.clear();
    stage.classList.add('has-error');
    empty.hidden = false;
    empty.replaceChildren(
      Object.assign(document.createElement('h1'), { textContent: 'Это не воркфлоу' }),
      Object.assign(document.createElement('p'), { textContent: message }),
    );
  }

  function load(text: string, label: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      fail(
        `Файл не является корректным JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
      return;
    }

    // `n8n export:workflow --all` пишет массив. Берём первый и говорим об этом, вместо того
    // чтобы показать пустой холст для файла, который очевидно полон воркфлоу.
    if (Array.isArray(parsed)) {
      const first: unknown = parsed[0];
      if (first === undefined) {
        fail('Файл — пустой список.');
        return;
      }
      show(first, label, `${label} — первый из ${parsed.length} воркфлоу в файле`);
      return;
    }
    show(parsed, label, label);
  }

  // ------------------------------------------------------------------ ввод

  for (const demo of DEMOS) {
    const option = document.createElement('option');
    option.value = demo.id;
    option.textContent = demo.label;
    demoSelect.append(option);
  }

  demoSelect.addEventListener('change', () => {
    const demo = DEMOS.find((item) => item.id === demoSelect.value);
    if (demo !== undefined) load(demo.json, `шаблон ${demo.id} — ${demo.note}`);
  });

  need<HTMLButtonElement>('open').addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (file === undefined) return;
    void file.text().then((text) => load(text, file.name));
    fileInput.value = '';
  });

  let dragDepth = 0;
  stage.addEventListener('dragenter', (event) => {
    event.preventDefault();
    dragDepth += 1;
    dropzone.hidden = false;
  });
  stage.addEventListener('dragover', (event) => {
    event.preventDefault();
  });
  stage.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropzone.hidden = true;
  });
  stage.addEventListener('drop', (event) => {
    event.preventDefault();
    dragDepth = 0;
    dropzone.hidden = true;
    const file = event.dataTransfer?.files[0];
    if (file !== undefined) {
      void file.text().then((text) => load(text, file.name));
      return;
    }
    const text = event.dataTransfer?.getData('text/plain');
    if (text !== undefined && text.trim() !== '') load(text, 'перетащенный текст');
  });

  document.addEventListener('paste', (event) => {
    const target = event.target;
    if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) return;
    const text = event.clipboardData?.getData('text/plain') ?? '';
    if (text.trim().startsWith('{') || text.trim().startsWith('[')) {
      event.preventDefault();
      load(text, 'вставленный воркфлоу');
    }
  });

  // --------------------------------------------------------------- управление

  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-view]')) {
    button.addEventListener('click', () => {
      const action = button.dataset['view'];
      if (action === 'fit') canvas.fit();
      if (action === 'in') canvas.zoomBy(1.25);
      if (action === 'out') canvas.zoomBy(0.8);
    });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') select(null);
    if (event.key === 'f' && !event.metaKey && !event.ctrlKey) canvas.fit();
  });

  globalThis.addEventListener('resize', () => canvas.fit());

  // Выбор стартует на каноническом случае, а не на пустой странице: визуализатор, который
  // открывается пустым, сначала надо понять и только потом попробовать.
  const first = DEMOS[0];
  if (first !== undefined) {
    demoSelect.value = first.id;
    load(first.json, `шаблон ${first.id} — ${first.note}`);
  }
}
