import type { GraphNode } from '../graph/types.js';
import { isExpression } from '../expressions/parse.js';
import type { ExpressionRef } from '../expressions/parse.js';
import type { SensitiveParams } from '../expressions/sensitive.js';
import type { TaintAnalysis } from '../taint/engine.js';
import type { TaintSource, TaintWalk } from '../taint/types.js';

/** Что получает каждый чекер. Добавить правило — значит прочитать это, а не обойти граф заново. */
export interface CheckerContext {
  readonly taint: TaintAnalysis;
  readonly params: SensitiveParams;
}

/**
 * Ссылка внутри выражения, разрешённая относительно taint-анализа.
 *
 * Именно это делает правила фазы 4 точнее, чем правила фазы 3. Достижимость говорит, что нода
 * стоит ниже вебхука; разрешённая ссылка говорит, что *этот параметр* читает тело вебхука.
 * Первое — повод посмотреть, второе — повод показать находку.
 */
export interface ResolvedRef {
  readonly ref: ExpressionRef;
  /** Нода, чей taint делает эту ссылку недоверенной. */
  readonly via: string;
  /** Худший источник, доходящий до `via`, или сам `via`, если источник — он. */
  readonly source: TaintSource;
  readonly walk: TaintWalk | undefined;
}

/**
 * Какие из ссылок выражения несут данные, которые может написать атакующий.
 *
 * - `$json` и `$input` читают то, что пришло в эту ноду, поэтому они недоверенные, когда до
 *   ноды доходит taint, — но никогда из-за того, что нода сама является источником: то, что
 *   она приносит извне, это её вывод, и он появляется уже после вычисления её параметров.
 * - `$('Другая нода')` читает вывод той ноды, что бы ни пришло в эту.
 * - `$fromAI(…)` пишет модель, поэтому ссылка недоверенная, когда недоверенно всё, что
 *   доходит до агента, — а агент это та нода, к которой эта подключена как инструмент.
 * - `$env`, `$vars`, `$secrets` и часы атакующим не пишутся. Для SECRET_EXFIL_RISK они важны
 *   по противоположной причине.
 */
export function untrustedRefs(
  ctx: CheckerContext,
  node: GraphNode,
  refs: readonly ExpressionRef[],
): ResolvedRef[] {
  const resolved: ResolvedRef[] = [];
  const seen = new Set<string>();

  for (const ref of refs) {
    for (const { via, readsOutput } of carriers(ctx, node, ref)) {
      if (!carriesUntrusted(ctx, via, readsOutput)) continue;

      const source = worstSource(ctx, via, readsOutput);
      if (!source) continue;

      const key = `${ref.kind} ${via} ${source.node}`;
      if (seen.has(key)) continue;
      seen.add(key);

      resolved.push({
        ref,
        via,
        source,
        walk: source.node === via ? undefined : ctx.taint.front(source.node).walkTo(via),
      });
    }
  }
  return resolved;
}

/**
 * Нода или ноды, чьи данные ссылка действительно втягивает, и с какой их стороны.
 *
 * Различие важнее, чем кажется. `$json` в URL HTTP-ноды читает то, что *пришло* в эту ноду;
 * нода при этом сама является источником, потому что её ответ приходит извне, — но этот ответ
 * это её вывод, и в её собственных параметрах он появиться не может. Если считать это одним и
 * тем же, каждая HTTP-нода с выражением в URL начинает показывать саму себя.
 */
interface Carrier {
  readonly via: string;
  /** Истина, когда ссылка читает вывод ноды, а не её вход. */
  readonly readsOutput: boolean;
}

function carriers(ctx: CheckerContext, node: GraphNode, ref: ExpressionRef): Carrier[] {
  switch (ref.kind) {
    case 'json':
      return [{ via: node.name, readsOutput: false }];
    case 'node': {
      // Вычисляемое имя ноды — `$('Префикс ' + x)` — может оказаться любым. Показать находку
      // по догадке хуже, чем промолчать, поэтому безымянная ссылка не разрешается ни во что,
      // и находку должны вытянуть другие ссылки этой ноды.
      if (ref.node === undefined) return [];
      const target = ctx.taint.graph.node(ref.node);
      if (!target) return [];
      return readsLiteralField(target, ref.field) ? [] : [{ via: ref.node, readsOutput: true }];
    }
    case 'fromAI':
      return agentsHolding(ctx, node.name).map((via) => ({ via, readsOutput: true }));
    default:
      return [];
  }
}

const FIELD_NODES = new Set(['n8n-nodes-base.set', 'n8n-nodes-base.editFields']);

/**
 * Истина, когда ссылка читает одно поле ноды Set и это поле — константа.
 *
 * Конфиг в ноде Set это самая частая в корпусе форма хранения базового URL, хоста API или
 * идентификатора таблицы. Такая нода стоит ниже триггера, поэтому taint до неё доходит, — но
 * `$('Config').json.BASE_URL` читает строку, которую кто-то напечатал, а не то, что пришло.
 * Без этой проверки пять из первых двенадцати `critical`-находок SSRF в корпусе оказались
 * одним воркфлоу, читающим собственный захардкоженный базовый URL.
 *
 * Годятся только литеральные присваивания. Поле Set, чьё значение само является выражением,
 * или нода в режиме сырого JSON остаются недоверенными: вполне может быть, что они пропускают
 * ввод насквозь.
 */
function readsLiteralField(target: GraphNode, field: string | undefined): boolean {
  if (field === undefined || !FIELD_NODES.has(target.type)) return false;

  const params = target.parameters;
  if (params['mode'] === 'raw' || typeof params['jsonOutput'] === 'string') return false;

  for (const assignment of assignmentsOf(params)) {
    if (assignment.name !== field) continue;
    return typeof assignment.value === 'string' && !isExpression(assignment.value);
  }
  return false;
}

/** Нода Set v3 хранит `assignments.assignments[]`; версии постарше — `values.<type>[]`. */
function assignmentsOf(
  params: Readonly<Record<string, unknown>>,
): { name: string; value: unknown }[] {
  const out: { name: string; value: unknown }[] = [];

  const push = (entry: unknown): void => {
    if (entry === null || typeof entry !== 'object') return;
    const record = entry as Record<string, unknown>;
    if (typeof record['name'] === 'string')
      out.push({ name: record['name'], value: record['value'] });
  };

  const modern = params['assignments'];
  if (modern !== null && typeof modern === 'object') {
    const list = (modern as Record<string, unknown>)['assignments'];
    if (Array.isArray(list)) for (const entry of list) push(entry);
  }

  const legacy = params['values'];
  if (legacy !== null && typeof legacy === 'object') {
    for (const list of Object.values(legacy as Record<string, unknown>)) {
      if (Array.isArray(list)) for (const entry of list) push(entry);
    }
  }

  return out;
}

/** Агенты, к которым эта нода подключена как инструмент, — те, кто пишет её значения `$fromAI`. */
function agentsHolding(ctx: CheckerContext, tool: string): string[] {
  return ctx.taint.graph
    .incoming(tool)
    .filter((e) => e.kind === 'invocation')
    .map((e) => e.from);
}

/**
 * Истина, когда читаемая сторона ноды несёт данные, которые может написать атакующий.
 *
 * *Вывод* ноды недоверенный, если она источник — ответ HTTP, скачанная страница — или если до
 * неё доходит taint. Её *вход* недоверенный только во втором случае: то, что нода приносит
 * извне, появляется уже после вычисления её параметров.
 */
function carriesUntrusted(ctx: CheckerContext, node: string, readsOutput: boolean): boolean {
  if (readsOutput && ctx.taint.classify(node)?.source !== undefined) return true;
  return ctx.taint.isTainted(node);
}

function worstSource(
  ctx: CheckerContext,
  node: string,
  readsOutput: boolean,
): TaintSource | undefined {
  const own = readsOutput ? ctx.taint.classify(node)?.source : undefined;
  const reaching = ctx.taint.sourcesReaching(node);
  // Нода, которая сама является источником, конкурирует с теми, что стоят выше: HTTP-нода,
  // скачивающая враждебную страницу, рассказывает историю лучше, чем триггер тремя шагами
  // раньше, — если только тот триггер не стоит дороже.
  const mine: TaintSource | undefined = own ? { node, trust: own.trust } : undefined;
  const best = reaching[0];
  if (!mine) return best;
  if (!best) return mine;
  return rankOf(best.trust) > rankOf(mine.trust) ? best : mine;
}

const rankOf = (trust: TaintSource['trust']): number =>
  trust === 'untrusted-public' ? 3 : trust === 'untrusted-external' ? 2 : 1;
