import type { GraphEdge } from '../graph/types.js';
import type { SideEffect, TrustLevel } from '../rules/types.js';
import type { TaintAnalysis } from '../taint/engine.js';
import type { CheckerContext } from './context.js';
import type { TaintSource, TaintWalk } from '../taint/types.js';
import { trustRank } from '../taint/engine.js';
import { lower, rank } from './severity.js';
import type { Confidence, Finding, Severity, TraceStep } from './types.js';

/**
 * Главное правило: недоверенный ввод доходит до ноды, умеющей вызывать инструменты, а та
 * дотягивается до чего-то необратимого, и между ними никого нет.
 *
 * Именно это отличает сканер для n8n от сканера вообще. Опасен не тот факт, что модель
 * увидела враждебный текст, — опасно, что её вывод подключён к действию. Тело письма,
 * скрапленная страница или элемент RSS-ленты превращается в инструкцию, и эту инструкцию
 * выполняет агент с настоящими доступами.
 *
 * Сознательно не помечается:
 *
 * - **Всё, что стоит за сильным гейтом.** Taint останавливается на `sendAndWait`: это увидел
 *   человек. Сама нода-гейт тоже никогда не показывается как sink — рассказывать, что в
 *   запросе на подтверждение есть подконтрольный атакующему текст, значит описывать механизм,
 *   а не находку.
 * - **Агент сам по себе.** Агент, читающий враждебную почту и никуда не подключённый, — это
 *   чат-бот, который говорит странное. Без sink находки нет.
 *
 * Одна находка на sink, а не на маршрут. Воркфлоу, где тридцать источников кормят одного
 * агента с дюжиной инструментов, — это двенадцать проблем, а не триста шестьдесят; показан
 * маршрут, который читается хуже всех, остальные сведены в него.
 */
export function indirectPromptInjection(ctx: CheckerContext): Finding[] {
  const { taint } = ctx;
  const agents = taint.graph.nodes
    .map((n) => n.name)
    .filter((name) => taint.classify(name)?.invokesTools === true);
  if (agents.length === 0) return [];

  const feeds = new Map<string, readonly TaintSource[]>(
    agents.map((agent) => [agent, taint.sourcesReaching(agent)]),
  );

  const findings: Finding[] = [];

  for (const target of taint.graph.nodes) {
    const sink = target.name;
    const c = taint.classify(sink);
    if (!c) continue;
    // Что бы эта нода ни делала, человек на это согласился.
    if (c.sanitizer?.strength === 'strong') continue;
    if (!c.sink && !c.boundary) continue;

    const routes: Route[] = [];
    const reachingSources = new Set<string>();

    for (const agent of agents) {
      if (agent === sink) continue;
      const front = taint.front(agent);
      if (!front.reached.has(sink)) continue;

      const feeding = feeds.get(agent) ?? [];
      if (feeding.length === 0) continue;
      for (const s of feeding) reachingSources.add(s.node);

      const source = pickSource(feeding, sink, taint);
      const toAgent = taint.front(source.node).walkTo(agent);
      const toSink = front.walkTo(sink);
      if (!toAgent || !toSink) continue;

      const gatedOnAction = !front.ungated.has(sink);
      const confidence: Confidence = c.boundary && !c.sink ? 'uncertain' : 'firm';
      routes.push({
        agent,
        source,
        toAgent,
        toSink,
        gatedOnAction,
        confidence,
        severity: severityOf({
          trust: source.trust,
          // За границей воркфлоу необратимость не видна, и трактуется она как худший случай:
          // полоса описывает цену, а сомнение живёт в confidence (см. severityOf).
          irreversible: c.sink?.irreversible === true || (c.boundary === true && !c.sink),
          gatedOnAction,
          confidence,
          effect: c.sink?.effect,
          // Последний шаг говорит, какую часть действия выбрал агент. `invocation` означает,
          // что он решил это вызвать и написал каждый аргумент; ребро `data` — что он лишь
          // подставил значения в то, что и так собиралось сработать.
          agentInvoked: toSink.steps[toSink.steps.length - 1]?.kind === 'invocation',
        }),
      });
    }

    const worst = routes.sort(byWorstRoute)[0];
    if (!worst) continue;

    const weakGates = dedupe([...worst.toAgent.weakGates, ...worst.toSink.weakGates]);
    findings.push({
      rule: 'INDIRECT_PROMPT_INJECTION',
      severity: worst.severity,
      confidence: worst.confidence,
      workflow: taint.graph.name,
      title:
        worst.confidence === 'uncertain'
          ? `«${worst.agent}» может передать подконтрольные атакующему данные в «${sink}», а его последствия лежат в другом воркфлоу`
          : `Недоверенный ввод, доходящий до «${worst.agent}», способен управлять «${sink}»`,
      detail: detailOf({
        source: worst.source.node,
        trust: worst.source.trust,
        agent: worst.agent,
        sink,
        effect: c.sink?.effect,
        irreversible: c.sink?.irreversible === true,
        confidence: worst.confidence,
        gatedOnAction: worst.gatedOnAction,
        actionGates: worst.toSink.weakGates,
      }),
      remediation:
        worst.confidence === 'uncertain'
          ? `Просканируйте воркфлоу, который вызывает «${sink}», и считайте его sink-и ` +
            `достижимыми отсюда. Если он действует необратимо, поставьте шаг подтверждения ` +
            `в этом воркфлоу — до вызова вложенного.`
          : `Поставьте человека между «${worst.agent}» и «${sink}»: операции \`sendAndWait\` ` +
            `в n8n останавливают выполнение, пока кто-нибудь не ответит, и анализ на них ` +
            `прекращается. Если это невозможно — сузьте то, до чего дотягивается агент: ` +
            `инструмент, который читает, это не инструмент, который отправляет. Указания в ` +
            `промпте игнорировать вставленный текст защитой не являются: модель не отличает ` +
            `ваши инструкции от входных данных.`,
      source: { node: worst.source.node, trust: worst.source.trust },
      agent: worst.agent,
      sink: { node: sink, effect: c.sink?.effect, irreversible: c.sink?.irreversible === true },
      trace: [...worst.toAgent.steps, ...worst.toSink.steps].map(toTraceStep),
      weakGates,
      otherSources: [...reachingSources].filter((s) => s !== worst.source.node).sort(),
      notes: notesOf(worst, routes.length),
    });
  }

  return findings;
}

interface Route {
  readonly agent: string;
  readonly source: TaintSource;
  readonly toAgent: TaintWalk;
  readonly toSink: TaintWalk;
  readonly gatedOnAction: boolean;
  readonly confidence: Confidence;
  readonly severity: Severity;
}

/**
 * Сначала худший, потом самый короткий, потом агент, ближайший к источнику.
 *
 * Последнее важно, когда модели выстроены в цепочку: если на маршруте два агента, инъекция
 * попадает в первого, и назвать второго значит показать читателю не ту ноду, которую надо
 * чинить.
 */
const byWorstRoute = (a: Route, b: Route): number =>
  rank(b.severity) - rank(a.severity) ||
  a.toAgent.steps.length +
    a.toSink.steps.length -
    (b.toAgent.steps.length + b.toSink.steps.length) ||
  a.toAgent.steps.length - b.toAgent.steps.length ||
  a.agent.localeCompare(b.agent);

/**
 * Какую точку входа показать читателю.
 *
 * Severity зависит от уровня доверия, поэтому он идёт первым. Дальше это уже вопрос подачи:
 * нода, которая одновременно является sink, даёт трассу, начинающуюся там же, где она
 * заканчивается, а триггер рассказывает историю лучше, чем инструмент, который агент вызвал
 * двумя шагами раньше, — при том что поток данных описывается один и тот же.
 */
function pickSource(
  feeding: readonly TaintSource[],
  sink: string,
  taint: TaintAnalysis,
): TaintSource {
  const isEntry = (node: string): boolean => taint.graph.incoming(node).length === 0;
  return [...feeding].sort(
    (a, b) =>
      trustRank(b.trust) - trustRank(a.trust) ||
      Number(a.node === sink) - Number(b.node === sink) ||
      Number(isEntry(b.node)) - Number(isEntry(a.node)) ||
      a.node.localeCompare(b.node),
  )[0] as TaintSource;
}

/**
 * Начинаем с того, сколько стоит источник, и снимаем по полосе за каждое препятствие.
 *
 * Считаются только гейты между агентом и sink. Фильтр выше агента решает, какие сообщения
 * вообще пойдут в обработку; он никогда не видит, что агент решил сделать, и потому не
 * является защитой от того, что агент решит сделать что-то другое. Фикстура 04057 — ровно
 * эта форма: фильтр, которым к тому же управляет модель, стоит перед агентом. Засчитать его
 * как смягчение значило бы занизить канонический случай, ради которого этот сканер и написан.
 */
function severityOf(f: {
  trust: TrustLevel;
  irreversible: boolean;
  gatedOnAction: boolean;
  confidence: Confidence;
  effect: SideEffect | undefined;
  agentInvoked: boolean;
}): Severity {
  // Раньше здесь стояло `if (confidence === 'uncertain') return 'medium'` — неизвестность за
  // границей воркфлоу понижала полосу. Это дисконтировало одно и то же сомнение дважды: сперва
  // в confidence, потом в severity. Полигон (фаза 8.2, сценарий S1) развёл эти две вещи
  // замером: довести агента до вызова под-воркфлоу с аргументами атакующего удаётся
  // практически всегда — 15 из 15 на Sonnet первой же заготовкой, 13 из 13 на GPT с
  // усилением. Неизвестным осталось только одно: есть ли внутри под-воркфлоу необратимое
  // действие. Это и держит `confidence: uncertain`. Severity же отвечает на другой вопрос —
  // насколько плохо, ЕСЛИ оно там есть, — и на него ответ такой же, как для необратимого sink
  // на том же пути. Разбор в docs/scoring.md.
  let severity: Severity = f.trust === 'semi-trusted' ? 'high' : 'critical';
  if (!f.irreversible) severity = lower(severity);
  if (f.gatedOnAction) severity = lower(severity);
  // Выполнение кода теряет полосу ВСЕГДА — и ниже агента, и когда агент вызывает его сам.
  //
  // Раньше здесь стояло `!f.agentInvoked`: считалось, что `toolCode`, который вызывает агент, —
  // обратный случай, потому что тело кода в нём сочиняет модель. Полигон (фаза 8.2, сценарий S4)
  // это опроверг, и опроверг не замером, а устройством ноды. У `toolCode` тело кода — параметр
  // `jsCode`/`pythonCode`, который пишет АВТОР воркфлоу (дефолт `return query.toUpperCase()`),
  // а модель передаёт только `query` либо аргументы по `inputSchema`. Места, куда модель вписала
  // бы свой код, у ноды нет. По всей библиотеке так во всех 135 нодах `toolCode`: `jsCode` задан
  // у 92, `pythonCode` у 7, дефолт у 36, `specifyInputSchema` у 8.
  //
  // То есть агент решает ЗАПУСТИТЬ выполнение и пишет его аргумент — но не то, что выполнится.
  // Чтобы аргумент стал выполнением, код автора должен быть неаккуратным, а это вопрос к
  // EXPRESSION_RCE: то же самое, что и для ноды Code ниже по потоку. Таких нод в библиотеке
  // одна из 135, и правило её ловит.
  if (f.effect === 'execute-code' || f.effect === 'execute-command') {
    severity = lower(severity);
  }
  return severity;
}

const TRUST_PHRASE: Record<TrustLevel, string> = {
  'untrusted-public': 'любой, кто может достучаться до этой точки входа',
  'untrusted-external':
    'кто-то вне этого воркфлоу — отправитель письма, владелец ленты, автор страницы',
  'semi-trusted': 'тот, кто когда-то записал данные, которые она читает',
};

function detailOf(f: {
  source: string;
  trust: TrustLevel;
  agent: string;
  sink: string;
  effect: string | undefined;
  irreversible: boolean;
  confidence: Confidence;
  gatedOnAction: boolean;
  /** Слабые гейты на отрезке агент → sink. Только они говорят, проверяется ли действие. */
  actionGates: readonly string[];
}): string {
  const parts: string[] = [
    `«${f.source}» приносит данные, которыми управляет ${TRUST_PHRASE[f.trust]}, и эти данные ` +
      `доходят до «${f.agent}», который решает, какие инструменты вызывать.`,
  ];

  parts.push(
    f.confidence === 'uncertain'
      ? `Оттуда они попадают в «${f.sink}», запускающий другой воркфлоу. Что делает тот ` +
          `воркфлоу, в этом документе не написано, поэтому путь не безопасен, а не прослежен ` +
          `— просканируйте вызываемый воркфлоу, чтобы закрыть вопрос.`
      : `Оттуда они попадают в «${f.sink}» (${f.effect ?? 'побочный эффект'}), и это ` +
          `${f.irreversible ? 'нельзя отменить, когда уже произошло' : 'действует за пределами воркфлоу'}. ` +
          `Значит, текст, дошедший до агента, способен выбрать и само действие, и его аргументы.`,
  );

  parts.push(
    f.gatedOnAction
      ? `Каждый маршрут от агента до этого действия проходит через ${list(f.actionGates)} — ` +
          `это ограничивает проходящее, но никто не подтверждает, что оно значит то, что ` +
          `написано. Засчитано как частичное смягчение, не как защита.`
      : 'Между агентом и действием нет шага подтверждения.',
  );

  return parts.join(' ');
}

function notesOf(route: Route, routeCount: number): string[] {
  const notes: string[] = [];
  if (route.toAgent.usesDerivedEdge || route.toSink.usesDerivedEdge) {
    notes.push(
      'В трассе есть шаг агент → инструмент. n8n хранит эту связь в обратную сторону, поэтому ' +
        'на холсте такой стрелки нет — но аргументы инструменту готовит именно агент.',
    );
  }
  if (routeCount > 1) {
    notes.push(
      `До этого sink дотягивается ${routeCount} нод, вызывающих инструменты; показана ближайшая к источнику.`,
    );
  }
  if (route.confidence === 'uncertain') {
    notes.push(
      'Границы вложенных воркфлоу не прослеживаются. Просканируйте вызываемый воркфлоу отдельно.',
    );
  }
  return notes;
}

const toTraceStep = (e: GraphEdge): TraceStep => ({
  from: e.from,
  to: e.to,
  kind: e.kind,
  derived: e.derived,
});

const dedupe = (names: readonly string[]): string[] => [...new Set(names)];

const list = (names: readonly string[]): string => {
  if (names.length === 0) return 'проверку';
  const quoted = names.map((n) => `«${n}»`);
  if (quoted.length === 1) return quoted[0] as string;
  return `${quoted.slice(0, -1).join(', ')} и ${quoted[quoted.length - 1] as string}`;
};
