import type { SideEffect } from '../rules/types.js';
import type { CheckerContext } from './context.js';
import { list, traceOf } from './trace.js';
import type { Finding, Severity } from './types.js';

/**
 * Два правила о том, что агенту позволено делать самостоятельно, — независимо от того,
 * доходит ли до него хоть что-то недоверенное.
 *
 * `INDIRECT_PROMPT_INJECTION` отвечает на вопрос «может ли атакующий это устроить». Эти два
 * отвечают на другой: «должно ли это вообще происходить без присмотра». Агент, запускаемый по
 * расписанию и держащий инструмент удаления, — ничья не инъекция, и это по-прежнему воркфлоу
 * в одном неудачном ответе модели от пустой таблицы. Оба правила отступают там, где уже
 * сработало правило об инъекции, чтобы одна и та же схема не показывалась дважды под двумя
 * именами.
 */

/** Эффекты, которые никто не должен запускать без человека, что бы ни пришло на вход. */
const DESTRUCTIVE: ReadonlySet<SideEffect> = new Set<SideEffect>([
  'delete-data',
  'payment',
  'execute-command',
  'admin-api',
]);

/** Начиная с этого числа необратимых инструментов находкой становятся сами полномочия агента. */
const CROWDED = 4;

export function missingHumanApproval(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  for (const node of ctx.taint.graph.nodes) {
    const agent = node.name;
    if (ctx.taint.classify(agent)?.invokesTools !== true) continue;
    // Недоверенный ввод, доходящий до агента, делает это находкой INDIRECT_PROMPT_INJECTION.
    if (ctx.taint.sourcesReaching(agent).length > 0) continue;

    const front = ctx.taint.front(agent);

    for (const target of ctx.taint.graph.nodes) {
      const sink = target.name;
      if (sink === agent || !front.reached.has(sink)) continue;

      const c = ctx.taint.classify(sink);
      if (!c?.sink?.irreversible || c.sanitizer?.strength === 'strong') continue;

      const walk = front.walkTo(sink);
      if (!walk) continue;

      let severity: Severity = DESTRUCTIVE.has(c.sink.effect) ? 'high' : 'medium';
      if (walk.weakGates.length > 0) severity = 'low';

      findings.push({
        rule: 'MISSING_HUMAN_APPROVAL',
        severity,
        confidence: 'firm',
        workflow: ctx.taint.graph.name,
        title: `«${agent}» может запустить «${sink}», и это никто не подтверждает`,
        detail:
          `«${agent}» решает, какие инструменты вызывать, и «${sink}» (${c.sink.effect}) — ` +
          `одно из того, до чего он дотягивается. Это действие нельзя отменить, и между ними ` +
          `нет шага подтверждения. Недоверенные данные до этого агента не доходят, так что ` +
          `это не инъекция — это агент, чей худший неверный ответ необратим. Операции ` +
          `\`sendAndWait\` в n8n останавливают выполнение, пока человек не ответит.`,
        remediation:
          `Добавьте шаг подтверждения между «${agent}» и «${sink}»: операция \`sendAndWait\` ` +
          `в Gmail, Slack, Telegram, Discord или WhatsApp приостановит выполнение, пока ` +
          `человек не ответит. Если действие настолько рутинное, что это избыточно, стоит ` +
          `спросить, должен ли агент вообще его выбирать — может быть, хватит фиксированной ` +
          `ветки.`,
        source: { node: agent, trust: 'semi-trusted' },
        agent,
        sink: { node: sink, effect: c.sink.effect, irreversible: true },
        trace: traceOf(walk),
        weakGates: walk.weakGates,
        otherSources: [],
        notes: [],
      });
    }
  }

  return findings;
}

export function overbroadToolAccess(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  for (const node of ctx.taint.graph.nodes) {
    const agent = node.name;
    if (ctx.taint.classify(agent)?.invokesTools !== true) continue;

    // Сами инструменты: ноды, подключённые к агенту как инструменты, а не всё, что ниже.
    const tools = ctx.taint.graph
      .outgoing(agent)
      .filter((e) => e.kind === 'invocation')
      .map((e) => e.to);

    const destructive: string[] = [];
    const irreversible: string[] = [];
    for (const tool of tools) {
      const sink = ctx.taint.classify(tool)?.sink;
      if (!sink) continue;
      if (sink.irreversible) irreversible.push(tool);
      if (DESTRUCTIVE.has(sink.effect)) destructive.push(tool);
    }

    const crowded = irreversible.length >= CROWDED;
    if (destructive.length === 0 && !crowded) continue;

    const gated = tools.some((t) => ctx.taint.classify(t)?.sanitizer?.strength === 'strong');
    if (gated) continue;

    const exposed = ctx.taint.sourcesReaching(agent).length > 0;
    const severity: Severity = destructive.length > 0 ? (exposed ? 'high' : 'medium') : 'medium';

    findings.push({
      rule: 'OVERBROAD_TOOL_ACCESS',
      severity,
      confidence: 'firm',
      workflow: ctx.taint.graph.name,
      title:
        destructive.length > 0
          ? `«${agent}» держит инструменты, которые уничтожают или тратят, и ни одного шага подтверждения среди них`
          : `«${agent}» держит ${irreversible.length} инструментов, чьи последствия необратимы`,
      detail:
        (destructive.length > 0
          ? `«${agent}» может вызвать ${list(destructive)} — ${destructive.length === 1 ? 'этот инструмент удаляет, платит или выполняет команды' : 'эти инструменты удаляют, платят или выполняют команды'}. `
          : `«${agent}» может вызвать ${irreversible.length} инструментов, чьи последствия необратимы: ${list(irreversible)}. `) +
        `Ни один из них не требует ничьего подтверждения. Список инструментов агента — это ` +
        `его набор прав: всё, что в нём есть, доступно при каждом ответе модели, включая ` +
        `неверный. ` +
        (exposed
          ? `До этого агента к тому же доходит недоверенный ввод — во что это обходится, ` +
            `сказано в находках об инъекции на той же ноде.`
          : `Сегодня недоверенные данные до этого агента не доходят, но это свойство текущей ` +
            `схемы связей, а не самого агента.`),
      remediation:
        `Сократите список инструментов до того, что нужно этому агенту для его работы, а ` +
        `разрушительным дайте собственный гейт: инструмент \`sendAndWait\` рядом с ними ` +
        `заставит агента спросить, прежде чем действовать. Там, где инструмент существует и ` +
        `в читающей, и в пишущей форме, подключайте читающую. Разделить одного широкого ` +
        `агента на двух узких стоит одной ноды и убирает саму комбинацию.`,
      source: { node: agent, trust: 'semi-trusted' },
      agent,
      sink: { node: agent, effect: undefined, irreversible: true },
      trace: [],
      weakGates: [],
      otherSources: [],
      notes: [`Инструменты: ${tools.join(', ')}`],
    });
  }

  return findings;
}
