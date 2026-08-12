import type { GraphNode } from '../graph/types.js';
import { findExpressions } from '../expressions/parse.js';
import type { SideEffect } from '../rules/types.js';
import { untrustedRefs } from './context.js';
import type { CheckerContext } from './context.js';
import { lower } from './severity.js';
import { traceOf } from './trace.js';
import type { Finding, Severity } from './types.js';

/** Эффекты, которые что-то меняют или уничтожают, в отличие от тех, что что-то сообщают. */
const HEAVY: ReadonlySet<SideEffect> = new Set<SideEffect>([
  'delete-data',
  'payment',
  'admin-api',
  'write-database',
  'write-file',
]);

/**
 * `execute-code` и `execute-command` здесь сознательно не считаются тяжёлыми.
 *
 * Нода Code выполняет код, который написал её автор. Недоверенные данные, приходящие в неё, —
 * это строка в переменной, и чтобы строка стала выполнением, сам код должен быть
 * неаккуратным. Это вопрос EXPRESSION_RCE, заданный к коду, а не к этому правилу. Ноды Code —
 * самый частый sink, который показывает это правило (10 631 находка по всей библиотеке), и
 * пометка их как тяжёлых делала правило рассказом не о том.
 */

/**
 * Недоверенный ввод доходит до необратимого действия, и между ними нет ни модели, ни гейта.
 *
 * Это правило приходится всё время удерживать в честных рамках, потому что буквально оно
 * описывает автоматизацию как таковую: вебхук, который пишет строку в таблицу, делает ровно
 * то, ради чего его сделали. Находкой это становится из-за отсутствия чего-либо, решающего,
 * должен ли *именно этот* ввод приводить к такому эффекту.
 *
 * Три ограничения не дают правилу проглотить весь отчёт:
 *
 * - **Только действительно внешние источники.** `semi-trusted` — своя же база, своя же
 *   таблица — исключён. Прочитать одну таблицу и записать другую это ETL, а не экспозиция.
 * - **Ничего, где участвует агент.** Это находка `INDIRECT_PROMPT_INJECTION`, и показывать
 *   одну и ту же схему дважды под двумя именами никому не помогает.
 * - **Потолок ниже `critical`.** Без модели, выбирающей действие, атакующий подставляет
 *   значения в действие, которое выбрал автор. Это стоит меньше, чем когда действие выбирает
 *   атакующий, и полосы severity должны это говорить.
 */
export function ungatedSideEffect(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  const agents = ctx.taint.graph.nodes
    .map((n) => n.name)
    .filter((name) => ctx.taint.classify(name)?.invokesTools === true);

  for (const target of ctx.taint.graph.nodes) {
    const sink = target.name;
    const c = ctx.taint.classify(sink);
    if (!c?.sink?.irreversible || c.sanitizer?.strength === 'strong') continue;

    // Всё, до чего дотягивается открытый агент, принадлежит правилу об инъекции.
    const viaAgent = agents.some(
      (agent) =>
        agent !== sink &&
        ctx.taint.front(agent).reached.has(sink) &&
        ctx.taint.sourcesReaching(agent).length > 0,
    );
    if (viaAgent) continue;

    const source = ctx.taint
      .sourcesReaching(sink)
      .find((s) => s.trust !== 'semi-trusted' && s.node !== sink);
    if (!source) continue;

    const walk = ctx.taint.front(source.node).walkTo(sink);
    if (!walk) continue;

    // Ввод действительно определяет форму действия — или только запускает его? Sink, в
    // параметры которого подставляются недоверенные данные, действует *над* этими данными;
    // sink, у которого все параметры константы, сделал бы то же самое, что бы ни пришло.
    const shaping = shapedByUntrusted(ctx, target);

    let severity: Severity = HEAVY.has(c.sink.effect) ? 'high' : 'medium';
    if (!shaping) severity = lower(severity);
    if (walk.weakGates.length > 0) severity = lower(severity);

    findings.push({
      rule: 'UNGATED_SIDE_EFFECT',
      severity,
      confidence: shaping ? 'firm' : 'uncertain',
      workflow: ctx.taint.graph.name,
      title: shaping
        ? `Данные из «${source.node}» определяют, что сделает «${sink}», и это никто не проверяет`
        : `Данные из «${source.node}» доходят до «${sink}», и это никто не проверяет`,
      detail:
        `«${source.node}» приносит данные, которые этот воркфлоу не контролирует, и они ` +
        `попадают в «${sink}» (${c.sink.effect}) — а это нельзя отменить. Между ними нет ни ` +
        `шага подтверждения, ни валидации. ` +
        (shaping
          ? `В параметры самой ноды эти данные подставляются, то есть что именно сделает ` +
            `действие, решает то, что пришло.`
          : `Ни один параметр ноды эти данные явно не читает, так что, возможно, ввод только ` +
            `запускает действие, а не управляет им. Стоит проверить: нода, которая напрямую ` +
            `раскладывает поля из потока элементов, читает их без всякого выражения, и здесь ` +
            `это не видно.`),
      remediation:
        `Проверяйте ввод на соответствие тому, что этому действию действительно нужно, до ` +
        `того как он сюда дойдёт: \`if\` или нода Code, сверяющая конкретные поля, которые ` +
        `использует «${sink}», а не просто факт, что что-то пришло. Для действия, которое так ` +
        `трудно отменить, шаг подтверждения — ответ сильнее: операции \`sendAndWait\` в n8n ` +
        `ждут, пока человек ответит.`,
      source: { node: source.node, trust: source.trust },
      agent: undefined,
      sink: { node: sink, effect: c.sink.effect, irreversible: true },
      trace: traceOf(walk),
      weakGates: walk.weakGates,
      otherSources: ctx.taint
        .sourcesReaching(sink)
        .filter((s) => s.node !== source.node && s.trust !== 'semi-trusted')
        .map((s) => s.node)
        .sort(),
      notes: [],
    });
  }

  return findings;
}

/** Истина, когда хоть одно выражение в параметрах ноды читает данные, которые пишет атакующий. */
function shapedByUntrusted(ctx: CheckerContext, node: GraphNode): boolean {
  return findExpressions(node.parameters).some(
    (found) => untrustedRefs(ctx, node, found.parsed.refs).length > 0,
  );
}
