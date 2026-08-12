import { dangerousConstructs } from '../expressions/position.js';
import type { CheckerContext } from './context.js';
import { describeRef, sensitiveHits, worstRef } from './expression-flow.js';
import { lower } from './severity.js';
import { traceOf } from './trace.js';
import { list } from './trace.js';
import type { Finding, Severity } from './types.js';

/**
 * Недоверенные данные доходят до чего-то, что их выполняет.
 *
 * Две формы, и они заслуживают разной уверенности:
 *
 * - **Команда shell, собранная подстановкой.** `executeCommand` и `ssh` принимают команду в
 *   поле-выражении, поэтому подставленное значение склеивается в строку для shell. В
 *   выборочном корпусе так делают четырнадцать нод. Доказывать дальше нечего.
 * - **Нода Code, которая вычисляет строки.** `jsCode` — это не выражение, а код, который сам
 *   читает `$json`, поэтому находке нужно, чтобы в коде было что-то, превращающее строку в
 *   выполнение. Доходит ли недоверенное значение до этой конструкции — за пределами того, что
 *   прослеживает анализ, поэтому находка идёт на полосу ниже с явно названной причиной.
 *
 * В выборке из 794 воркфлоу ни одна нода Code не вызывает `eval` и не импортирует
 * `child_process`. Это стоит сказать вслух: правило существует потому, что форма настоящая, а
 * не потому, что корпус ею полон.
 */
export function expressionRce(ctx: CheckerContext): Finding[] {
  return [...commandInjection(ctx), ...evaluatedStrings(ctx)];
}

function commandInjection(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  for (const hit of sensitiveHits(ctx, ['command'])) {
    const worst = worstRef(hit);
    const node = hit.node.name;
    const classification = ctx.taint.classify(node);

    let severity: Severity = worst.source.trust === 'semi-trusted' ? 'high' : 'critical';
    if (worst.walk && worst.walk.weakGates.length > 0) severity = lower(severity);

    findings.push({
      rule: 'EXPRESSION_RCE',
      severity,
      confidence: 'firm',
      workflow: ctx.taint.graph.name,
      title: `«${node}» собирает команду shell из недоверенных данных`,
      detail:
        `Параметр \`${hit.path}\` ноды «${node}» собирается подстановкой, и ` +
        `${describeRef(worst)}. Значение склеивается в командную строку, где точка с запятой ` +
        `или обратная кавычка заканчивает задуманную команду и начинает другую — с правами ` +
        `того пользователя, под которым работает n8n, прямо на хосте.`,
      remediation:
        `Не собирайте командную строку из данных. Если команда обязана меняться, ограничьте ` +
        `меняющуюся часть значением, сверенным с фиксированным списком до попадания сюда, и ` +
        `возьмите его в кавычки. Ещё лучше — замените ноду на ту, что делает конкретную ` +
        `работу: HTTP-запрос, файловая нода, — тогда не будет и shell, из которого можно ` +
        `выйти.`,
      source: { node: worst.source.node, trust: worst.source.trust },
      agent: worst.ref.kind === 'fromAI' ? worst.via : undefined,
      sink: {
        node,
        effect: classification?.sink?.effect,
        irreversible: classification?.sink?.irreversible === true,
      },
      trace: traceOf(worst.walk),
      weakGates: worst.walk?.weakGates ?? [],
      otherSources: hit.untrusted
        .map((r) => r.source.node)
        .filter((s) => s !== worst.source.node)
        .sort(),
      notes: [`Команда: ${hit.parsed.raw}`],
    });
  }

  return findings;
}

function evaluatedStrings(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  for (const node of ctx.taint.graph.nodes) {
    if (!ctx.taint.isTainted(node.name)) continue;

    for (const { path, code } of ctx.params.codeIn(node)) {
      const constructs = dangerousConstructs(code);
      if (constructs.length === 0) continue;

      const source = ctx.taint.sourcesReaching(node.name)[0];
      if (!source) continue;
      const walk = ctx.taint.front(source.node).walkTo(node.name);

      let severity: Severity = source.trust === 'semi-trusted' ? 'medium' : 'high';
      if (walk && walk.weakGates.length > 0) severity = lower(severity);

      findings.push({
        rule: 'EXPRESSION_RCE',
        severity,
        // Конструкция — в коде, данные — в ноде. Что первое дотягивается до второго, никто
        // не проверял.
        confidence: 'uncertain',
        workflow: ctx.taint.graph.name,
        title: `«${node.name}» вычисляет строки и получает недоверенные данные`,
        detail:
          `В \`${path}\` ноды «${node.name}» есть ${list(constructs, 'динамическое вычисление')}, ` +
          `и в эту ноду приходят недоверенные данные из «${source.node}». Доходит ли одно до ` +
          `другого, зависит от самого кода, который этот анализ читает, но не выполняет, — ` +
          `так что это место, куда стоит посмотреть, а не доказанный путь.`,
        remediation:
          `Прочитайте код и проверьте, может ли недоверенное значение дойти до ` +
          `${list(constructs, 'динамического вычисления')}. Если может — замените динамическое ` +
          `вычисление на то, что не умеет выполнять свой ввод: таблицу соответствий, парсер, ` +
          `явную ветку.`,
        source: { node: source.node, trust: source.trust },
        agent: undefined,
        sink: {
          node: node.name,
          effect: ctx.taint.classify(node.name)?.sink?.effect,
          irreversible: ctx.taint.classify(node.name)?.sink?.irreversible === true,
        },
        trace: traceOf(walk),
        weakGates: walk?.weakGates ?? [],
        otherSources: ctx.taint
          .sourcesReaching(node.name)
          .slice(1)
          .map((s) => s.node)
          .sort(),
        notes: ['Прежде чем действовать по этой находке, прочитайте код.'],
      });
    }
  }

  return findings;
}
