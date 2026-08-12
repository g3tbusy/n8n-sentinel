import type { CheckerContext } from './context.js';
import { describeRef, sensitiveHits, worstRef } from './expression-flow.js';
import { lower } from './severity.js';
import { traceOf } from './trace.js';
import type { Finding, Severity } from './types.js';

/**
 * Недоверенные данные, склеенные в SQL-запрос.
 *
 * Здесь, в отличие от правила про URL, спорить о позиции не о чем: ноды баз данных в n8n
 * принимают параметры запроса, и воркфлоу, подставляющий `{{ }}` в текст запроса, выбрал
 * склейку вместо них. Попадёт значение в `WHERE` или в имя колонки — запрос всё равно
 * собирается из данных.
 *
 * Проверяются только ноды, принимающие SQL текстом, и только их параметр `query`: совпадения
 * по одному имени показали бы поисковые инструменты из корпуса, у которых параметр тоже
 * называется `query`. Список лежит в rules/sensitive-params.yaml.
 */
export function expressionSqli(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  for (const hit of sensitiveHits(ctx, ['sql'])) {
    const worst = worstRef(hit);
    const node = hit.node.name;
    const classification = ctx.taint.classify(node);

    let severity: Severity = worst.source.trust === 'semi-trusted' ? 'high' : 'critical';
    if (worst.walk && worst.walk.weakGates.length > 0) severity = lower(severity);

    findings.push({
      rule: 'EXPRESSION_SQLI',
      severity,
      confidence: 'firm',
      workflow: ctx.taint.graph.name,
      title: `«${node}» собирает свой SQL-запрос из недоверенных данных`,
      detail:
        `Параметр \`${hit.path}\` ноды «${node}» собирается подстановкой, и ` +
        `${describeRef(worst)}. Значение становится частью запроса, а не параметром к нему, ` +
        `поэтому им можно закончить задуманный запрос и начать другой. Ноды баз данных в n8n ` +
        `принимают параметры запроса; с ними значение оказывается вне досягаемости парсера.`,
      remediation:
        `Используйте параметры запроса вместо сборки строки: напишите в запросе \`$1\`, ` +
        `\`$2\`, а сами значения передайте через «Query Parameters» в настройках ноды. Тогда ` +
        `значение доедет до базы как данные и никогда как синтаксис. Ручное экранирование ` +
        `заменой не является — оно должно срабатывать каждый раз.`,
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
      notes: [`Запрос: ${hit.parsed.raw}`],
    });
  }

  return findings;
}
