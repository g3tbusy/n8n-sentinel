import { urlControl } from '../expressions/position.js';
import type { UrlControl } from '../expressions/position.js';
import type { CheckerContext } from './context.js';
import { describeRef, sensitiveHits, worstRef } from './expression-flow.js';
import { cap, lower } from './severity.js';
import { traceOf } from './trace.js';
import type { Finding, Severity } from './types.js';

/**
 * Недоверенные данные решают, куда уйдёт HTTP-запрос.
 *
 * Всё правило держится на том, *насколько большую часть* URL они решают. В официальной
 * библиотеке 6129 HTTP-нод собирают URL из выражения, и почти все подставляют идентификатор в
 * путь на хосте, зафиксированном ещё при написании воркфлоу. Показывать их так же, как
 * `{{ $json.url }}`, значит похоронить настоящие. Поэтому позиция первой подстановки задаёт
 * потолок severity, а рассуждение лежит в самой находке, а не в сноске.
 */
export function expressionSsrf(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  for (const hit of sensitiveHits(ctx, ['url'])) {
    const control = urlControl(hit.parsed);
    if (control === 'none') continue;

    const worst = worstRef(hit);
    const node = hit.node.name;
    const classification = ctx.taint.classify(node);

    let severity: Severity = worst.source.trust === 'semi-trusted' ? 'high' : 'critical';
    severity = cap(severity, CEILING[control]);
    if (worst.walk && worst.walk.weakGates.length > 0) severity = lower(severity);

    findings.push({
      rule: 'EXPRESSION_SSRF',
      severity,
      confidence: 'firm',
      workflow: ctx.taint.graph.name,
      title: `«${node}» собирает ${DESCRIBE[control]} своего запроса из недоверенных данных`,
      detail:
        `Параметр \`${hit.path}\` ноды «${node}» — это выражение, и ${describeRef(worst)}. ` +
        `${EXPLAIN[control]} ` +
        `Запрос уходит с доступами этого воркфлоу для того хоста, а ответ возвращается ` +
        `обратно в воркфлоу.`,
      remediation:
        `Решайте, какой хост, в воркфлоу, а не в данных: держите схему и хост литералами, а ` +
        `выражению оставьте только сегмент пути или значение в query. Там, где адресат ` +
        `действительно должен меняться, сверяйте его со списком принимаемых хостов до того, ` +
        `как отработает нода запроса.` +
        (worst.ref.kind === 'fromAI'
          ? ` Здесь значение пишет модель, поэтому список должен проверяться вне промпта.`
          : ''),
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
      notes: [`Выражение: ${hit.parsed.raw}`],
    });
  }

  return findings;
}

const CEILING: Record<Exclude<UrlControl, 'none'>, Severity> = {
  full: 'critical',
  host: 'critical',
  path: 'high',
  query: 'medium',
};

const DESCRIBE: Record<Exclude<UrlControl, 'none'>, string> = {
  full: 'весь URL',
  host: 'хост',
  path: 'путь',
  query: 'строку запроса',
};

const EXPLAIN: Record<Exclude<UrlControl, 'none'>, string> = {
  full: 'В URL не зафиксировано ничего, так что адресат — это то, что скажут данные.',
  host:
    'Схема зафиксирована, а хост нет, так что запрос можно направить куда угодно — в том ' +
    'числе на внутренний адрес, доступный только с машины, где работает n8n.',
  path:
    'Хост был зафиксирован при написании воркфлоу, так что здесь выбирается путь на ' +
    'известном сервисе, а не адресат: обход каталогов и непредусмотренные эндпоинты, а не ' +
    'произвольный исходящий запрос.',
  query: 'Хост и путь зафиксированы; здесь выбирается значение в query.',
};
