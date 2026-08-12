import { urlControl } from '../expressions/position.js';
import { untrustedRefs } from './context.js';
import type { CheckerContext } from './context.js';
import { traceOf } from './trace.js';
import type { Finding, Severity } from './types.js';

const SECRET_KINDS = new Set(['env', 'vars', 'secrets']);

/**
 * Секрет, прочитанный из окружения, уезжает в запросе, к которому приложил руку атакующий.
 *
 * Правило сознательно звучит не как «у этой ноды есть доступы». Доступы есть у любой ноды,
 * которая хоть что-то делает; сказать это про все — не находка, а инвентаризация. Путём утечки
 * дорогу делает то, что секрет пишется в запрос *и* кто-то извне влияет на то, куда этот
 * запрос уходит или что ещё он несёт.
 *
 * Два уровня, потому что случаи не равнозначны:
 *
 * - Сам адресат собирается из недоверенных данных — секрет уедет туда, куда скажут эти данные.
 *   Это путь утечки, а не риск такового.
 * - Адресат зафиксирован, но недоверенные данные до ноды доходят. Секрет и данные атакующего
 *   собираются в один запрос — на это стоит посмотреть, и не более того.
 */
export function secretExfilRisk(ctx: CheckerContext): Finding[] {
  const findings: Finding[] = [];

  for (const node of ctx.taint.graph.nodes) {
    const positions = ctx.params.expressionsIn(node);
    if (positions.length === 0) continue;

    const secrets = positions.filter(
      ({ kind, found }) =>
        (kind === 'url' || kind === 'egress-payload') &&
        found.parsed.refs.some((r) => SECRET_KINDS.has(r.kind)),
    );
    if (secrets.length === 0) continue;

    // Решает ли что-нибудь недоверенное, куда уйдёт этот запрос?
    const destination = positions.find(({ kind }) => kind === 'url');
    const steered =
      destination !== undefined &&
      urlControl(destination.found.parsed) !== 'none' &&
      untrustedRefs(ctx, node, destination.found.parsed.refs).length > 0;

    if (!steered && !ctx.taint.isTainted(node.name)) continue;

    const source = ctx.taint.sourcesReaching(node.name)[0];
    if (!source) continue;
    const walk = ctx.taint.front(source.node).walkTo(node.name);

    const severity: Severity = steered
      ? source.trust === 'semi-trusted'
        ? 'medium'
        : 'high'
      : 'medium';

    const held = [
      ...new Set(
        secrets.flatMap(({ found }) =>
          found.parsed.refs.filter((r) => SECRET_KINDS.has(r.kind)).map((r) => r.text),
        ),
      ),
    ];
    const paths = secrets.map(({ found }) => found.path);

    findings.push({
      rule: 'SECRET_EXFIL_RISK',
      severity,
      confidence: steered ? 'firm' : 'uncertain',
      workflow: ctx.taint.graph.name,
      title: steered
        ? `«${node.name}» отправляет ${held.join(', ')} туда, куда указывают недоверенные данные`
        : `«${node.name}» подмешивает ${held.join(', ')} в запрос, который несёт и недоверенные данные`,
      detail: steered
        ? `«${node.name}» читает ${held.join(', ')} в \`${paths.join('`, `')}\`, а URL самого ` +
          `запроса собирается из данных, которыми управляет «${source.node}». Кто пишет эти ` +
          `данные, тот и выбирает, куда уедет секрет.`
        : `«${node.name}» читает ${held.join(', ')} в \`${paths.join('`, `')}\`, и в ту же ` +
          `ноду приходят недоверенные данные из «${source.node}». Адресат зафиксирован, так ` +
          `что это место, где секрет и данные под влиянием атакующего собираются в один ` +
          `запрос, — а не показанная утечка.`,
      remediation: steered
        ? `Зафиксируйте адресата или сверяйте его со списком принимаемых хостов до того, как ` +
          `отработает эта нода. Доступы должны уходить только на хост, выбранный при ` +
          `написании воркфлоу.`
        : `Убедитесь, что секрет не может попасть в запрос, которым управляет ввод. Если ` +
          `адресат действительно зафиксирован, здесь делать нечего; если он может меняться — ` +
          `считайте это первым случаем.`,
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
      notes: [`Ссылки на секреты: ${held.join(', ')}`],
    });
  }

  return findings;
}
