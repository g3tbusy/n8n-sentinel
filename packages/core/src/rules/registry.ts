import type { GraphNode } from '../graph/types.js';
import type {
  Classification,
  NodeDefaults,
  ResolvedParameters,
  RuleCondition,
  RuleEntry,
  RuleFile,
  RuleVariant,
} from './types.js';

const TOOL_SUFFIX = 'Tool';

/**
 * Назначает каждой ноде её роль в безопасности, используя собственные дефолты параметров
 * n8n, чтобы понять, что нода на самом деле делает.
 *
 * Сложность не в таксономии, а в том, что `operation` обычно отсутствует. n8n не сохраняет
 * параметры, оставленные на значении по умолчанию, поэтому нода Gmail без `operation` не
 * двусмысленна — это *отправка*. Разрешение этого по сгенерированной таблице дефолтов
 * превращает 155 из 265 нод Gmail в корпусе из «неизвестных» в «необратимый sink» и ровно так
 * же не даёт назвать записью 328 нод Google Sheets, у которых дефолт — `read`.
 */
export class NodeRegistry {
  readonly #byType: ReadonlyMap<string, RuleEntry>;
  readonly #defaults: NodeDefaults;

  constructor(rules: RuleFile, defaults: NodeDefaults) {
    const byType = new Map<string, RuleEntry>();
    for (const entry of rules.nodes) byType.set(entry.type, entry);
    this.#byType = byType;
    this.#defaults = defaults;
  }

  get size(): number {
    return this.#byType.size;
  }

  get n8nVersion(): string {
    return this.#defaults.n8nVersion;
  }

  /** Все типы нод, для которых у реестра есть правило. */
  types(): readonly string[] {
    return [...this.#byType.keys()];
  }

  classify(node: GraphNode): Classification {
    const resolved = this.resolve(node);

    let entry = this.#byType.get(node.type);
    let derivedFrom: string | undefined;

    // n8n генерирует вариант `…Tool` для любой ноды, помеченной `usableAsTool`, — в этом
    // каталоге их 275. `gmailTool` — это нода Gmail, подключённая к агенту, с теми же
    // операциями и теми же последствиями, поэтому она наследует то же правило.
    if (!entry && node.type.endsWith(TOOL_SUFFIX)) {
      const base = node.type.slice(0, -TOOL_SUFFIX.length);
      const baseEntry = this.#byType.get(base);
      if (baseEntry && baseEntry.noToolDerivation !== true) {
        entry = baseEntry;
        derivedFrom = base;
      }
    }

    if (!entry) {
      return {
        type: node.type,
        roles: [],
        llm: false,
        invokesTools: false,
        boundary: false,
        source: undefined,
        sink: undefined,
        sanitizer: undefined,
        known: false,
        matchedVariant: false,
        derivedFrom: undefined,
        resolved,
        notes: [],
      };
    }

    const variant = (entry.variants ?? []).find((v) => matches(v.when, resolved));
    return merge(entry, variant, resolved, derivedFrom);
  }

  /**
   * Подставляет параметры, которые n8n не сохранил.
   *
   * `resource` должен разрешаться первым, потому что от него зависит операция по умолчанию:
   * у Gmail для сообщений дефолт — `send`, а для черновиков — `create`.
   */
  resolve(node: GraphNode): ResolvedParameters {
    const declared = this.#defaults.nodes[node.type]?.defaults ?? {};
    const params = node.parameters;

    const pick = (key: string, resource?: string): string | undefined => {
      const explicit = params[key];
      if (typeof explicit === 'string') {
        // `=` помечает выражение n8n: значение вычисляется во время выполнения. Это ни
        // литеральный текст, ни дефолт — оно действительно неизвестно, и признание этого не
        // даёт уверенно классифицировать ноду, чья операция выбирается динамически.
        return explicit.startsWith('=') ? undefined : explicit;
      }
      if (explicit !== undefined) return undefined;

      const fallback = declared[key];
      if (typeof fallback === 'string') return fallback;
      if (fallback && typeof fallback === 'object') {
        if (resource !== undefined && typeof fallback[resource] === 'string') {
          return fallback[resource];
        }
        if (typeof fallback['*'] === 'string') return fallback['*'];
      }
      return undefined;
    };

    const resource = pick('resource');
    return {
      resource,
      operation: pick('operation', resource),
      method: pick('method', resource),
      mode: pick('mode', resource),
      resume: pick('resume', resource),
    };
  }
}

function matches(when: RuleCondition, resolved: ResolvedParameters): boolean {
  const check = (accepted: readonly string[] | undefined, actual: string | undefined): boolean =>
    accepted === undefined || (actual !== undefined && accepted.includes(actual));

  return (
    check(when.resource, resolved.resource) &&
    check(when.operation, resolved.operation) &&
    check(when.method, resolved.method) &&
    check(when.mode, resolved.mode) &&
    check(when.resume, resolved.resume)
  );
}

function merge(
  entry: RuleEntry,
  variant: RuleVariant | undefined,
  resolved: ResolvedParameters,
  derivedFrom: string | undefined,
): Classification {
  const notes: string[] = [];
  if (entry.note !== undefined) notes.push(entry.note);
  if (variant?.note !== undefined) notes.push(variant.note);

  return {
    type: entry.type,
    roles: variant?.roles ?? entry.roles,
    llm: variant?.llm ?? entry.llm ?? false,
    invokesTools: variant?.invokesTools ?? entry.invokesTools ?? false,
    boundary: variant?.boundary ?? entry.boundary ?? false,
    // Вариант заменяет базовую классификацию по той грани, которую объявляет, а не
    // подмешивается в неё: `gmail`, читающий почту, — это не одновременно `gmail`,
    // отправляющий её.
    source: variant ? variant.source : entry.source,
    sink: variant ? variant.sink : entry.sink,
    sanitizer: variant ? variant.sanitizer : entry.sanitizer,
    known: true,
    matchedVariant: variant !== undefined,
    derivedFrom,
    resolved,
    notes,
  };
}
