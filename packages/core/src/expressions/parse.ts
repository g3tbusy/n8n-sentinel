/**
 * Выражения n8n — ровно на ту глубину, которая нужна taint-анализу.
 *
 * Это не парсер JavaScript и не пытается им быть. Вопрос, на который он отвечает, узкий:
 * **какие данные втягивает этот параметр и в какое место строки они попадают.** Этого
 * достаточно, чтобы отличить `https://api.example.com/{{ $json.id }}`, где атакующий
 * управляет сегментом пути, от `{{ $json.url }}`, где он выбирает хост.
 *
 * Параметр является выражением, когда n8n сохранил его с ведущим `=`: этим префиксом n8n сам
 * записывает, что поле в режиме выражения. Про единственное исключение, которое навязал
 * корпус, и почему оно того стоит, — см. `isExpression`.
 */

export type RefKind =
  /** Собственный вход ноды: `$json`, `$input`. Недоверенный ровно тогда, когда недоверенна нода. */
  | 'json'
  /** Вывод другой ноды: `$('Имя')`, `$node["Имя"]`, `$items("Имя")`. */
  | 'node'
  /** Значение, которое пишет модель: `$fromAI(...)`. Недоверенное, когда недоверен держащий его агент. */
  | 'fromAI'
  /** Окружение процесса: `$env`. */
  | 'env'
  /** Переменные воркфлоу или инстанса: `$vars`. */
  | 'vars'
  /** Хранилище секретов: `$secrets`. */
  | 'secrets'
  /** Часы, метаданные воркфлоу и выполнения — ничего, что пишет атакующий. */
  | 'runtime';

export interface ExpressionRef {
  readonly kind: RefKind;
  /** Для ссылок вида `node` — названная нода. `undefined`, когда имя само вычисляется. */
  readonly node: string | undefined;
  /**
   * Единственное поле, читаемое у этой ноды, если ссылка его называет:
   * `$('Config').json.BASE_URL` читает `BASE_URL`. Undefined, когда берётся элемент целиком.
   *
   * В этом и разница между «данные из ноды, до которой доходит taint» и «данные, написанные
   * атакующим». Нода Set ниже вебхука держит и то и другое: захардкоженный базовый URL и всё,
   * что пришло в запросе.
   */
  readonly field: string | undefined;
  /** Ссылка в том виде, в каком она встретилась, — чтобы процитировать её читателю. */
  readonly text: string;
}

export interface Interpolation {
  /** То, что было между фигурными скобками. */
  readonly text: string;
  /** Всё, что стоит в параметре до этой подстановки, — литеральный префикс. */
  readonly before: string;
  readonly refs: readonly ExpressionRef[];
}

export interface ParsedExpression {
  readonly raw: string;
  readonly interpolations: readonly Interpolation[];
  readonly refs: readonly ExpressionRef[];
}

/** Одно выражение, найденное где-то внутри параметров ноды. */
export interface FoundExpression {
  /** Путь через точку внутри `parameters`, с `[]` для элементов массива. */
  readonly path: string;
  readonly parsed: ParsedExpression;
}

/**
 * Собственный вычислитель n8n проверяет одно: начинается ли строка с `=`. Здесь так же — с
 * одним исключением.
 *
 * В библиотеке 189 параметров `query` содержат `{{ … }}` без `=`, и 17 из них читают
 * `{{ $fromAI(…) }}`. Строго говоря, это литеральный текст, а воркфлоу сломан. Но `$fromAI`
 * как литеральный текст бессмыслен, параметры инструментов n8n разрешает отдельным проходом,
 * а находка, которую это скрыло бы, — модель, пишущая SQL-запрос целиком, — худшее, что
 * вообще умеет находить этот сканер. Узкое исключение стоит возможного ложного срабатывания
 * на сломанном воркфлоу; его отсутствие стоит той находки.
 */
export const isExpression = (value: unknown): value is string =>
  typeof value === 'string' && (value.startsWith('=') || /\{\{[\s\S]*\$fromAI/.test(value));

export function parseExpression(raw: string): ParsedExpression {
  const body = raw.startsWith('=') ? raw.slice(1) : raw;
  const interpolations: Interpolation[] = [];

  for (const span of interpolationSpans(body)) {
    const text = body.slice(span.start + 2, span.end - 2);
    interpolations.push({
      text,
      before: body.slice(0, span.start),
      refs: referencesIn(text),
    });
  }

  return { raw, interpolations, refs: interpolations.flatMap((i) => i.refs) };
}

/**
 * Находит участки `{{ … }}` подсчётом скобок, а не ленивым сопоставлением.
 *
 * `{{ items.map(i => ({ id: i.id })) }}` закрывает внутренний объект раньше разделителя, и
 * совпадение по `.*?\}\}` закончило бы выражение на середине. Строки в кавычках
 * перешагиваются, чтобы скобка внутри них не сбивала счёт.
 */
function interpolationSpans(body: string): { start: number; end: number }[] {
  const spans: { start: number; end: number }[] = [];

  for (let i = 0; i < body.length - 1; i++) {
    if (body[i] !== '{' || body[i + 1] !== '{') continue;

    let depth = 2;
    let j = i + 2;
    while (j < body.length && depth > 0) {
      const ch = body[j];
      if (ch === "'" || ch === '"' || ch === '`') {
        j = endOfString(body, j);
        continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      j++;
    }
    if (depth !== 0) break; // Скобки не сошлись: рассуждать об остатке не о чем.

    spans.push({ start: i, end: j });
    i = j - 1;
  }
  return spans;
}

/** Индекс сразу за закрывающей кавычкой или конец строки, если она так и не закрылась. */
function endOfString(body: string, start: number): number {
  const quote = body[start];
  for (let i = start + 1; i < body.length; i++) {
    if (body[i] === '\\') {
      i++;
      continue;
    }
    if (body[i] === quote) return i + 1;
  }
  return body.length;
}

/**
 * Ссылка на ноду, чьё имя — голый литерал: кавычка должна закрыться, и вызов должен на этом
 * закончиться. `$('Шаг ' + $json.n)` тоже открывается кавычкой, и вычитать оттуда `Шаг `
 * было бы догадкой — причём неверной, указывающей на несуществующую ноду.
 */
const NAMED_NODE = /\$(?:\(|node\[|items\()\s*(['"`])((?:[^\\]|\\.)*?)\1\s*[)\]]/g;
const ANY_NODE = /\$(?:\(|node\[|items\()/g;
const RUNTIME =
  /\$(now|today|workflow|execution|runIndex|itemIndex|prevNode|nodeVersion|position)\b/g;

/** `.json.ИМЯ`, `.json["ИМЯ"]` — единственное поле, которое читает ссылка, если читает. */
const FIELD_AFTER_JSON =
  /^[^.[]*(?:\.(?:item|first\(\)|last\(\)|all\(\)\[\d+\]))?\.json(?:\.(\w+)|\[\s*['"]([^'"]+)['"]\s*\])/;

function fieldRead(after: string): string | undefined {
  const m = FIELD_AFTER_JSON.exec(after);
  if (!m) return undefined;
  return m[1] ?? m[2];
}

function referencesIn(text: string): ExpressionRef[] {
  const refs: ExpressionRef[] = [];
  const add = (kind: RefKind, node: string | undefined, snippet: string, field?: string): void => {
    refs.push({ kind, node, field, text: snippet });
  };

  const named = new Set<number>();
  for (const m of text.matchAll(NAMED_NODE)) {
    named.add(m.index ?? -1);
    const after = text.slice((m.index ?? 0) + m[0].length);
    add('node', m[2], m[0], fieldRead(after));
  }
  // Любой другой `$(…)` называет цель вычислением. Записывается без имени, чтобы чекер знал,
  // что чтение из другой ноды было, а поток не терялся молча.
  for (const m of text.matchAll(ANY_NODE)) {
    if (!named.has(m.index ?? -1)) add('node', undefined, m[0]);
  }

  if (/\$fromAI\s*\(/.test(text)) add('fromAI', undefined, '$fromAI(…)');
  if (/\$json\b/.test(text)) add('json', undefined, '$json');
  if (/\$input\b/.test(text)) add('json', undefined, '$input');
  if (/\$env\b/.test(text)) add('env', undefined, '$env');
  if (/\$vars\b/.test(text)) add('vars', undefined, '$vars');
  if (/\$secrets\b/.test(text)) add('secrets', undefined, '$secrets');
  for (const m of text.matchAll(RUNTIME)) add('runtime', undefined, m[0]);

  return refs;
}

/**
 * Все выражения где угодно внутри параметров ноды вместе с путём, которым до них дошли.
 *
 * Параметры вложены произвольно — заголовки HTTP-ноды лежат в
 * `headerParameters.parameters[].value`, — и именно путь может назвать файл правил.
 */
export function findExpressions(parameters: unknown): FoundExpression[] {
  const found: FoundExpression[] = [];

  const walk = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      if (isExpression(value)) found.push({ path, parsed: parseExpression(value) });
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) walk(item, `${path}[]`);
      return;
    }
    if (value !== null && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        walk(child, path === '' ? key : `${path}.${key}`);
      }
    }
  };

  walk(parameters, '');
  return found;
}

/** Сырой текст параметра, который не является выражением: тело кода, литеральная строка SQL. */
export function readString(parameters: unknown, path: string): string | undefined {
  const segments = path.split('.');
  let cursor: unknown = parameters;
  for (const segment of segments) {
    if (cursor === null || typeof cursor !== 'object') return undefined;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return typeof cursor === 'string' ? cursor : undefined;
}
