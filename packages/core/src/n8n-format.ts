/**
 * Факты о формате JSON, в котором n8n хранит воркфлоу.
 *
 * Всё здесь проверено по фикстурам из `fixtures/real/` — неизменённым выгрузкам из
 * официальной библиотеки шаблонов n8n. Доказательства по каждому утверждению лежат в
 * `docs/n8n-json-format.md`.
 *
 * В этом модуле сознательно нет никакой логики анализа — только форма входных данных и
 * словарь, на котором говорит остальной сканер.
 */

/** Обычная связь данных: выход элементов одной ноды на вход следующей. */
export const MAIN_CONNECTION = 'main';

/**
 * Типы связей, которыми пользуются ноды LangChain/AI, — как это выглядит в корпусе.
 *
 * Числа ниже — количество воркфлоу, использующих каждый тип, в выборке из 794 воркфлоу
 * официальной библиотеки (см. docs/n8n-json-format.md).
 */
export const AI_CONNECTION_TYPES = [
  'ai_languageModel', // 465
  'ai_tool', // 221
  'ai_outputParser', // 164
  'ai_memory', // 158
  'ai_embedding', // 58
  'ai_document', // 48
  'ai_textSplitter', // 42
  'ai_vectorStore', // 22
  'ai_reranker', // 6
  'ai_retriever', // 3
] as const;

export type AiConnectionType = (typeof AI_CONNECTION_TYPES)[number];

const AI_CONNECTION_SET: ReadonlySet<string> = new Set<string>(AI_CONNECTION_TYPES);

/**
 * Истина для типов связи, подключающих sub-ноду к родительской AI-ноде.
 *
 * Считается любой тип `ai_*`, не только десять наблюдавшихся выше: n8n продолжает их
 * добавлять (`ai_reranker` появился недавно), и неизвестный тип `ai_*` следует считать
 * подключением sub-ноды, а не молча игнорировать.
 */
export function isAiConnectionType(type: string): boolean {
  return AI_CONNECTION_SET.has(type) || type.startsWith('ai_');
}

/**
 * Префиксы типов нод. Встроенные n8n поставляет под `n8n-nodes-base.*`; ноды AI/LangChain
 * живут под `@n8n/n8n-nodes-langchain.*`. Ноды сообщества используют имена собственных
 * пакетов, поэтому проверкой префикса нельзя *отвергать* тип ноды.
 */
export const BASE_NODE_PREFIX = 'n8n-nodes-base.';
export const LANGCHAIN_NODE_PREFIX = '@n8n/n8n-nodes-langchain.';

/** Одна нода в том виде, в каком она хранится в документе воркфлоу. */
export interface RawNode {
  /** Устойчивый uuid. Внимание: ключом в `connections` служит `name`, а НЕ `id`. */
  id?: string;
  name?: string;
  type?: string;
  typeVersion?: number;
  position?: [number, number];
  parameters?: Record<string, unknown>;
  credentials?: Record<string, unknown>;
  /** Выключенная нода по-прежнему есть в `connections`, но не выполняется. */
  disabled?: boolean;
  notes?: string;
  [key: string]: unknown;
}

/** Один конец связи внутри слота. */
export interface RawConnectionEndpoint {
  node?: string;
  type?: string;
  index?: number;
}

/**
 * `connections[имяНодыИсточника][типСвязи]` — это массив *выходных слотов*, а каждый слот —
 * массив концов связи. Номер слота важен: нода `if` кладёт ветку true в слот 0, а ветку
 * false — в слот 1.
 *
 * Оба уровня здесь намеренно `unknown`: в корпусе есть документы, где слот вообще не массив,
 * поэтому парсер проверяет, а не доверяет. См. `fixtures/real/06686-*.json`.
 */
export type RawConnectionSlots = unknown;

export interface RawWorkflow {
  name?: string;
  nodes?: unknown;
  connections?: unknown;
  settings?: Record<string, unknown>;
  /** Подменённый вывод ноды, сохранённый в редакторе; есть примерно у 10% настоящих воркфлоу. */
  pinData?: Record<string, unknown>;
  [key: string]: unknown;
}
