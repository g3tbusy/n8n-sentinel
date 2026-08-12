import type { RawNode } from '../n8n-format.js';

/**
 * Что ребро *значит* для потока данных — в отличие от того, как оно хранится.
 *
 * Объект `connections` в n8n описывает проводку, а не направление движения. Два из этих видов
 * ('invocation' и 'attachment') существуют потому, что хранимое направление и направление, в
 * котором данные действительно движутся, — не одно и то же; см. docs/n8n-json-format.md §5.
 */
export type EdgeKind =
  /** Обычный поток элементов по связи `main`. Хранимое направление и есть настоящее. */
  | 'data'
  /**
   * Агент → инструмент. Синтезируется, никогда не хранится: агент решает вызвать инструмент
   * и готовит его аргументы, поэтому всё, что держит агент, доходит до параметров инструмента.
   * Это то ребро, по которому prompt injection добирается до побочного эффекта.
   */
  | 'invocation'
  /**
   * Инструмент → агент. Именно так хранится `ai_tool`, и это тоже настоящий поток: результат
   * инструмента попадает в контекст агента.
   */
  | 'return'
  /**
   * Sub-нода → родитель, для всех остальных типов `ai_*`. Языковая модель, память, загрузчик
   * документов или векторное хранилище отдают свой вывод ноде, к которой подключены; хранимое
   * направление уже указывает туда.
   */
  | 'attachment';

export interface GraphNode {
  /** Имя ноды. Это та идентичность, которой пользуется `connections`; см. docs §2. */
  readonly name: string;
  /** Тип ноды, например `n8n-nodes-base.gmailTrigger`. Пустая строка, если документ его не дал. */
  readonly type: string;
  readonly typeVersion: number | undefined;
  /** Выключенная нода остаётся подключённой, но не выполняется; n8n пропускает данные сквозь неё. */
  readonly disabled: boolean;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly credentials: Readonly<Record<string, unknown>>;
  /** Истина, когда `pinData` воркфлоу подменяет вывод этой ноды. Аргументом безопасности не является. */
  readonly hasPinnedData: boolean;
  /** Нода ровно в том виде, в каком она была в документе, — для чекеров, которым нужно больше. */
  readonly raw: RawNode;
}

export interface GraphEdge {
  readonly from: string;
  readonly to: string;
  readonly kind: EdgeKind;
  /** Ключ в `connections`, откуда это пришло: `main`, `ai_tool`, `ai_languageModel`, … */
  readonly connectionType: string;
  /** Выходной порт ноды-источника. Слоты 0 и 1 у `if` — это ветки true и false. */
  readonly slot: number;
  /** Входной порт ноды-получателя. */
  readonly index: number;
  /**
   * Истина, когда это ребро создала нормализация, а не прочитал документ. Выведенными бывают
   * только рёбра `invocation`. Полезно, когда находку объясняют пользователю, который смотрит
   * на холст и такой стрелки там не увидит.
   */
  readonly derived: boolean;
}
