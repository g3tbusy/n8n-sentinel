/**
 * Словарь, на котором говорит реестр правил. Сознательно закрытый: чекер, вынужденный
 * обрабатывать неограниченный набор имён эффектов, не может рассуждать о severity.
 */

export type NodeRole =
  /** Приносит данные из-под контроля, который воркфлоу не имеет. */
  | 'source'
  /** Выполняет действие, эффект которого выходит за пределы воркфлоу. */
  | 'sink'
  /** Проносит данные сквозь себя, возможно преобразуя. */
  | 'propagator'
  /** Ограничивает то, что может пройти, или ставит на пути человека. */
  | 'sanitizer';

export type SideEffect =
  | 'send-message'
  | 'publish-content'
  | 'write-database'
  | 'write-file'
  | 'delete-data'
  | 'http-egress'
  | 'execute-code'
  | 'execute-command'
  | 'payment'
  | 'admin-api'
  /** Возвращает данные тому, кто дёрнул webhook, — канал раскрытия, а не действие. */
  | 'disclose-response';

export type TrustLevel =
  /** Это может подсунуть кто угодно из интернета. Публичный webhook, форма, чат-эндпоинт. */
  | 'untrusted-public'
  /** Приходит извне, но через названную сторону: почтовый ящик, лента, скрапленная страница. */
  | 'untrusted-external'
  /** Собственное хранилище, в котором всё равно может лежать то, что туда положили раньше. */
  | 'semi-trusted';

export type SanitizerKind =
  /** Человек должен подтвердить, прежде чем выполнение продолжится. */
  | 'human-approval'
  /** Вывод загоняется в объявленную форму. */
  | 'schema-validation'
  /** Условие решает, пойдут ли данные дальше. О том, *что* именно оно проверяет, не говорит. */
  | 'conditional';

export interface SinkInfo {
  readonly effect: SideEffect;
  /** Можно ли отменить действие после того, как оно совершено. Отправленное письмо — нет, запись в кэш — да. */
  readonly irreversible: boolean;
}

export interface SourceInfo {
  readonly trust: TrustLevel;
}

export interface SanitizerInfo {
  readonly kind: SanitizerKind;
  /**
   * `strong`-гейты останавливают путь наглухо — человек его одобрил.
   * `weak` — только *может быть*: нода `if` является гейтом ровно тогда, когда её условие
   * проверяет заражённое значение, а для этого нужен анализ выражений из фазы 4. Записанное
   * здесь различие не даёт фазе 3 ни игнорировать гейты, ни слепо им доверять.
   */
  readonly strength: 'strong' | 'weak';
}

/** Значения, определяющие, что делает нода, — уже после применения дефолтов n8n. */
export interface ResolvedParameters {
  readonly resource: string | undefined;
  readonly operation: string | undefined;
  readonly method: string | undefined;
  readonly mode: string | undefined;
  /** Как продолжается нода Wait: возобновление через `webhook` или `form` открывает публичный URL. */
  readonly resume: string | undefined;
}

export interface Classification {
  readonly type: string;
  readonly roles: readonly NodeRole[];
  /** Нода запускает модель. Отличается от `invokesTools`: chain — это LLM, но он ничего не вызывает. */
  readonly llm: boolean;
  /** Нода может решить вызвать инструменты — свойство, превращающее инъекцию в действие. */
  readonly invokesTools: boolean;
  /**
   * Нода передаёт данные тому, чего этот анализ не видит, — другому воркфлоу, запускаемому
   * шагом или инструментом. Его sink-и невидимы, поэтому путь, кончающийся здесь, не
   * безопасен, а не прослежен, и находка так и говорит, вместо того чтобы гадать в любую
   * сторону.
   */
  readonly boundary: boolean;
  readonly source: SourceInfo | undefined;
  readonly sink: SinkInfo | undefined;
  readonly sanitizer: SanitizerInfo | undefined;
  /** Ложь, когда этот тип ноды не покрыт ни одним правилом. */
  readonly known: boolean;
  /**
   * Истина, когда сработал вариант, зависящий от параметров. Ложь означает, что использована
   * базовая классификация записи, потому что ни один вариант не подошёл, — это стоит знать,
   * прежде чем показывать по ней critical-находку.
   */
  readonly matchedVariant: boolean;
  /** Заполнено, когда правило взято у базовой ноды за типом `…Tool`, например `gmailTool`. */
  readonly derivedFrom: string | undefined;
  readonly resolved: ResolvedParameters;
  readonly notes: readonly string[];
}

/** Одно условие `when:`. Все перечисленные ключи должны совпасть; ключ перечисляет принимаемые значения. */
export interface RuleCondition {
  readonly resource?: readonly string[];
  readonly operation?: readonly string[];
  readonly method?: readonly string[];
  readonly mode?: readonly string[];
  readonly resume?: readonly string[];
}

export interface RuleVariant {
  readonly when: RuleCondition;
  readonly roles?: readonly NodeRole[];
  readonly source?: SourceInfo;
  readonly sink?: SinkInfo;
  readonly sanitizer?: SanitizerInfo;
  readonly llm?: boolean;
  readonly invokesTools?: boolean;
  readonly boundary?: boolean;
  readonly note?: string;
}

export interface RuleEntry {
  readonly type: string;
  readonly roles: readonly NodeRole[];
  readonly llm?: boolean;
  readonly invokesTools?: boolean;
  readonly boundary?: boolean;
  readonly source?: SourceInfo;
  readonly sink?: SinkInfo;
  readonly sanitizer?: SanitizerInfo;
  readonly note?: string;
  readonly variants?: readonly RuleVariant[];
  /** Отключает подстановку правила `…Tool` для типов, которые просто заканчиваются на «Tool». */
  readonly noToolDerivation?: boolean;
}

export interface RuleFile {
  readonly nodes: readonly RuleEntry[];
}

/** Форма сгенерированного node-defaults.json. */
export interface NodeDefaults {
  readonly n8nVersion: string;
  readonly nodes: Readonly<
    Record<
      string,
      {
        readonly defaultVersion?: number;
        readonly usableAsTool?: boolean;
        readonly defaults?: Readonly<Record<string, string | Record<string, string>>>;
        readonly options?: Readonly<Record<string, readonly string[]>>;
      }
    >
  >;
}
