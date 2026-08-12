import type { ParsedExpression } from './parse.js';

/**
 * Какую часть URL решает выражение.
 *
 * В этом и разница между находкой и ложной тревогой. `{{ $json.url }}` позволяет атакующему
 * выбрать хост и отправить ваши доступы куда угодно; `https://api.stripe.com/v1/customers/{{
 * $json.id }}` позволяет ему выбрать идентификатор клиента на хосте, зафиксированном при
 * написании воркфлоу. И то и другое — недоверенный ввод в URL, и если называть их одним и
 * тем же, первое утонет под тысячами второго: 6129 HTTP-нод официальной библиотеки собирают
 * URL из выражения, и почти все они относятся ко второму виду.
 */
export type UrlControl =
  /** Весь URL, включая схему. */
  | 'full'
  /** Хост при зафиксированной схеме. Этого всё равно хватает, чтобы выбрать, куда уйдёт запрос. */
  | 'host'
  /** Сегмент пути на уже выбранном хосте. */
  | 'path'
  /** Значение в query. */
  | 'query'
  /** Подстановки нет вовсе. */
  | 'none';

export function urlControl(parsed: ParsedExpression): UrlControl {
  const first = parsed.interpolations[0];
  if (!first) return 'none';

  // `{{ 'https://api.example.com/v1/' + $json.id }}` кладёт фиксированную часть *внутрь*
  // скобок. Если читать только то, что стоит перед ними, это будет объявлено свободным
  // выбором хоста — то есть ровно наоборот; в корпусе десяток воркфлоу написаны именно так.
  const prefix = first.before + leadingLiteral(first.text);

  const scheme = prefix.indexOf('://');
  if (scheme === -1) return 'full';

  const authority = prefix.slice(scheme + 3);
  if (authority.includes('?')) return 'query';
  if (authority.includes('/')) return 'path';
  return 'host';
}

/** Строковый литерал, с которого начинается подстановка, если она к нему приклеивается. */
function leadingLiteral(text: string): string {
  const m = /^\s*(['"`])((?:[^\\]|\\.)*?)\1\s*\+/.exec(text);
  return m ? (m[2] as string) : '';
}

/**
 * Конструкции, превращающие строку в выполнение.
 *
 * Список сознательно короткий. В выборке из 794 воркфлоу ни одна нода Code не вызывает
 * `eval` и ни одна не импортирует `child_process`; пять вызывают `require`. То есть находки
 * лежат не здесь, а список подлиннее, собранный на догадках, добавил бы только шума — см.
 * docs/scoring.md.
 */
const DANGEROUS = [
  'eval(',
  'new Function(',
  'Function(',
  'child_process',
  'execSync',
  'spawnSync',
  'vm.runIn',
] as const;

export function dangerousConstructs(code: string): string[] {
  return DANGEROUS.filter((needle) => code.includes(needle));
}
