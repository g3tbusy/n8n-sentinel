/**
 * Где нода лежит в файле, чтобы находка могла указать на строку.
 *
 * Это текстовый поиск, а не позиция из парсера. Парсер работает с уже разобранным JSON, и
 * протаскивать через него смещения в байтах значило бы усложнить каждый слой ради одного
 * потребителя. Читателю — или вкладке Security на GitHub — нужна строка, куда прыгнуть, а
 * `"name": "Send Email"` встречается в корректном воркфлоу ровно один раз: имена нод
 * уникальны, а `connections` ссылается на них ключами объекта и значениями `"node":`, и ни то
 * ни другое сюда не подходит.
 *
 * Когда найти не удаётся, находка остаётся в силе — она просто указывает на файл, а не на
 * строку. Это правильный отказ: отсутствующий номер строки — меньшая ложь, чем неверный.
 */

export interface SourceRegion {
  /** Нумерация с единицы, как считают все редакторы и SARIF. */
  readonly line: number;
  readonly column: number;
  readonly length: number;
}

export function locateNode(text: string, nodeName: string): SourceRegion | undefined {
  const needle = `"name": ${JSON.stringify(nodeName)}`;
  let index = text.indexOf(needle);

  // n8n пишет `"name": "x"`, но пересохранённый документ мог потерять пробел.
  if (index === -1) index = text.indexOf(`"name":${JSON.stringify(nodeName)}`);
  if (index === -1) return undefined;

  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < index; i++) {
    if (text[i] === '\n') {
      line++;
      lineStart = i + 1;
    }
  }

  return {
    line,
    column: index - lineStart + 1,
    length: JSON.stringify(nodeName).length + 8,
  };
}
