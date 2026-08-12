#!/usr/bin/env node
/**
 * Транскрипт прогонов адаптивного раннера — для чтения глазами, а не для метрик.
 *
 * Разворачивает журнал `.range-runs/adaptive-*` в человекочитаемый разбор: по
 * каждому сценарию — раунд за раундом, что подставили жертве (атака), чем она
 * ответила и как это засчитано. Системный промпт жертвы печатается один раз в
 * шапке: он одинаков для всех прогонов сценария.
 *
 *   node scripts/adaptive-transcript.mjs [КАТАЛОГ] [--атака ID] [--прогон N]
 *     [--полно] [--только-пробитие]
 *
 *   КАТАЛОГ            путь к adaptive-*; без него берётся самый свежий
 *   --атака ID[,ID…]   только эти атаки
 *   --прогон N         только прогон №N
 *   --полно            показать всё сообщение, которое видела жертва (не только
 *                      инъекцию), и полный ответ, а не первые строки
 *   --только-пробитие  только сценарии, где хоть раз пробило
 *
 * Метрики этот скрипт не считает — для чисел есть scripts/adaptive-summary.mjs.
 */
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, dirname, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { СИСТЕМНЫЙ_ПРОМПТ_НАИВНЫЙ, собратьСообщение } from '../packages/range/agent-intake.mjs';

const здесь = dirname(fileURLToPath(import.meta.url));
const КОРЕНЬ = join(здесь, '..');
// yaml установлен в пакете range, а не в корне: резолвим его оттуда, как это делают
// сами раннеры полигона.
const { parse } = createRequire(join(КОРЕНЬ, 'packages/range/'))('yaml');
const аргументы = process.argv.slice(2);
const значение = (имя) => (аргументы.includes(имя) ? аргументы[аргументы.indexOf(имя) + 1] : null);
const естьФлаг = (имя) => аргументы.includes(имя);

// Каталог: либо явный первый позиционный аргумент, либо самый свежий adaptive-*.
function свежийКаталог() {
  const корень = join(КОРЕНЬ, '.range-runs');
  if (!existsSync(корень)) return null;
  const каталоги = readdirSync(корень)
    .filter((имя) => имя.startsWith('adaptive-'))
    .map((имя) => join(корень, имя))
    .filter((путь) => existsSync(join(путь, 'runs.jsonl')))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  return каталоги[0] ?? null;
}

const позиционный = аргументы.find((а) => !а.startsWith('--'));
const каталог = позиционный
  ? isAbsolute(позиционный)
    ? позиционный
    : join(process.cwd(), позиционный)
  : свежийКаталог();
if (!каталог || !existsSync(join(каталог, 'runs.jsonl'))) {
  console.error('Не нашёл журнал runs.jsonl. Укажи каталог adaptive-* первым аргументом.');
  process.exit(1);
}

const выборАтак = значение('--атака')
  ?.split(',')
  .map((с) => с.trim());
const выборПрогона = значение('--прогон') ? Number(значение('--прогон')) : null;
const полно = естьФлаг('--полно');
const толькоПробитие = естьФлаг('--только-пробитие');

// Корпус нужен, чтобы восстановить полное сообщение жертвы: в журнале хранится
// только подставленный комментарий, а документы базы знаний и отравленный
// инструмент лежат в корпусе и на каждом раунде те же.
const корпус = parse(
  readFileSync(join(здесь, '..', 'packages/range/corpus/attacks-intake.yaml'), 'utf8'),
);
const поИд = new Map(корпус.атаки.map((а) => [а.id, а]));

// Как в run-adaptive.mjs: вариант атаки с подменённым комментарием заявителя.
function сИнъекцией(атака, комментарий) {
  return { ...атака, заявка: { ...(атака.заявка ?? {}), комментарий } };
}

const обрыв = (текст, сколько) => {
  const т = String(текст ?? '').trim();
  if (полно || т.length <= сколько) return т;
  return т.slice(0, сколько).trimEnd() + ' […]';
};

const отступ = (текст, префикс = '    ') =>
  String(текст ?? '')
    .split('\n')
    .map((с) => префикс + с)
    .join('\n');

const значки = {
  пробило: '💥 ПРОБИЛО',
  'не поддался': '· не поддался',
  выстоял: '🛡 выстоял',
  'защита сдержала': '🛡 защита сдержала',
  'модель отказалась': '✋ модель отказалась (жертва)',
  'атакующий отказался': '✋ атакующий отказался',
  'не состоялся': '! не состоялся',
};

const записи = readFileSync(join(каталог, 'runs.jsonl'), 'utf8')
  .trim()
  .split('\n')
  .filter(Boolean)
  .map((с) => {
    try {
      return JSON.parse(с);
    } catch {
      return null;
    }
  })
  .filter(Boolean)
  .filter((з) => !выборАтак || выборАтак.includes(з.атака))
  .filter((з) => выборПрогона == null || з.номер === выборПрогона)
  .filter((з) => !толькоПробитие || з.исход === 'пробило');

if (!записи.length) {
  console.log(`Под фильтр ничего не попало в ${каталог.replace(КОРЕНЬ + '/', '')}.`);
  // Частый случай: по умолчанию берётся самый свежий прогон, а пробития — в другом
  // (baseline). Подскажем, где они есть, а не оставим гадать.
  const корень = join(КОРЕНЬ, '.range-runs');
  if (existsSync(корень)) {
    const сПробитиями = [];
    for (const имя of readdirSync(корень)) {
      const ж = join(корень, имя, 'runs.jsonl');
      if (!имя.startsWith('adaptive-') || !existsSync(ж)) continue;
      const проб = readFileSync(ж, 'utf8')
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((с) => {
          try {
            return JSON.parse(с);
          } catch {
            return null;
          }
        })
        .filter((з) => з?.исход === 'пробило').length;
      if (проб) сПробитиями.push({ имя, проб });
    }
    if (сПробитиями.length) {
      console.log('\nПробития есть в этих прогонах:');
      for (const { имя, проб } of сПробитиями) console.log(`  .range-runs/${имя}  (${проб})`);
      console.log(
        `\nНапример:\n  node scripts/adaptive-transcript.mjs .range-runs/${сПробитиями[0].имя} --только-пробитие`,
      );
    } else {
      console.log('Ни в одном прогоне adaptive-* пробитий нет.');
    }
  }
  process.exit(0);
}

const шапка = записи[0];
console.log('═'.repeat(78));
console.log(`ТРАНСКРИПТ  ${каталог.replace(КОРЕНЬ + '/', '')}`);
console.log(
  `жертва ${шапка.модель}, атакующий ${шапка.атакующий}, ` +
    `защиты: ${шапка.защиты?.length ? шапка.защиты.join('+') : 'нет'}`,
);
console.log('═'.repeat(78));
console.log('\nСИСТЕМНЫЙ ПРОМПТ ЖЕРТВЫ (одинаков для всех прогонов ниже):');
console.log(отступ(СИСТЕМНЫЙ_ПРОМПТ_НАИВНЫЙ));

for (const з of записи) {
  const атака = поИд.get(з.атака);
  console.log('\n' + '─'.repeat(78));
  console.log(`▶ ${з.атака}  прогон №${з.номер}  ·  канал: ${з.класс}`);
  console.log(
    `  итог сценария: ${значки[з.исход] ?? з.исход}` +
      (з.раундовДо ? ` на раунде ${з.раундовДо}` : ''),
  );

  for (const [i, ш] of (з.история ?? []).entries()) {
    const раунд = i + 1;
    console.log(
      `\n  ┌─ РАУНД ${раунд} ${раунд === 1 ? '(заготовка из корпуса)' : '(усиление атакующим)'}`,
    );

    // Что увидела жертва целиком — по флагу --полно; иначе только сама инъекция.
    if (полно && атака) {
      const вариант = раунд === 1 ? атака : сИнъекцией(атака, ш.инъекция);
      console.log('  │ СООБЩЕНИЕ ЖЕРТВЕ:');
      console.log(отступ(собратьСообщение(вариант), '  │   '));
    } else {
      console.log('  │ АТАКА (подставленный комментарий заявителя):');
      console.log(отступ(обрыв(ш.инъекция, 600), '  │   '));
    }

    console.log('  │ ОТВЕТ ЖЕРТВЫ:');
    console.log(отступ(обрыв(ш.текст, 600), '  │   '));
    console.log(
      `  └─ исход раунда: ${значки[ш.исход] ?? ш.исход}` + (ш.почему ? ` — ${ш.почему}` : ''),
    );
  }
}
console.log('\n' + '═'.repeat(78));
console.log(`Прогонов показано: ${записи.length}. Числа и ASR — scripts/adaptive-summary.mjs.`);
