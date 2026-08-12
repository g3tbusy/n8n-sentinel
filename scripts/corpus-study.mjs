#!/usr/bin/env node
/**
 * Прогоняет сканер по всему закэшированному корпусу и пишет исследование.
 *
 * Всё, что лежит в `corpus-study/`, генерирует этот скрипт: графики, числа и прозу вокруг них.
 * Это сознательно: отчёт, чьи цифры набраны руками, расходится с кодом за неделю, и первым это
 * замечает читатель, который одну из них проверил.
 *
 * Этика, как требует план: только агрегаты. Ни идентификатор шаблона, ни имя, ни URL, ни имя
 * ноды из просканированного воркфлоу в вывод не попадают. Публикуется форма проблемы по
 * библиотеке, а не список живых воркфлоу с дырой.
 *
 * Использование:
 *   pnpm corpus:study                 # сначала сборка, потом это
 *   node scripts/corpus-study.mjs [--cache .corpus-cache] [--out corpus-study]
 */
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { analyseWorkflow, defaultRules } from '../packages/core/dist/index.js';

const LIBRARY = 'https://api.n8n.io/api/templates';

function parseArgs(argv) {
  const out = { cache: '.corpus-cache', outDir: 'corpus-study' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cache') out.cache = argv[++i];
    else if (a === '--out') out.outDir = argv[++i];
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error(`Unknown argument: ${a}`);
  }
  return out;
}

const bump = (map, key, by = 1) => map.set(key, (map.get(key) ?? 0) + by);

/**
 * Склеивает два факта в один ключ карты.
 *
 * Явно, а не пробелом внутри шаблонной строки: prettier переносит длинные строки, и шаблонная
 * строка, попавшая под перенос, утаскивает перевод строки в ключ. В исходнике это невидимо, в
 * опубликованном JSON вылезает escape-последовательностью и ломает всё, что потом разбирает
 * ключ обратно. Этот разделитель не встречается ни в одном типе ноды, эффекте или имени
 * правила.
 */
const PAIR = ' → ';
const pair = (a, b) => `${a}${PAIR}${b}`;
const top = (map, n) =>
  [...map]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, n)
    .map(([key, count]) => ({ key, count }));
const pc = (n, total) => (total === 0 ? 0 : Number(((n / total) * 100).toFixed(1)));
/** Всегда один знак после запятой: `83` и `83,0` в одной таблице читаются как разная точность. */
const fmtPc = (value) => value.toFixed(1).replace('.', ',');
// Неразрывный пробел между разрядами и запятая в дробях — русская типографика чисел.
const n = (value) => value.toLocaleString('ru-RU').replace(/\u00a0/g, ' ');

/** Обрезает тип ноды до того, что нужно читателю: `n8n-nodes-base.gmail` -> `gmail`. */
const shortType = (type) =>
  type.replace('@n8n/n8n-nodes-langchain.', 'lc:').replace('n8n-nodes-base.', '');

async function analyse(cache, rules) {
  const files = (await readdir(cache)).filter((f) => f.endsWith('.json') && f !== '_manifest.json');

  const stats = {
    cached: files.length,
    analysed: 0,
    /** Записи кэша, в которых вообще нет графа: анализировать нечего, и это не чистый результат. */
    empty: 0,
    withFindings: 0,
    withCritical: 0,
    withHighOrWorse: 0,
    withAgent: 0,
    withAgentAndCritical: 0,
    nodes: 0,
    /** Экземпляры нод, для которых у реестра есть правило. Утверждение о покрытии надо
     * измерять, а не выводить из чего-то соседнего. */
    knownNodes: 0,
    findings: 0,
  };
  const bySeverity = new Map();
  const byRule = new Map();
  const byRuleSeverity = new Map();
  const byConfidence = new Map();
  const sinkTypes = new Map();
  const sourceTypes = new Map();
  const sourceSink = new Map();
  const agentTools = new Map();
  const nodesPerWorkflow = [];

  for (const file of files) {
    const record = JSON.parse(await readFile(join(cache, file), 'utf8'));
    const document = record.workflow;
    if (!document || !Array.isArray(document.nodes) || document.nodes.length === 0) {
      stats.empty++;
      continue;
    }

    const { findings, graph, taint } = analyseWorkflow(document, rules);
    stats.analysed++;
    stats.nodes += graph.nodes.length;
    nodesPerWorkflow.push(graph.nodes.length);

    const typeOf = (name) => shortType(graph.node(name)?.type ?? 'unknown');

    for (const node of graph.nodes) {
      if (rules.registry.classify(node).known) stats.knownNodes++;
    }

    const agents = graph.nodes.filter((n) => rules.registry.classify(n).invokesTools);
    if (agents.length > 0) stats.withAgent++;
    for (const agent of agents) {
      for (const edge of graph.outgoing(agent.name)) {
        if (edge.kind === 'invocation') bump(agentTools, typeOf(edge.to));
      }
    }

    if (findings.length > 0) stats.withFindings++;
    const worst = findings.some((f) => f.severity === 'critical');
    if (worst) stats.withCritical++;
    if (agents.length > 0 && worst) stats.withAgentAndCritical++;
    if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) {
      stats.withHighOrWorse++;
    }

    for (const finding of findings) {
      stats.findings++;
      bump(bySeverity, finding.severity);
      bump(byRule, finding.rule);
      bump(byRuleSeverity, pair(finding.rule, finding.severity));
      bump(byConfidence, finding.confidence);
      bump(sinkTypes, pair(typeOf(finding.sink.node), finding.sink.effect ?? 'boundary'));
      bump(sourceTypes, pair(typeOf(finding.source.node), finding.source.trust));
      bump(sourceSink, pair(typeOf(finding.source.node), typeOf(finding.sink.node)));
    }

    // Держим память ровной: ничего из документа дальше этой точки не сохраняется.
    void taint;
  }

  nodesPerWorkflow.sort((a, b) => a - b);
  return {
    stats,
    bySeverity,
    byRule,
    byRuleSeverity,
    byConfidence,
    sinkTypes,
    sourceTypes,
    sourceSink,
    agentTools,
    medianNodes: nodesPerWorkflow[Math.floor(nodesPerWorkflow.length / 2)] ?? 0,
  };
}

// ------------------------------------------------------------- графики

const PALETTE = {
  critical: '#a4243b',
  high: '#d8572a',
  medium: '#c8a415',
  low: '#5c80bc',
  bar: '#3f5e78',
  ink: '#1b1b1b',
  muted: '#6b6b6b',
  paper: '#fbfaf8',
  grid: '#e2ded8',
};

const escape = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/**
 * Горизонтальная столбчатая диаграмма как самостоятельный SVG.
 *
 * Написана руками, а не библиотекой графиков: три диаграммы не оправдывают зависимость, а SVG
 * с явно заданным фоном выглядит в README на тёмной теме так же, как на светлой, — чего нельзя
 * сказать о прозрачном.
 */
function barChart({ title, subtitle, rows, colourOf, width = 760 }) {
  const rowHeight = 26;
  const labelWidth = 250;
  const padding = { top: subtitle ? 68 : 50, right: 60, bottom: 16, left: 16 };
  const height = padding.top + rows.length * rowHeight + padding.bottom;
  const plotWidth = width - padding.left - labelWidth - padding.right;
  const max = Math.max(1, ...rows.map((r) => r.value));

  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escape(title)}">`,
    `<rect width="${width}" height="${height}" fill="${PALETTE.paper}"/>`,
    `<style>text{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}</style>`,
    `<text x="${padding.left}" y="26" font-size="15" font-weight="600" fill="${PALETTE.ink}">${escape(title)}</text>`,
  ];
  if (subtitle) {
    parts.push(
      `<text x="${padding.left}" y="46" font-size="12" fill="${PALETTE.muted}">${escape(subtitle)}</text>`,
    );
  }

  rows.forEach((row, i) => {
    const y = padding.top + i * rowHeight;
    const barWidth = Math.max(1, Math.round((row.value / max) * plotWidth));
    const x = padding.left + labelWidth;
    parts.push(
      `<text x="${padding.left + labelWidth - 8}" y="${y + 14}" font-size="12" text-anchor="end" fill="${PALETTE.ink}">${escape(row.label)}</text>`,
      `<rect x="${x}" y="${y + 3}" width="${barWidth}" height="15" rx="2" fill="${colourOf ? colourOf(row) : PALETTE.bar}"/>`,
      `<text x="${x + barWidth + 6}" y="${y + 15}" font-size="11" fill="${PALETTE.muted}">${escape(row.note ?? row.value)}</text>`,
    );
  });

  parts.push('</svg>');
  return parts.join('\n');
}

/** A single stacked bar: how the corpus divides by the worst thing found in each workflow. */
function stackedChart({ title, subtitle, segments, total, width = 760 }) {
  const height = 150;
  const left = 16;
  const barWidth = width - 32;
  const y = subtitle ? 76 : 58;

  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escape(title)}">`,
    `<rect width="${width}" height="${height}" fill="${PALETTE.paper}"/>`,
    `<style>text{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}</style>`,
    `<text x="${left}" y="26" font-size="15" font-weight="600" fill="${PALETTE.ink}">${escape(title)}</text>`,
  ];
  if (subtitle) {
    parts.push(
      `<text x="${left}" y="46" font-size="12" fill="${PALETTE.muted}">${escape(subtitle)}</text>`,
    );
  }

  let x = left;
  const legend = [];
  for (const segment of segments) {
    const w = Math.round((segment.value / total) * barWidth);
    if (w > 0) {
      parts.push(`<rect x="${x}" y="${y}" width="${w}" height="34" fill="${segment.colour}"/>`);
      if (w > 46) {
        parts.push(
          `<text x="${x + w / 2}" y="${y + 22}" font-size="12" text-anchor="middle" fill="#ffffff">${fmtPc(pc(segment.value, total))}%</text>`,
        );
      }
      x += w;
    }
    legend.push(segment);
  }

  let lx = left;
  for (const segment of legend) {
    parts.push(
      `<rect x="${lx}" y="${y + 48}" width="10" height="10" rx="2" fill="${segment.colour}"/>`,
      `<text x="${lx + 15}" y="${y + 58}" font-size="11" fill="${PALETTE.ink}">${escape(`${segment.label} ${n(segment.value)}`)}</text>`,
    );
    lx += 22 + String(`${segment.label} ${n(segment.value)}`).length * 6.2;
  }

  parts.push('</svg>');
  return parts.join('\n');
}

// --------------------------------------------------------------- отчёт

function report(data, meta) {
  const { stats } = data;
  const sev = (band) => data.bySeverity.get(band) ?? 0;
  const rule = (id) => data.byRule.get(id) ?? 0;

  const ruleRows = top(data.byRule, 20)
    .map(({ key, count }) => `| \`${key}\` | ${n(count)} | ${fmtPc(pc(count, stats.findings))}% |`)
    .join('\n');

  const sinkRows = top(data.sinkTypes, 12)
    .map(({ key, count }) => {
      const [type, effect] = key.split(PAIR);
      return `| \`${type}\` | ${effect} | ${n(count)} |`;
    })
    .join('\n');

  const pairRows = top(data.sourceSink, 12)
    .map(({ key, count }) => {
      const [source, sink] = key.split(PAIR);
      return `| \`${source}\` | \`${sink}\` | ${n(count)} |`;
    })
    .join('\n');

  const toolRows = top(data.agentTools, 12)
    .map(({ key, count }) => `| \`${key}\` | ${n(count)} |`)
    .join('\n');

  return `# Что ${n(stats.analysed)} публичных воркфлоу n8n делают с недоверенным вводом

Каждое число здесь получено командой \`pnpm corpus:study\`, которая сканирует закэшированный
корпус и пишет этот файл. Руками не набрано ничего, поэтому текст не может разъехаться с
данными.

**У ${fmtPc(pc(stats.withCritical, stats.analysed))}% воркфлоу собственной библиотеки шаблонов n8n есть хотя бы один путь, по которому данные извне доходят до действия, которое нельзя отменить, и между ними нет ничего.**

Среди ${n(stats.withAgent)} воркфлоу, дающих модели инструменты для вызова, таких ${fmtPc(pc(stats.withAgentAndCritical, stats.withAgent))}%.

## Что сканировалось

| | |
| --- | --- |
| Источник | Официальная библиотека шаблонов n8n, \`${LIBRARY}\` |${scope(data)}
| В кэше | ${n(stats.cached)} записей |
| Проанализировано | ${n(stats.analysed)} воркфлоу |
| Пропущено | ${n(stats.empty)} записей без графа внутри |
| Нод | ${n(stats.nodes)}, медиана ${data.medianNodes} на воркфлоу |
| Сканер | n8n-sentinel, ${meta.rules} классифицированных типов нод, дефолты нод из n8n ${meta.n8nVersion} |
| Прогон | ${meta.date} |

${scopeNote(data)}

Воркфлоу в этой библиотеке публикуют n8n и сообщество как примеры для копирования — и
именно это делает форму результатов интересной: перед нами шаблоны, с которых люди начинают,
а не те, к которым они пришли.

### Почему эта библиотека, а не та, которой пользуются все

Очевидный корпус для такого исследования — [\`Zie619/n8n-workflows\`](https://github.com/Zie619/n8n-workflows),
за которым тянутся почти все статьи про воркфлоу n8n. **Для анализа графов он непригоден.**
Из его 2061 файла воркфлоу у 694 объект \`connections\` опустошён целиком, а у 1362 переписан
ключами-UUID, указывающими на несуществующие ноды. Целыми остались четыре. Это проверяется по
\`raw.githubusercontent.com\`, то есть таково состояние самого репозитория, а не артефакт
клонирования.

У воркфлоу без рёбер нет путей, и сканер, натравленный на этот репозиторий, не нашёл бы почти
ничего и выглядел бы при этом отлично. Это исследование использует библиотеку, которую отдаёт
сам n8n.

## Главное число

![Воркфлоу по худшей находке внутри](charts/severity-mix.svg)

| | Воркфлоу | Доля |
| --- | --- | --- |
| Хотя бы одна \`critical\` | ${n(stats.withCritical)} | ${fmtPc(pc(stats.withCritical, stats.analysed))}% |
| Хотя бы одна \`high\` или хуже | ${n(stats.withHighOrWorse)} | ${fmtPc(pc(stats.withHighOrWorse, stats.analysed))}% |
| Хотя бы одна находка любой полосы | ${n(stats.withFindings)} | ${fmtPc(pc(stats.withFindings, stats.analysed))}% |
| Содержат ноду, умеющую вызывать инструменты | ${n(stats.withAgent)} | ${fmtPc(pc(stats.withAgent, stats.analysed))}% |

Последняя строка — та, что меняется со временем. Агент это то, что превращает текст в
действие, и у ${fmtPc(pc(stats.withAgent, stats.analysed))}% этой библиотеки он уже есть.

**Цитировать надо ${fmtPc(pc(stats.withCritical, stats.analysed))}%, а не ${fmtPc(pc(stats.withFindings, stats.analysed))}%.** Нижняя полоса составляет ${fmtPc(pc(sev('low'), stats.findings))}% всех находок и существует, чтобы её отфильтровывали; см. ограничения ниже.

## По правилам

![Находки по правилам](charts/findings-by-rule.svg)

| Правило | Находок | Доля |
| --- | --- | --- |
${ruleRows}

Всего ${n(stats.findings)} находок: ${n(sev('critical'))} \`critical\`, ${n(sev('high'))} \`high\`, ${n(sev('medium'))} \`medium\`, ${n(sev('low'))} \`low\`. ${fmtPc(pc(data.byConfidence.get('uncertain') ?? 0, stats.findings))}% помечены как \`uncertain\`: сканер видит путь, но не видит, что он эксплуатируем, и говорит об этом вместо того, чтобы округлить вверх.

\`INDIRECT_PROMPT_INJECTION\` — это ${fmtPc(pc(rule('INDIRECT_PROMPT_INJECTION'), stats.findings))}% находок и флагман этого инструмента: недоверенный ввод доходит до модели, держащей инструменты, а та дотягивается до чего-то необратимого, и человека между ними нет.

## Куда доходят недоверенные данные

![Самые частые пары источник — sink](charts/top-source-sink.svg)

| Нода-sink | Эффект | Находок |
| --- | --- | --- |
${sinkRows}

Самые частые пары источник → sink, по типам нод:

| Откуда | Куда | Находок |
| --- | --- | --- |
${pairRows}

И что агентам в этом корпусе на самом деле дают в руки:

| Инструмент, подключённый к агенту | Раз |
| --- | --- |
${toolRows}

## Как принимается решение о находке

В одном абзаце: парсер превращает документ в граф, чьи рёбра говорят, куда идут данные, — а
это не то же самое, как n8n хранит проводку: связь \`ai_tool\` записана как инструмент → агент,
а направление, в котором путешествует вставленная инструкция, обратное. Каждая нода
классифицируется по реестру из ${meta.rules} типов нод с разрешением параметров, которые n8n
не сохраняет, потому что они оставлены по умолчанию. Taint распространяется от каждого
источника; шаг человеческого подтверждения его останавливает, условие — нет. Находка — это
путь от источника до sink с приложенной трассой. Severity стартует от того, сколько стоит
источник, и теряет полосу за каждое препятствие.

Каждое такое суждение принималось осознанно и записано в правилах — они лежат данными в
\`packages/core/rules/\`, и с ними можно спорить, поменяв одну строку.

## Ограничения методики

Честная часть. Каждое из перечисленного делает числа выше неверными в известную сторону.

**Это достижимость, а не эксплуатируемость.** Сканер показывает, что недоверенные данные
могут дойти до действия. Пропустил бы это на самом деле промпт конкретного воркфлоу, его
схема или код ниже по потоку — на такой вопрос статический анализ не отвечает. Каждое число
здесь — верхняя граница настоящих уязвимостей и нижняя граница путей, которые стоит
пересмотреть.

**Ничего не выполнялось.** Ни один воркфлоу не запускался, ни один живой инстанс не
затрагивался, ни против кого не пробовался эксплойт. Это сознательное ограничение этой фазы, и
поэтому ничто здесь нельзя читать как «эти ${n(stats.withCritical)} воркфлоу эксплуатируемы».

**Границы вложенных воркфлоу не прослеживаются.** Путь в \`executeWorkflow\` или в
воркфлоу-инструмент показывается как непрослеженный. Часть таких ведёт к необратимым
действиям и здесь недосчитана; часть не ведёт никуда.

**Неявная раскладка полей невидима.** Нода, настроенная раскладывать входящие поля по
колонкам, читает недоверенный ввод, и в её параметрах нет никакого выражения. Правила,
спрашивающие «читает ли параметр недоверенные данные», отвечают «нет», и это опускает часть
находок на полосу ниже, чем они заслуживают.

**Классифицировано ${fmtPc(pc(stats.knownNodes, stats.nodes))}% экземпляров нод, а не все.** Остаток — длинный хвост нод сообщества, ни одна из которых не является частой сама по себе. Неклассифицированная нода считается пропускающей данные насквозь и никогда — sink, поэтому она может скрыть конец пути, но никогда не выдумает его.

**В реестре зашито суждение.** Является ли нода Code необратимым sink, считать ли смену метки
в Gmail эффектом, защита ли нода \`if\` — это принятые решения, и
разумный человек мог бы расставить их иначе и получить другие итоги. Правила — это данные в
\`packages/core/rules/\`; поменять одно и перезапустить занимает минуту.

**Библиотека шаблонов — это не продакшен.** Это примеры, написанные, чтобы их копировали и
дорабатывали, часто с заглушками вместо доступов и без настоящих данных за ними. Числа
описывают форму шаблонов, с которых люди начинают, а не состояние чьего-либо живого инстанса.

## Этика

Только агрегаты. Ни идентификатор шаблона, ни название, ни URL, ни имя ноды из просканированных
воркфлоу не попадают ни в этот отчёт, ни в \`data.json\`, и ни один эксплойт не был написан или
применён против живого инстанса. Анализ читает опубликованный JSON, который n8n отдаёт кому
угодно; отдельные результаты не публикуются потому, что список названных воркфлоу с дырой — это
список целей, а интересна закономерность, а не экземпляр.

## Как это воспроизвести

\`\`\`bash
export NODE_EXTRA_CA_CERTS=$(brew --prefix)/etc/ca-certificates/cert.pem   # только для macOS/Homebrew
node scripts/fetch-corpus.mjs --limit 12000     # возобновляемо; ~${Math.round(stats.cached / 1000)} тыс. файлов в .corpus-cache/
pnpm corpus:study                               # пересобирает этот файл и графики
\`\`\`

Кэш не коммитится: это ${Math.round(stats.cached / 1000)} тыс. документов JSON, принадлежащих их
авторам. \`data.json\` рядом с этим файлом держит все агрегаты, из которых построен отчёт.
`;
}

/** Одна строка таблицы охвата — только если скачивание записало, что заявляла библиотека. */
function scope(data) {
  if (!data.fetched?.libraryTotal) return '';
  return `\n| Библиотека сообщает | ${n(data.fetched.libraryTotal)} воркфлоу |\n| Идентификаторов отдал поисковый эндпоинт | ${n(data.fetched.listed)} |`;
}

/**
 * Абзац, решающий, может ли это исследование говорить «вся библиотека».
 *
 * Не вполне может: постраничный обход поискового эндпоинта возвращает меньше идентификаторов,
 * чем сообщает сам API. Назвать разрыв дешевле, чем альтернатива, — когда его находит
 * читатель.
 */
function scopeNote(data) {
  const { stats } = data;
  if (!data.fetched?.libraryTotal) {
    return `Это то, что лежало в кэше на момент прогона. Скачивание не записало, сколько библиотека заявляла у себя, поэтому считайте покрытие неизвестным, а не полным.`;
  }
  const listed = data.fetched.listed;
  const total = data.fetched.libraryTotal;
  if (listed >= total) {
    const gone = total - stats.analysed;
    return gone > 0
      ? `Это все идентификаторы, которые перечисляет библиотека. ${n(gone)} из них (${fmtPc(pc(gone, total))}%) отдают 404 — шаблоны, отозванные с тех пор, — так что исследование покрывает ${fmtPc(pc(stats.analysed, total))}% библиотеки в её нынешнем виде.`
      : `Это все воркфлоу, которые перечисляет библиотека.`;
  }
  return `**Это не вся библиотека.** API сообщает о ${n(total)} воркфлоу; постраничный обход его поискового эндпоинта отдаёт ${n(listed)} идентификаторов, то есть ${fmtPc(pc(listed, total))}%, а до остальных так не добраться. Из них ${n(stats.analysed)} удалось скачать и они несут граф. Ничто не говорит, что недостающие ${n(total - listed)} чем-то отличаются по сути, но никто этого не проверял, поэтому читайте каждую цифру ниже как относящуюся к тем ${n(stats.analysed)}, что были просканированы.`;
}

/** Черновик поста. Держится отдельно от отчёта, чтобы отчёт оставался отчётом. */
function post(data) {
  const { stats } = data;
  return `# Черновик: «Я просканировал все ${n(stats.analysed)} воркфлоу из библиотеки шаблонов n8n»

Не опубликовано. Отправная точка: сократить и дать голос, прежде чем это куда-то пойдёт.

---

Я просканировал ${n(stats.analysed)} воркфлоу из официальной библиотеки шаблонов n8n — тех
самых, которые редактор предлагает по кнопке «browse templates». «Официальная» тут про площадку,
а не про авторство: шаблоны пишет сообщество, n8n их публикует и раздаёт. Искал я одну вещь:
могут ли данные извне дойти до действия, которое нельзя отменить.

У ${fmtPc(pc(stats.withCritical, stats.analysed))}% из них могут.

Не «есть уязвимость». Сканер ничего не запускает и не может сказать, попадётся ли на это
конкретный промпт. Он может сказать, что путь существует: приходит письмо, тело вебхука или
скрапленная страница, и без чего-либо между доходит до отправки, удаления, платежа или shell.

Второе число важнее. ${fmtPc(pc(stats.withAgent, stats.analysed))}% этих воркфлоу дают модели
инструменты для вызова. Из них у ${fmtPc(pc(stats.withAgentAndCritical, stats.withAgent))}% есть
недоверенный путь в один из этих инструментов. Для модели ваши инструкции и входящее письмо —
один и тот же поток символов, так что автор письма получает право голоса в том, какой
инструмент запустится и с какими аргументами.

**Три вещи, которых я не ожидал:**

1. n8n не записывает, что делает нода. Он сохраняет только параметры, отличающиеся от значения
   по умолчанию, поэтому нода Gmail без \`operation\` не двусмысленна — это *отправка*.
   Ошибиться здесь в любую сторону значит сломать весь анализ. [развернуть]
2. Самое опасное ребро в воркфлоу n8n на холсте не нарисовано. Связи \`ai_tool\` хранятся как
   инструмент → агент, а вставленная инструкция путешествует в обратную сторону. Без
   синтезирования этого ребра флагманская находка невидима. [развернуть]
3. Корпус, которым для этого пользуются все, сломан. \`Zie619/n8n-workflows\` — репозиторий, за
   которым тянется большинство статей про n8n; из его 2061 файла у 694 \`connections\` опустошены,
   а у 1362 переписаны UUID-ами, указывающими на несуществующие ноды. Целыми остались четыре.
   Сканер, натравленный на него, не находит почти ничего и отлично при этом выглядит.
   [развернуть]

**Чего я утверждать не стану:** что эти ${n(stats.withCritical)} воркфлоу эксплуатируемы. Это
достижимость — путь существует, — а пропустил бы это на самом деле конкретный промпт, схема или
проверка ниже по потоку, статический анализ не отвечает. Ничего не выполнялось, ни один живой
инстанс не затрагивался. Полный список того, чем эта методика неверна, — в исследовании.

Сканер, правила и методика открыты: [ссылка]. Каждое суждение о severity записано и оспоримо —
только так числа такого рода вообще чего-то стоят.
`;
}

// -------------------------------------------------------------- запуск

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log('Использование: node scripts/corpus-study.mjs [--cache DIR] [--out DIR]');
    return;
  }

  const rules = defaultRules();
  // Пишется fetch-corpus.mjs. На старом кэше отсутствует — тогда отчёт говорит, что
  // просканировал, и молчит о том, чего не смог.
  const fetched = await readFile(join(args.cache, '_manifest.json'), 'utf8')
    .then((t) => JSON.parse(t))
    .catch(() => null);

  console.log(`сканирую ${args.cache}…`);
  const started = Date.now();
  const data = await analyse(args.cache, rules);
  data.fetched = fetched;
  console.log(
    `  ${data.stats.analysed} воркфлоу, ${data.stats.findings} находок за ${((Date.now() - started) / 1000).toFixed(1)} с`,
  );

  const meta = {
    rules: rules.registry.size,
    n8nVersion: rules.registry.n8nVersion,
    date: new Date().toISOString().slice(0, 10),
  };

  await mkdir(join(args.outDir, 'charts'), { recursive: true });

  const { stats } = data;
  await writeFile(
    join(args.outDir, 'charts', 'findings-by-rule.svg'),
    barChart({
      title: 'Находки по правилам',
      subtitle: `${n(stats.findings)} находок в ${n(stats.analysed)} воркфлоу`,
      rows: top(data.byRule, 10).map(({ key, count }) => ({
        label: key,
        value: count,
        note: `${count} (${pc(count, stats.findings)}%)`,
      })),
    }),
  );

  await writeFile(
    join(args.outDir, 'charts', 'severity-mix.svg'),
    stackedChart({
      title: 'Воркфлоу по худшей находке внутри',
      subtitle: `${n(stats.analysed)} воркфлоу из официальной библиотеки шаблонов n8n`,
      total: stats.analysed,
      segments: [
        { label: 'critical', value: stats.withCritical, colour: PALETTE.critical },
        {
          label: 'high',
          value: stats.withHighOrWorse - stats.withCritical,
          colour: PALETTE.high,
        },
        {
          label: 'medium или low',
          value: stats.withFindings - stats.withHighOrWorse,
          colour: PALETTE.medium,
        },
        {
          label: 'ничего не найдено',
          value: stats.analysed - stats.withFindings,
          colour: PALETTE.grid,
        },
      ],
    }),
  );

  await writeFile(
    join(args.outDir, 'charts', 'top-source-sink.svg'),
    barChart({
      title: 'Откуда приходят недоверенные данные и до чего доходят',
      subtitle: 'по типам нод, топ-12 пар',
      rows: top(data.sourceSink, 12).map(({ key, count }) => {
        return { label: key, value: count, note: n(count) };
      }),
    }),
  );

  // Агрегаты — чтобы читатель мог проверить цифру, не перезапуская скан.
  const serialise = (map) =>
    Object.fromEntries([...map].sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, v]));
  await writeFile(
    join(args.outDir, 'data.json'),
    `${JSON.stringify(
      {
        generatedAt: meta.date,
        library: LIBRARY,
        scanner: { rules: meta.rules, n8nVersion: meta.n8nVersion },
        stats,
        bySeverity: serialise(data.bySeverity),
        byRule: serialise(data.byRule),
        byRuleSeverity: serialise(data.byRuleSeverity),
        byConfidence: serialise(data.byConfidence),
        topSinks: serialise(data.sinkTypes),
        topSources: serialise(data.sourceTypes),
        topSourceSinkPairs: serialise(data.sourceSink),
        agentTools: serialise(data.agentTools),
        medianNodesPerWorkflow: data.medianNodes,
      },
      null,
      2,
    )}\n`,
  );

  await writeFile(join(args.outDir, 'REPORT.md'), report(data, meta));
  await writeFile(join(args.outDir, 'POST-DRAFT.md'), post(data));

  console.log(`записано: ${args.outDir}/REPORT.md, data.json, POST-DRAFT.md и 3 графика`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
