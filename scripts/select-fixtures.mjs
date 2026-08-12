#!/usr/bin/env node
/**
 * Выбирает из скачанного корпуса небольшой набор фикстур с максимальным покрытием.
 *
 * Цель не «30 случайных воркфлоу», а «наименьший набор, который всё ещё задействует каждый
 * тип связи и каждую структурную странность, которую парсер обязан пережить». Выбор — жадное
 * покрытие множеств по фиксированному списку признаков, с детерминированным разрешением
 * ничьих, чтобы один и тот же кэш всегда давал одни и те же фикстуры.
 *
 * Использование:
 *   node scripts/select-fixtures.mjs [--cache .corpus-cache] [--out fixtures/real] [--max 30]
 */
import { mkdir, readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';

function parseArgs(argv) {
  const out = { cache: '.corpus-cache', outDir: 'fixtures/real', max: 30 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cache') out.cache = argv[++i];
    else if (a === '--out') out.outDir = argv[++i];
    else if (a === '--max') out.max = Number(argv[++i]);
    else throw new Error(`Unknown argument: ${a}`);
  }
  return out;
}

const arr = (v) => (Array.isArray(v) ? v : []);

/**
 * Описывает один воркфлоу набором тегов-признаков.
 * Именно по тегам оптимизирует жадное покрытие, и именно их документирует манифест.
 */
export function describe(wf) {
  const tags = new Set();
  if (!wf || !Array.isArray(wf.nodes)) return tags;

  const names = new Set(wf.nodes.map((n) => n?.name).filter((n) => typeof n === 'string'));
  const conns = wf.connections ?? {};

  // --- связи -------------------------------------------------------------
  const mainAdj = new Map();
  const undirected = new Map(wf.nodes.map((n) => [n?.name, new Set()]));
  for (const [src, byType] of Object.entries(conns)) {
    if (!names.has(src)) tags.add('struct:nonNameConnectionKey');
    for (const [ctype, slots] of Object.entries(byType ?? {})) {
      tags.add(`conn:${ctype}`);
      const filled = arr(slots).filter((s) => arr(s).length > 0);
      if (filled.length > 1) tags.add('struct:multiOutput');
      for (const slot of arr(slots)) {
        for (const c of arr(slot)) {
          const dst = c?.node;
          if (typeof dst !== 'string') continue;
          if (!names.has(dst)) tags.add('struct:danglingTarget');
          if (dst === src) tags.add('struct:selfLoop');
          if (ctype === 'main') {
            if (!mainAdj.has(src)) mainAdj.set(src, []);
            mainAdj.get(src).push(dst);
          }
          if (undirected.has(src) && undirected.has(dst)) {
            undirected.get(src).add(dst);
            undirected.get(dst).add(src);
          }
        }
      }
    }
  }

  // --- циклы по рёбрам main ----------------------------------------------
  const state = new Map();
  let cyclic = false;
  const visit = (n) => {
    if (cyclic) return;
    state.set(n, 1);
    for (const m of mainAdj.get(n) ?? []) {
      const s = state.get(m) ?? 0;
      if (s === 1) {
        cyclic = true;
        return;
      }
      if (s === 0) visit(m);
    }
    state.set(n, 2);
  };
  for (const n of mainAdj.keys()) if ((state.get(n) ?? 0) === 0) visit(n);
  if (cyclic) tags.add('struct:cycle');

  // --- изолированные ноды (стикеры изолированы всегда, поэтому исключены) -
  const real = wf.nodes.filter((n) => n?.type !== 'n8n-nodes-base.stickyNote');
  if (real.length > 2 && real.some((n) => (undirected.get(n?.name)?.size ?? 0) === 0)) {
    tags.add('struct:disconnectedNode');
  }

  // --- флаги уровня воркфлоу ---------------------------------------------
  if (wf.pinData && Object.keys(wf.pinData).length > 0) tags.add('struct:pinData');
  if (wf.nodes.some((n) => n?.disabled === true)) tags.add('struct:disabledNode');

  const raw = JSON.stringify(wf);
  if (/\{\{[^}]*\$json/.test(raw)) tags.add('expr:$json');
  if (/\{\{[^}]*\$\(\s*['"]/.test(raw)) tags.add("expr:$('Node')");
  if (/\{\{[^}]*\$env/.test(raw)) tags.add('expr:$env');
  if (raw.includes('sendAndWait')) tags.add('gate:sendAndWait');

  // --- грубая таксономия нод (настоящий реестр приходит в фазе 2) --------
  const SRC = {
    'n8n-nodes-base.webhook': 'src:webhook',
    'n8n-nodes-base.formTrigger': 'src:formTrigger',
    'n8n-nodes-base.gmailTrigger': 'src:gmailTrigger',
    'n8n-nodes-base.emailReadImap': 'src:emailReadImap',
    'n8n-nodes-base.telegramTrigger': 'src:telegramTrigger',
    'n8n-nodes-base.rssFeedRead': 'src:rssFeedRead',
    'n8n-nodes-base.executeWorkflowTrigger': 'src:executeWorkflowTrigger',
  };
  const SINK = {
    'n8n-nodes-base.emailSend': 'sink:emailSend',
    'n8n-nodes-base.gmail': 'sink:gmail',
    'n8n-nodes-base.postgres': 'sink:postgres',
    'n8n-nodes-base.mySql': 'sink:mySql',
    'n8n-nodes-base.executeCommand': 'sink:executeCommand',
    'n8n-nodes-base.code': 'sink:code',
    'n8n-nodes-base.httpRequest': 'sink:httpRequest',
    'n8n-nodes-base.slack': 'sink:slack',
    'n8n-nodes-base.telegram': 'sink:telegram',
  };
  for (const n of wf.nodes) {
    const t = n?.type;
    if (typeof t !== 'string') continue;
    if (SRC[t]) tags.add(SRC[t]);
    if (SINK[t]) tags.add(SINK[t]);
    if (t.includes('chatTrigger')) tags.add('src:chatTrigger');
    if (t === 'n8n-nodes-base.executeWorkflow') tags.add('boundary:executeWorkflow');
    if (t.includes('toolWorkflow')) tags.add('boundary:toolWorkflow');
    if (t.includes('toolCode')) tags.add('boundary:toolCode');
    if (t.includes('toolHttpRequest')) tags.add('boundary:toolHttpRequest');
    if (t.endsWith('.agent') || t.includes('.agent')) tags.add('llm:agent');
    if (t.includes('chainLlm')) tags.add('llm:chainLlm');
    if (t.includes('openAi')) tags.add('llm:openAi');
    if (t.endsWith('Tool')) tags.add('llm:baseNodeAsTool');
  }
  return tags;
}

const slug = (s) =>
  String(s ?? 'workflow')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'workflow';

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const files = (await readdir(args.cache)).filter((f) => f.endsWith('.json')).sort();
  const items = [];
  for (const f of files) {
    const rec = JSON.parse(await readFile(join(args.cache, f), 'utf8'));
    const wf = rec.workflow;
    if (!wf || !Array.isArray(wf.nodes) || wf.nodes.length === 0) continue;
    const nodeTypes = new Set(wf.nodes.map((n) => n?.type).filter((t) => typeof t === 'string'));
    items.push({ rec, wf, tags: describe(wf), nodeTypes, nodeCount: wf.nodes.length });
  }
  console.log(`analysed ${items.length} cached workflows`);

  const universe = new Set();
  for (const it of items) for (const t of it.tags) universe.add(t);
  console.log(`${universe.size} distinct feature tags in corpus`);

  // Жадное покрытие множеств. Ничьи разрешаются в пользу меньшего числа нод (фикстуру легче
  // читать), затем в пользу меньшего идентификатора, чтобы вывод был стабилен между прогонами.
  const covered = new Set();
  const chosen = [];
  const pool = [...items].sort((a, b) => a.nodeCount - b.nodeCount || a.rec.id - b.rec.id);

  while (chosen.length < args.max && covered.size < universe.size) {
    let best = null;
    let bestGain = 0;
    for (const it of pool) {
      if (chosen.includes(it)) continue;
      let gain = 0;
      for (const t of it.tags) if (!covered.has(t)) gain++;
      if (gain > bestGain) {
        bestGain = gain;
        best = it;
      }
    }
    if (!best) break;
    chosen.push(best);
    for (const t of best.tags) covered.add(t);
  }

  const uncovered = [...universe].filter((t) => !covered.has(t)).sort();
  console.log(`set cover: ${chosen.length} fixtures for ${covered.size}/${universe.size} tags`);

  // Второй проход: добираем остаток бюджета теми воркфлоу, которые приносят больше всего
  // ранее не встречавшихся типов нод. Фазе 2 нужна широта типов, чтобы строить по ним реестр
  // source/sink, а одно только покрытие множеств тяготеет к графам, набитым AI.
  const seenTypes = new Set();
  for (const it of chosen) for (const t of it.nodeTypes) seenTypes.add(t);
  while (chosen.length < args.max) {
    let best = null;
    let bestGain = 0;
    for (const it of pool) {
      if (chosen.includes(it)) continue;
      let gain = 0;
      for (const t of it.nodeTypes) if (!seenTypes.has(t)) gain++;
      if (gain > bestGain) {
        bestGain = gain;
        best = it;
      }
    }
    if (!best) break;
    chosen.push(best);
    for (const t of best.nodeTypes) seenTypes.add(t);
  }
  console.log(
    `after node-type fill: ${chosen.length} fixtures, ${seenTypes.size} distinct node types`,
  );

  await rm(args.outDir, { recursive: true, force: true });
  await mkdir(args.outDir, { recursive: true });

  const manifest = [];
  for (const it of chosen.sort((a, b) => a.rec.id - b.rec.id)) {
    const file = `${String(it.rec.id).padStart(5, '0')}-${slug(it.rec.name)}.json`;
    // Фикстуры хранятся обычными документами воркфлоу n8n — ровно тем, что пользователь
    // выгружает из редактора, — чтобы сканер работал на настоящей форме данных.
    const doc = { name: it.rec.name, ...it.wf };
    await writeFile(join(args.outDir, file), JSON.stringify(doc, null, 2) + '\n');
    manifest.push({
      file,
      templateId: it.rec.id,
      name: it.rec.name,
      url: it.rec.url,
      nodeCount: it.nodeCount,
      features: [...it.tags].sort(),
    });
  }

  const distinctNodeTypes = new Set();
  for (const it of chosen) for (const t of it.nodeTypes) distinctNodeTypes.add(t);

  const coverage = {
    source: 'https://api.n8n.io/api/templates (official n8n template library)',
    generatedBy: 'scripts/select-fixtures.mjs',
    corpusSampleSize: items.length,
    fixtureCount: manifest.length,
    distinctNodeTypes: distinctNodeTypes.size,
    featuresCovered: [...covered].sort(),
    featuresUncovered: uncovered,
    nodeTypes: [...distinctNodeTypes].sort(),
    fixtures: manifest,
  };
  await writeFile(join(args.outDir, 'manifest.json'), JSON.stringify(coverage, null, 2) + '\n');

  console.log(
    `selected ${manifest.length} fixtures covering ${covered.size}/${universe.size} tags`,
  );
  if (uncovered.length) console.log('uncovered:', uncovered.join(', '));
  for (const m of manifest) console.log(`  ${m.file} (${m.nodeCount} nodes)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
