#!/usr/bin/env node
/**
 * Качает воркфлоу n8n из официальной публичной библиотеки шаблонов в локальный кэш.
 *
 * Кэш — сырьё для двух вещей:
 *   - фаза 0: небольшой отобранный набор фикстур (см. select-fixtures.mjs)
 *   - фаза 6: исследование корпуса
 *
 * Использование:
 *   node scripts/fetch-corpus.mjs [--limit 500] [--out .corpus-cache] [--concurrency 4]
 *
 * Вежливость: ограниченная параллельность, повтор с отступом и кэш на диске, чтобы
 * повторные запуски не перезапрашивали уже скачанное.
 */
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const API = 'https://api.n8n.io/api/templates';
const USER_AGENT = 'n8n-sentinel-research/0.1 (+https://github.com/n8n-sentinel)';

function parseArgs(argv) {
  const out = { limit: 500, outDir: '.corpus-cache', concurrency: 4 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--limit') out.limit = Number(argv[++i]);
    else if (a === '--out') out.outDir = argv[++i];
    else if (a === '--concurrency') out.concurrency = Number(argv[++i]);
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (!Number.isFinite(out.limit) || out.limit <= 0)
    throw new Error('--limit must be a positive number');
  if (!Number.isFinite(out.concurrency) || out.concurrency <= 0) {
    throw new Error('--concurrency must be a positive number');
  }
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJson(url, attempt = 0) {
  try {
    const res = await fetch(url, {
      headers: { 'user-agent': USER_AGENT, accept: 'application/json' },
    });
    if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
    if (!res.ok) return { error: `HTTP ${res.status}` };
    return { data: await res.json() };
  } catch (err) {
    if (attempt >= 4) return { error: err.message };
    await sleep(500 * 2 ** attempt);
    return getJson(url, attempt + 1);
  }
}

/**
 * Обходит поисковый эндпоинт, пока не соберёт `limit` идентификаторов.
 *
 * Возвращает вместе с ними то общее число, которое сообщает сама библиотека, потому что они
 * не совпадают: постраничный обход поиска отдаёт меньше идентификаторов, чем заявляет
 * `totalWorkflows`, а исследование, которое говорит «вся библиотека», этого не заметив,
 * ошибается насчёт собственного охвата.
 */
async function listIds(limit) {
  const ids = [];
  const seen = new Set();
  let libraryTotal = null;
  const rows = 250;
  for (let page = 1; ids.length < limit; page++) {
    const { data, error } = await getJson(`${API}/search?rows=${rows}&page=${page}`);
    if (error) {
      console.error(`  search page ${page} failed: ${error}`);
      break;
    }
    if (typeof data?.totalWorkflows === 'number') libraryTotal = data.totalWorkflows;
    const batch = data?.workflows ?? [];
    if (batch.length === 0) break;
    for (const w of batch) {
      if (w?.id != null && !seen.has(w.id)) {
        seen.add(w.id);
        ids.push(w.id);
      }
    }
    process.stdout.write(
      `\r  listing… ${ids.length}/${limit} (page ${page}, library total ${data.totalWorkflows})`,
    );
    await sleep(150);
  }
  process.stdout.write('\n');
  return { ids: ids.slice(0, limit), libraryTotal };
}

/** Гоняет `worker` по `items` фиксированным числом параллельных дорожек. */
async function pooled(items, concurrency, worker) {
  let cursor = 0;
  const lanes = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const i = cursor++;
      await worker(items[i], i);
    }
  });
  await Promise.all(lanes);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(
      'Использование: node scripts/fetch-corpus.mjs [--limit N] [--out DIR] [--concurrency N]',
    );
    return;
  }

  await mkdir(args.outDir, { recursive: true });
  const existing = new Set(
    (await readdir(args.outDir).catch(() => []))
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.slice(0, -5)),
  );
  console.log(`cache: ${args.outDir} (${existing.size} already present)`);

  console.log(`listing up to ${args.limit} template ids…`);
  const { ids, libraryTotal } = await listIds(args.limit);
  const missing = ids.filter((id) => !existing.has(String(id)));
  console.log(`${ids.length} ids listed, ${missing.length} to download`);

  let done = 0;
  let failed = 0;
  await pooled(missing, args.concurrency, async (id) => {
    const { data, error } = await getJson(`${API}/workflows/${id}`);
    done++;
    if (error || !data?.workflow) {
      failed++;
      console.error(`\n  ${id}: ${error ?? 'no workflow field'}`);
      return;
    }
    const t = data.workflow;
    const record = {
      id: t.id,
      name: t.name,
      description: t.description ?? null,
      url: `https://n8n.io/workflows/${t.id}/`,
      createdAt: t.createdAt ?? null,
      totalViews: t.totalViews ?? null,
      // Сам документ воркфлоу n8n: { nodes, connections, … }
      workflow: t.workflow ?? null,
    };
    await writeFile(join(args.outDir, `${id}.json`), JSON.stringify(record, null, 2));
    if (done % 10 === 0 || done === missing.length) {
      process.stdout.write(`\r  downloaded ${done}/${missing.length} (${failed} failed)`);
    }
    await sleep(120);
  });
  process.stdout.write('\n');

  // То, что нужно исследованию, чтобы точно описать свой охват, а не предполагать его.
  await writeFile(
    join(args.outDir, '_manifest.json'),
    JSON.stringify(
      {
        library: API,
        fetchedAt: new Date().toISOString().slice(0, 10),
        libraryTotal,
        listed: ids.length,
        downloadFailed: failed,
      },
      null,
      2,
    ),
  );

  const total = (await readdir(args.outDir)).filter(
    (f) => f.endsWith('.json') && f !== '_manifest.json',
  ).length;
  console.log(`cache now holds ${total} workflows`);

  // Дешёвый признак целостности: у скольких записей кэша действительно есть граф.
  let withGraph = 0;
  for (const f of await readdir(args.outDir)) {
    if (!f.endsWith('.json') || f === '_manifest.json') continue;
    const rec = JSON.parse(await readFile(join(args.outDir, f), 'utf8'));
    if (Array.isArray(rec.workflow?.nodes) && rec.workflow.nodes.length > 0) withGraph++;
  }
  console.log(`${withGraph}/${total} contain a non-empty nodes array`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
