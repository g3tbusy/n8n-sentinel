#!/usr/bin/env node
/**
 * Извлекает у каждого типа ноды дефолтные `resource`/`operation` (и им подобные) из самого n8n.
 *
 * Зачем это нужно: n8n сохраняет только параметры, отличающиеся от значения по умолчанию,
 * поэтому отсутствующий `operation` означает не «неизвестно», а дефолт этой ноды. В выборке
 * корпуса `operation` отсутствует у 155 из 265 нод Gmail; каждая из них — *отправка*, потому
 * что `send` это дефолт для ресурса message. Гадание здесь либо залило бы отчёт ложными
 * срабатываниями, либо потеряло бы большую часть настоящих sink-ов.
 *
 * Поэтому дефолты берутся из работающего продукта, а не по памяти, и версия n8n, из которой
 * они взяты, записывается в вывод.
 *
 * Использование:
 *   node scripts/extract-node-defaults.mjs --catalogue <nodes.json> --n8n-version 2.32.7
 *
 * Каталог — это собственный кэш типов нод у n8n. Из работающего контейнера:
 *   docker cp <контейнер>:/home/node/.cache/n8n/public/types/nodes.json ./nodes.json
 *   docker exec <контейнер> n8n --version
 */
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

/** Параметры, чьё значение решает, что нода *делает*, в отличие от того, как она это делает. */
const DISCRIMINATORS = ['resource', 'operation', 'mode', 'method', 'resume'];

function parseArgs(argv) {
  const out = {
    catalogue: 'nodes.json',
    out: 'packages/core/rules/node-defaults.json',
    n8nVersion: 'unknown',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--catalogue') out.catalogue = argv[++i];
    else if (a === '--out') out.out = argv[++i];
    else if (a === '--n8n-version') out.n8nVersion = argv[++i];
    else throw new Error(`Unknown argument: ${a}`);
  }
  return out;
}

/**
 * Каталог держит по записи на версионную *группу* ноды, и все они делят один
 * `defaultVersion`. Взять первое совпадение значит взять самую старую реализацию, чьи дефолты
 * могут отличаться от той, которую n8n на самом деле создаёт: у Google Sheets v2 дефолтная
 * операция не та, что у v4.7. Выбираем группу, содержащую `defaultVersion`.
 */
function currentEntry(entries) {
  const withDefault = entries.find((e) => {
    const v = e.version;
    return Array.isArray(v) ? v.includes(e.defaultVersion) : v === e.defaultVersion;
  });
  if (withDefault) return withDefault;
  // У нод без объявленного defaultVersion реализация одна; берём самую новую.
  return entries.reduce((best, e) => {
    const rank = (x) => (Array.isArray(x.version) ? Math.max(...x.version) : (x.version ?? 0));
    return rank(e) > rank(best) ? e : best;
  }, entries[0]);
}

/**
 * Все значения, которые различителю позволено принимать, — чтобы написанные руками правила
 * можно было сверить с реальностью. Правило, ловящее `operation: sendEmail`, когда нода
 * предлагает только `send`, молча мертво; тест, сверяющийся с этим списком, его ловит.
 */
function extractOptions(entry) {
  const result = {};
  for (const key of DISCRIMINATORS) {
    const values = new Set();
    for (const p of (entry.properties ?? []).filter((x) => x?.name === key)) {
      for (const o of p.options ?? []) {
        if (typeof o?.value === 'string') values.add(o.value);
      }
    }
    if (values.size > 0) result[key] = [...values].sort();
  }
  return result;
}

function extractDefaults(entry) {
  const result = {};
  for (const key of DISCRIMINATORS) {
    const props = (entry.properties ?? []).filter((p) => p?.name === key);
    if (props.length === 0) continue;

    // Нода может объявлять по дефолту на ресурс, разграниченному через displayOptions.
    const byResource = {};
    let unconditional;
    for (const p of props) {
      if (p.default === undefined) continue;
      const shownFor = p.displayOptions?.show?.resource;
      if (Array.isArray(shownFor) && shownFor.length > 0) {
        for (const r of shownFor) byResource[String(r)] = p.default;
      } else {
        unconditional = p.default;
      }
    }
    if (Object.keys(byResource).length > 0) {
      result[key] =
        unconditional === undefined ? byResource : { ...byResource, '*': unconditional };
    } else if (unconditional !== undefined) {
      result[key] = unconditional;
    }
  }
  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const raw = JSON.parse(await readFile(args.catalogue, 'utf8'));
  const list = Array.isArray(raw) ? raw : Object.values(raw);

  const byName = new Map();
  for (const entry of list) {
    if (typeof entry?.name !== 'string') continue;
    if (!byName.has(entry.name)) byName.set(entry.name, []);
    byName.get(entry.name).push(entry);
  }

  const nodes = {};
  let withDefaults = 0;
  let usableAsTool = 0;
  for (const name of [...byName.keys()].sort()) {
    const entry = currentEntry(byName.get(name));
    const defaults = extractDefaults(entry);
    const options = extractOptions(entry);
    const record = {};
    if (entry.defaultVersion !== undefined) record.defaultVersion = entry.defaultVersion;
    if (entry.usableAsTool) {
      record.usableAsTool = true;
      usableAsTool++;
    }
    if (Object.keys(defaults).length > 0) {
      record.defaults = defaults;
      withDefaults++;
    }
    if (Object.keys(options).length > 0) record.options = options;
    nodes[name] = record;
  }

  const output = {
    $comment:
      'Generated by scripts/extract-node-defaults.mjs from n8n’s own node catalogue. Do not edit by hand.',
    n8nVersion: args.n8nVersion,
    nodeTypes: Object.keys(nodes).length,
    nodeTypesWithDefaults: withDefaults,
    nodeTypesUsableAsTool: usableAsTool,
    nodes,
  };

  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, JSON.stringify(output, null, 2) + '\n');
  console.log(
    `${output.nodeTypes} node types (${withDefaults} with discriminator defaults, ${usableAsTool} usable as tools) -> ${args.out}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
