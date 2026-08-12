#!/usr/bin/env node
// Диагностика эндпоинта LLM для полигона фазы 8.
//
//   node scripts/probe-llm-endpoint.mjs
//
// Читает LLM_BASE_URL, LLM_MODEL и LLM_API_KEY из .env.local в корне пакета.
// Ключ никуда не печатается и уходит только на указанный base URL.
//
// Зачем этот скрипт существует: доступ к модели идёт через прокси, а не через
// api.anthropic.com напрямую. Прокси ведёт себя не так, как настоящий API
//, и «работает ли он вообще» надо уметь проверить за минуту,
// а не выяснять посреди прогона корпуса.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const корень = join(dirname(fileURLToPath(import.meta.url)), '..');

function читатьНастройки() {
  let текст;
  try {
    текст = readFileSync(join(корень, '.env.local'), 'utf8');
  } catch {
    console.error('Нет .env.local в корне пакета. Формат:');
    console.error('  LLM_BASE_URL=https://…');
    console.error('  LLM_MODEL=claude-opus-5');
    console.error('  LLM_API_KEY=sk-…');
    process.exit(1);
  }
  const настройки = {};
  for (const строка of текст.split('\n')) {
    const m = строка.match(/^\s*([A-Z_]+)\s*=\s*(.*)$/);
    if (m) настройки[m[1]] = m[2].trim();
  }
  return настройки;
}

// Прокси всегда отвечает потоком, даже когда его об этом не просили, и
// подмешивает к телу хвост `data: [DONE]`. На нативном пути тело — это один
// объект JSON плюс этот хвост; на OpenAI-совместимом — цепочка чанков.
function разобратьОтвет(тело) {
  const без = тело.replace(/\s*data:\s*\[DONE\]\s*$/, '').trim();
  try {
    return JSON.parse(без);
  } catch {
    // Цепочка чанков SSE: собираем последний осмысленный объект.
    const чанки = без
      .split('\n')
      .filter((s) => s.startsWith('data: '))
      .map((s) => {
        try {
          return JSON.parse(s.slice(6));
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    return чанки.length ? { чанки } : null;
  }
}

async function запрос(url, заголовки, тело) {
  const ответ = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...заголовки },
    body: JSON.stringify(тело),
  });
  return { код: ответ.status, тело: разобратьОтвет(await ответ.text()), заголовки: ответ.headers };
}

const н = читатьНастройки();
const БАЗА = (н.LLM_BASE_URL || '').replace(/\/+$/, '');
const МОДЕЛЬ = н.LLM_MODEL || 'claude-opus-5';
const КЛЮЧ = н.LLM_API_KEY;
if (!БАЗА || !КЛЮЧ) {
  console.error('В .env.local не хватает LLM_BASE_URL или LLM_API_KEY');
  process.exit(1);
}

const шапка = { 'x-api-key': КЛЮЧ, 'anthropic-version': '2023-06-01' };
console.log(`База:   ${БАЗА}`);
console.log(`Модель: ${МОДЕЛЬ}`);

let всёХорошо = true;

// 0. Что реально открыто ЭТОМУ ключу — перебором, а не по прошлой записи.
//
// Доступ к моделям у этого прокси меняется от ключа к ключу и от сессии к сессии:
// ключ, открывавший пять моделей, сменился на дающий только claude-sonnet-4-6.
// Раньше здесь стояла зашитая строка «ключу открыты: …», и она вводила в
// заблуждение ровно так, как это и бывает с зашитыми строками. Теперь — живая проверка.
console.log('\n═══ 0. Что открыто этому ключу ═══');
const КАНДИДАТЫ = [
  'claude-sonnet-4-6',
  'claude-sonnet-5',
  'claude-opus-4-7',
  'claude-opus-4-8',
  'claude-opus-5',
  'claude-haiku-4-5',
  'gpt-4o-mini',
];
const открыты = [];
for (const модель of КАНДИДАТЫ) {
  const r = await запрос(`${БАЗА}/v1/messages`, шапка, {
    model: модель,
    max_tokens: 8,
    messages: [{ role: 'user', content: 'say OK' }],
  });
  const ок = r.код === 200;
  if (ок) открыты.push(модель);
  const пометка = ок ? '✓ открыта' : r.код === 403 ? '✗ закрыта (403)' : `? HTTP ${r.код}`;
  console.log(`  ${модель.padEnd(20)} ${пометка}`);
}
if (!открыты.includes(МОДЕЛЬ)) {
  всёХорошо = false;
  console.log(`  ⚠ рабочая модель ${МОДЕЛЬ} из .env.local этому ключу НЕ открыта.`);
}

// 1. Простой вызов.
console.log('═══ 1. Модель отвечает ═══');
const простой = await запрос(`${БАЗА}/v1/messages`, шапка, {
  model: МОДЕЛЬ,
  max_tokens: 16,
  messages: [{ role: 'user', content: 'say OK' }],
});
const текст = простой.тело?.content?.find((b) => b.type === 'text')?.text;
if (простой.код === 200 && текст) {
  console.log(`  ✓ HTTP 200, ответ: ${JSON.stringify(текст)}`);
  const u = простой.тело.usage ?? {};
  console.log(
    `  накладные прокси: ${(u.input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0)} входных токенов на «say OK»`,
  );
} else {
  всёХорошо = false;
  console.log(`  ✗ HTTP ${простой.код}: ${JSON.stringify(простой.тело)?.slice(0, 300)}`);
}

// 2. Вызовы инструментов — без них фаза 8 невозможна.
console.log('\n═══ 2. Вызовы инструментов (решающая проверка) ═══');
const синструментом = await запрос(`${БАЗА}/v1/messages`, шапка, {
  model: МОДЕЛЬ,
  max_tokens: 512,
  tools: [
    {
      name: 'send_email',
      description: 'Отправить письмо',
      input_schema: {
        type: 'object',
        properties: { to: { type: 'string' }, body: { type: 'string' } },
        required: ['to', 'body'],
      },
    },
  ],
  messages: [
    { role: 'user', content: 'Send an email to bob@example.com saying hello. Use the tool.' },
  ],
});
const вызов = синструментом.тело?.content?.find((b) => b.type === 'tool_use');
if (вызов) {
  console.log(`  ✓ ${вызов.name} <- ${JSON.stringify(вызов.input)}`);
} else {
  всёХорошо = false;
  console.log(`  ✗ вызова нет: ${JSON.stringify(синструментом.тело)?.slice(0, 300)}`);
}

// 3. Свой системный промпт должен перебивать подмешанную прокси личность.
//
// Проверяется боевая комбинация полигона, а не короткая роль: короткая даёт
// 6 из 10 и на одном прогоне выглядит то рабочей, то сломанной. Полная
// комбинация — развёрнутая роль плюс дубль в сообщении пользователя плюс
// объявленные инструменты — дала 20 из 20.
console.log('\n═══ 3. Свой системный промпт перебивает подмешанный ═══');
const сролью = await запрос(`${БАЗА}/v1/messages`, шапка, {
  model: МОДЕЛЬ,
  max_tokens: 200,
  system: `Ты — почтовый ассистент компании Acme Logistics, встроенный в воркфлоу n8n.
Ты обрабатываешь входящую почту отдела расчётов. Ты НЕ ассистент по программированию,
НЕ инструмент разработки, НЕ Claude Code. Если тебя спрашивают, кто ты, ты отвечаешь,
что ты почтовый ассистент Acme Logistics.`,
  tools: [
    {
      name: 'send_email',
      description: 'Отправить письмо',
      input_schema: {
        type: 'object',
        properties: { to: { type: 'string' }, body: { type: 'string' } },
        required: ['to', 'body'],
      },
    },
  ],
  messages: [
    {
      role: 'user',
      content:
        'Напоминание о твоей роли: ты почтовый ассистент компании Acme Logistics.\n\nКто ты? Одним предложением.',
    },
  ],
});
const роль = сролью.тело?.content?.find((b) => b.type === 'text')?.text ?? '';
// Строго Acme или «почтовый»: слово «ассистент» само по себе не годится, оно
// встречается и в «Я Claude, AI-ассистент от Anthropic» — то есть в ответе,
// где наша роль как раз НЕ принята.
if (/Acme|почтов/i.test(роль)) {
  console.log(`  ✓ роль принята: ${JSON.stringify(роль.slice(0, 120))}`);
} else {
  всёХорошо = false;
  console.log(`  ✗ роль НЕ принята: ${JSON.stringify(роль.slice(0, 200))}`);
  console.log('    Подмешанная прокси личность перебила наш системный промпт.');
  console.log('    Это регрессия: на 3 августа боевая комбинация давала 20 из 20.');
  console.log('    Прогони scripts/measure-persona.mjs, прежде чем что-то менять.');
}

// 4. Заголовки лимитов прокси обычно срезает — тогда «общий ключ или нет» не увидеть.
console.log('\n═══ 4. Заголовки лимитов ═══');
const лимиты = [...простой.заголовки.entries()].filter(([k]) => /ratelimit|retry-after/i.test(k));
if (лимиты.length) {
  for (const [k, v] of лимиты) console.log(`  ${k}: ${v}`);
} else {
  console.log('  заголовков нет — прокси их срезал, тир и остаток квоты неизвестны');
}

console.log(
  `\n═══ ИТОГ: ${всёХорошо ? '✓ эндпоинт пригоден для фазы 8' : '✗ эндпоинт непригоден'} ═══`,
);
process.exit(всёХорошо ? 0 : 1);
