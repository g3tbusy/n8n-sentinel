// Драйверы жертвы: один цикл агента, два провайдера.
//
// Зачем. Жертва полигона до фазы 8.1 всегда была Anthropic (Sonnet), и весь цикл
// агента говорил на формате Anthropic Messages. Но библиотека n8n на 63% живёт на
// OpenAI, и главная оговорка отчёта — «замерена только Anthropic 7,8%». Чтобы её
// снять, жертвой должна уметь быть и модель OpenAI. Форматы несовместимы: у
// Anthropic инструменты и результаты лежат блоками в content, у OpenAI — отдельными
// ролями (`assistant.tool_calls`, `role:tool`). Драйвер прячет эту разницу, а цикл
// агента (`прогонЖертвы`) остаётся один.
//
// Детектор успеха, защиты и корпус к провайдеру безразличны: они работают с
// нормализованным вызовом `{ name, input }`, который выдают оба драйвера.

import { создатьКлиента, создатьOpenAIКлиента } from './lib.mjs';

// Нормализованный ответ жертвы, одинаковый для обоих провайдеров:
//   { код, обрублен, отказ, текст, вызовы: [{ id, name, input }], ход }
// где `ход` — сырой объект ответа ассистента, который надо дописать в диалог перед
// тем, как класть туда результаты инструментов.

// ─── Anthropic (Messages) ────────────────────────────────────────────────────
function драйверAnthropic({ база, ключ, модель }) {
  const клиент = создатьКлиента({ база, ключ });
  return {
    модель,
    провайдер: 'anthropic',
    инструменты: (список) => список, // уже в формате Anthropic
    async спросить({ система, инструменты, сообщения }) {
      const ответ = await клиент({
        model: модель,
        max_tokens: 8192,
        system: система,
        tools: инструменты,
        messages: сообщения,
      });
      if (ответ.код !== 200 || !ответ.тело?.content) {
        return { код: ответ.код, ошибка: `HTTP ${ответ.код}` };
      }
      const блоки = ответ.тело.content;
      const вызовы = блоки
        .filter((б) => б.type === 'tool_use')
        .map((б) => ({ id: б.id, name: б.name, input: б.input ?? {} }));
      return {
        код: 200,
        обрублен: ответ.тело.stop_reason === 'max_tokens',
        отказ: ответ.тело.stop_reason === 'refusal',
        текст: блоки.find((б) => б.type === 'text')?.text ?? '',
        вызовы,
        ход: { role: 'assistant', content: блоки },
        usage: ответ.тело.usage ?? null,
      };
    },
    // Результаты инструментов у Anthropic — один user-ход с массивом блоков.
    добавитьХодИРезультаты(сообщения, ход, результаты) {
      сообщения.push(ход);
      сообщения.push({
        role: 'user',
        content: результаты.map((р) => ({
          type: 'tool_result',
          tool_use_id: р.id,
          ...(р.ошибка ? { is_error: true } : {}),
          content: р.содержимое,
        })),
      });
    },
  };
}

// ─── OpenAI (Chat Completions, function-calling) ─────────────────────────────
function драйверOpenAI({ база, ключ, модель }) {
  const клиент = создатьOpenAIКлиента({ база, ключ });
  return {
    модель,
    провайдер: 'openai',
    // Anthropic-инструмент { name, description, input_schema } → OpenAI-функция.
    инструменты: (список) =>
      список.map((и) => ({
        type: 'function',
        function: { name: и.name, description: и.description, parameters: и.input_schema },
      })),
    async спросить({ система, инструменты, сообщения }) {
      // Система у OpenAI — отдельным сообщением в начале, а не параметром.
      const ответ = await клиент({
        model: модель,
        max_tokens: 4096,
        tools: инструменты,
        tool_choice: 'auto',
        messages: [{ role: 'system', content: система }, ...сообщения],
      });
      const выбор = ответ.тело?.choices?.[0];
      if (ответ.код !== 200 || !выбор?.message) {
        return { код: ответ.код, ошибка: `HTTP ${ответ.код}` };
      }
      const сообщение = выбор.message;
      const вызовы = (сообщение.tool_calls ?? []).map((в) => {
        let input = {};
        try {
          input = JSON.parse(в.function?.arguments ?? '{}');
        } catch {
          input = {}; // невалидный JSON аргументов — считаем пустым, как и Anthropic-путь
        }
        return { id: в.id, name: в.function?.name, input };
      });
      return {
        код: 200,
        обрублен: выбор.finish_reason === 'length',
        отказ: false, // у OpenAI нет stop_reason=refusal; отказ — это текст, его ловит детектор
        текст: сообщение.content ?? '',
        вызовы,
        ход: сообщение, // сырое assistant-сообщение с tool_calls
        usage: ответ.тело.usage ?? null,
      };
    },
    // Результаты у OpenAI — по отдельному сообщению role:tool на каждый вызов.
    добавитьХодИРезультаты(сообщения, ход, результаты) {
      сообщения.push(ход);
      for (const р of результаты) {
        сообщения.push({ role: 'tool', tool_call_id: р.id, content: String(р.содержимое) });
      }
    },
  };
}

export function создатьДрайверЖертвы({ провайдер, база, ключ, модель }) {
  if (провайдер === 'openai') return драйверOpenAI({ база, ключ, модель });
  if (провайдер === 'anthropic') return драйверAnthropic({ база, ключ, модель });
  throw new Error(`Неизвестный провайдер жертвы: ${провайдер}`);
}
