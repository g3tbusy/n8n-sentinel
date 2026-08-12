// Замок на драйверы жертвы: конвертация инструментов и склейка диалога у Anthropic
// и OpenAI различаются, и если формат разъедется — жертва просто перестанет видеть
// инструменты или результаты, а замер молча уползёт в «не поддался». Сеть тут не
// нужна: клиент создаётся лениво, а проверяем мы чистую часть драйвера.

import { describe, it, expect } from 'vitest';
import { создатьДрайверЖертвы } from '../victim.mjs';

const ИНСТРУМЕНТЫ = [
  {
    name: 'http_request',
    description: 'Выполнить HTTP-запрос',
    input_schema: {
      type: 'object',
      properties: { url: { type: 'string' } },
      required: ['url'],
    },
  },
];

describe('драйвер жертвы — Anthropic', () => {
  const д = создатьДрайверЖертвы({
    провайдер: 'anthropic',
    база: 'https://x',
    ключ: 'k',
    модель: 'claude-sonnet-4-6',
  });

  it('инструменты оставляет в формате Anthropic (input_schema)', () => {
    expect(д.инструменты(ИНСТРУМЕНТЫ)).toEqual(ИНСТРУМЕНТЫ);
  });

  it('результаты кладёт одним user-ходом с блоками tool_result', () => {
    const сообщения: unknown[] = [];
    const ход = {
      role: 'assistant',
      content: [{ type: 'tool_use', id: 't1', name: 'x', input: {} }],
    };
    д.добавитьХодИРезультаты(сообщения, ход, [{ id: 't1', содержимое: 'ок' }]);
    expect(сообщения).toHaveLength(2);
    expect(сообщения[0]).toBe(ход);
    const результат = сообщения[1] as {
      role: string;
      content: Array<{ type: string; tool_use_id: string }>;
    };
    expect(результат.role).toBe('user');
    expect(результат.content[0]?.type).toBe('tool_result');
    expect(результат.content[0]?.tool_use_id).toBe('t1');
  });
});

describe('драйвер жертвы — OpenAI', () => {
  const д = создатьДрайверЖертвы({
    провайдер: 'openai',
    база: 'https://x/v1',
    ключ: 'k',
    модель: 'gpt-5.4-mini',
  });

  it('инструменты конвертирует в function-формат OpenAI', () => {
    const t = (
      д.инструменты(ИНСТРУМЕНТЫ) as Array<{
        type: string;
        function: { name: string; parameters: unknown };
      }>
    )[0];
    expect(t?.type).toBe('function');
    expect(t?.function.name).toBe('http_request');
    expect(t?.function.parameters).toEqual(ИНСТРУМЕНТЫ[0]?.input_schema);
  });

  it('результаты кладёт отдельными сообщениями role:tool', () => {
    const сообщения: unknown[] = [];
    const ход = {
      role: 'assistant',
      content: null,
      tool_calls: [{ id: 'c1', function: { name: 'x', arguments: '{}' } }],
    };
    д.добавитьХодИРезультаты(сообщения, ход, [
      { id: 'c1', содержимое: 'ок' },
      { id: 'c2', содержимое: 'отклонено', ошибка: true },
    ]);
    expect(сообщения).toHaveLength(3); // ход + два результата
    expect(сообщения[0]).toBe(ход);
    const р1 = сообщения[1] as { role: string; tool_call_id: string; content: string };
    expect(р1.role).toBe('tool');
    expect(р1.tool_call_id).toBe('c1');
    expect(р1.content).toBe('ок');
    expect((сообщения[2] as { tool_call_id: string }).tool_call_id).toBe('c2');
  });

  it('неизвестный провайдер — ошибка, а не тихий неверный драйвер', () => {
    expect(() => создатьДрайверЖертвы({ провайдер: 'gemini', модель: 'x' })).toThrow();
  });
});
