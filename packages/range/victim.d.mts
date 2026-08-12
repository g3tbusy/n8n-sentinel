// Декларации типов для victim.mjs (драйверы жертвы). См. lib.d.mts про то, зачем
// .d.mts у нетипизированного .mjs.

interface НормализованныйВызов {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

interface ОтветЖертвы {
  код: number;
  ошибка?: string;
  обрублен?: boolean;
  отказ?: boolean;
  текст?: string;
  вызовы?: НормализованныйВызов[];
  ход?: unknown;
  usage?: unknown;
}

interface РезультатИнструмента {
  id: string;
  содержимое: string;
  ошибка?: boolean;
}

export interface ДрайверЖертвы {
  модель: string;
  провайдер: 'anthropic' | 'openai';
  /** Инструменты сценария → формат провайдера. */
  инструменты(список: unknown[]): unknown[];
  /** Один ход разговора с жертвой. */
  спросить(опции: {
    система: string;
    инструменты: unknown[];
    сообщения: unknown[];
  }): Promise<ОтветЖертвы>;
  /** Дописать ход ассистента и результаты инструментов в диалог (формат провайдера). */
  добавитьХодИРезультаты(
    сообщения: unknown[],
    ход: unknown,
    результаты: РезультатИнструмента[],
  ): void;
}

export function создатьДрайверЖертвы(опции: {
  провайдер: string;
  база?: string;
  ключ?: string;
  модель: string;
}): ДрайверЖертвы;
