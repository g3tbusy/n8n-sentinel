import canonicalVulnerable from '../../../fixtures/real/04057-auto-respond-to-gmail-enquiries-using-gpt-4o-dum.json?raw';
import canonicalSafe from '../../../fixtures/real/13216-post-ai-news-to-telegram-with-google-gemini-and-.json?raw';
import agentWithManyTools from '../../../fixtures/real/14008-openclaw-clone-expandable-personal-telegram-ai-a.json?raw';
import structurallyBroken from '../../../fixtures/real/05805-create-youtube-shorts-scripts-from-video-links-w.json?raw';

/**
 * Примеры в выпадающем списке.
 *
 * Все четыре — закоммиченные фикстуры, побайтово те же, что отдаёт библиотека шаблонов n8n:
 * те самые документы, к которым набор тестов привязывает свои утверждения. Здесь нет ни
 * одного воркфлоу, написанного, чтобы показать проблему: сканер, продемонстрированный только
 * на материале собственного авторства, не доказывает ничего, — а интересное в каноническом
 * случае как раз то, что это шаблон, опубликованный кем-то для копирования другими.
 */

export interface Demo {
  /** Идентификатор шаблона в библиотеке n8n. */
  readonly id: string;
  readonly label: string;
  /** Почему он в списке — показывается под заголовком. */
  readonly note: string;
  readonly json: string;
}

export const DEMOS: readonly Demo[] = [
  {
    id: '04057',
    label: 'Gmail → GPT-4o → агент, который шлёт письма',
    note: 'канонический случай: входящее письмо доходит до инструмента, который на него отвечает',
    json: canonicalVulnerable,
  },
  {
    id: '13216',
    label: 'AI-новости → Telegram, с подтверждением',
    note: 'та же форма, но на пути человек; сильный гейт режет путь наглухо',
    json: canonicalSafe,
  },
  {
    id: '14008',
    label: 'Telegram-агент со множеством инструментов',
    note: 'один агент, дюжина инструментов: находка на действие, а не на маршрут',
    json: agentWithManyTools,
  },
  {
    id: '05805',
    label: 'Воркфлоу, который n8n сам отказывается импортировать',
    note: 'ребро к удалённой ноде; сканер говорит об этом и продолжает работу',
    json: structurallyBroken,
  },
];
