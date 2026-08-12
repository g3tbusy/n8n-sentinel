import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyseWorkflow } from '../src/analyse.js';
import { defaultRules } from '../src/rules/default-rules.js';
import type { Finding, RuleId } from '../src/checkers/types.js';
import { T, workflow } from './build-workflow.js';
import type { Edge, NodeSpec } from './build-workflow.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const FIXTURES = join(REPO_ROOT, 'fixtures', 'real');
const rules = defaultRules();

const scan = (nodes: Record<string, string | NodeSpec>, edges: readonly Edge[]): Finding[] => [
  ...analyseWorkflow(workflow(nodes, edges), rules).findings,
];

/** Находки только одного правила — у каждого остального есть свой тест. */
const scanRule = (
  rule: RuleId,
  nodes: Record<string, string | NodeSpec>,
  edges: readonly Edge[],
): Finding[] => scan(nodes, edges).filter((f) => f.rule === rule);

const scanFixture = (file: string): readonly Finding[] =>
  analyseWorkflow(JSON.parse(readFileSync(join(FIXTURES, file), 'utf8')), rules).findings;

/** Имена нод вдоль трассы находки, источник первым, — то, что печатает отчёт. */
const traceNodes = (f: Finding): string[] => [
  f.trace[0]?.from ?? f.source.node,
  ...f.trace.map((s) => s.to),
];

const sendAndWait = { type: T.telegram, parameters: { operation: 'sendAndWait' } };
const draft = {
  type: 'n8n-nodes-base.gmail',
  parameters: { resource: 'draft', operation: 'create' },
};
const dbRead = { type: T.postgres, parameters: { operation: 'select' } };

// Форма, ради поиска которой существует сканер: что-то извне, агент, действующий инструмент.
const injectable: [Record<string, string | NodeSpec>, Edge[]] = [
  { Hook: T.webhook, Agent: T.agent, Mail: T.gmailTool },
  [
    ['Hook', 'Agent'],
    ['Mail', 'Agent', 'ai_tool'],
  ],
];

describe('INDIRECT_PROMPT_INJECTION', () => {
  it('срабатывает на источник → агент → необратимый инструмент, со всей трассой', () => {
    const findings = scan(...injectable);
    expect(findings).toHaveLength(1);

    const f = findings[0] as Finding;
    expect(f.rule).toBe('INDIRECT_PROMPT_INJECTION');
    expect(f.severity).toBe('critical');
    expect(f.confidence).toBe('firm');
    expect(f.agent).toBe('Agent');
    expect(f.sink).toEqual({ node: 'Mail', effect: 'send-message', irreversible: true });
    expect(traceNodes(f)).toEqual(['Hook', 'Agent', 'Mail']);
    // Второй шаг — это ребро, которое n8n хранит задом наперёд. Читатель, сверяющий это с
    // холстом, такой стрелки не найдёт, поэтому находка обязана об этом сказать.
    expect(f.trace[1]).toMatchObject({ kind: 'invocation', derived: true });
    expect(f.notes.join(' ')).toContain('на холсте такой стрелки нет');
  });

  it('молчит, когда между агентом и действием подтверждает человек', () => {
    const findings = scan(
      { Hook: T.webhook, Agent: T.agent, Approve: sendAndWait, Mail: T.emailSend },
      [
        ['Hook', 'Agent'],
        ['Agent', 'Approve'],
        ['Approve', 'Mail'],
      ],
    );
    expect(findings).toEqual([]);
  });

  it('снова срабатывает, когда шаг подтверждения выключили', () => {
    // Тот же документ, один флаг. Выключенная нода не выполняется, и n8n пропускает данные
    // сквозь неё — так что это разница между защищённым воркфлоу и открытым.
    const findings = scan(
      {
        Hook: T.webhook,
        Agent: T.agent,
        Approve: { ...sendAndWait, disabled: true },
        Mail: T.emailSend,
      },
      [
        ['Hook', 'Agent'],
        ['Agent', 'Approve'],
        ['Approve', 'Mail'],
      ],
    );
    expect(findings.map((f) => f.sink.node)).toEqual(['Mail']);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('никогда не показывает сам шаг подтверждения как действие', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Approve: sendAndWait }, [
      ['Hook', 'Agent'],
      ['Agent', 'Approve'],
    ]);
    // `Approve` — это отправка сообщения, и она действительно несёт подконтрольный атакующему
    // текст — тому человеку, которого просят подтвердить. Это работающий механизм, а не находка.
    expect(findings).toEqual([]);
  });

  it('молчит об агенте, у которого ничего не подключено к эффекту', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Out: T.set }, [
      ['Hook', 'Agent'],
      ['Agent', 'Out'],
    ]);
    expect(findings).toEqual([]);
  });

  it('молчит, когда на пути нет модели с инструментами', () => {
    // Недоверенный ввод, доходящий до sink напрямую, — другое правило (фаза 4), не это.
    const findings = scanRule(
      'INDIRECT_PROMPT_INJECTION',
      { Hook: T.webhook, Chain: T.chain, Mail: T.emailSend },
      [
        ['Hook', 'Chain'],
        ['Chain', 'Mail'],
      ],
    );
    expect(findings).toEqual([]);
  });
});

describe('severity', () => {
  it('снимает полосу за слабый гейт между агентом и действием', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Check: T.if, Mail: T.emailSend }, [
      ['Hook', 'Agent'],
      ['Agent', 'Check'],
      ['Check', 'Mail'],
    ]);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.weakGates).toEqual(['Check']);
  });

  it('не снимает полосу за слабый гейт перед агентом', () => {
    // Фильтр выше по потоку решает, какие сообщения пойдут в обработку. Он никогда не видит,
    // что решил агент, и потому не защищает от того, что агент решит сделать что-то другое.
    const findings = scan({ Hook: T.webhook, Check: T.if, Agent: T.agent, Mail: T.gmailTool }, [
      ['Hook', 'Check'],
      ['Check', 'Agent'],
      ['Mail', 'Agent', 'ai_tool'],
    ]);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.weakGates).toEqual(['Check']);
  });

  it('снимает полосу, когда действие можно отменить', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Draft: draft }, [
      ['Hook', 'Agent'],
      ['Agent', 'Draft'],
    ]);
    expect(findings[0]?.sink.irreversible).toBe(false);
    expect(findings[0]?.severity).toBe('high');
  });

  it('оценивает источник, который всего лишь ваше хранилище, ниже внешнего', () => {
    const findings = scan({ Read: dbRead, Agent: T.agent, Mail: T.emailSend }, [
      ['Read', 'Agent'],
      ['Agent', 'Mail'],
    ]);
    expect(findings[0]?.source.trust).toBe('semi-trusted');
    expect(findings[0]?.severity).toBe('high');
  });

  it('упирается в low, а не проваливается ниже', () => {
    const findings = scan({ Read: dbRead, Agent: T.agent, Check: T.if, Draft: draft }, [
      ['Read', 'Agent'],
      ['Agent', 'Check'],
      ['Check', 'Draft'],
    ]);
    expect(findings[0]?.severity).toBe('low');
  });
});

describe('границы вложенных воркфлоу', () => {
  it('помечает путь в другой воркфлоу непрослеженным, а не гадает', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Sub: T.toolWorkflow }, [
      ['Hook', 'Agent'],
      ['Sub', 'Agent', 'ai_tool'],
    ]);
    expect(findings).toHaveLength(1);

    const f = findings[0] as Finding;
    // Сомнение живёт в confidence: sink-ов вызываемого воркфлоу в этом документе нет,
    // и узнать, есть ли внутри необратимое действие, отсюда нельзя.
    expect(f.confidence).toBe('uncertain');
    // А полоса отвечает на другой вопрос — насколько плохо, ЕСЛИ оно там есть, — и потому
    // считается как для необратимого sink на том же пути. Раньше здесь стояло `medium`:
    // неизвестность понижала полосу, то есть одно сомнение дисконтировалось дважды.
    // Полигон (фаза 8.2, S1) развёл эти вещи замером — довести агента до вызова
    // под-воркфлоу с аргументами атакующего удаётся практически всегда.
    expect(f.severity).toBe('critical');
    expect(f.sink.effect).toBeUndefined();
    expect(f.notes.join(' ')).toContain('Просканируйте вызываемый воркфлоу');
  });
});

describe('подача находок', () => {
  it('показывает по находке на действие, а не на маршрут к нему', () => {
    // Два источника, два агента, один sink. Отчёт с четырьмя записями об одной проблеме —
    // это отчёт, который никто не дочитает.
    const findings = scan(
      { Hook: T.webhook, Mail: T.gmailTrigger, First: T.agent, Second: T.agent, Send: T.emailSend },
      [
        ['Hook', 'First'],
        ['Mail', 'First'],
        ['First', 'Second'],
        ['Second', 'Send'],
      ],
    );
    expect(findings).toHaveLength(1);

    const f = findings[0] as Finding;
    // Инъекция попадает в первого агента на маршруте; назвать второго значило бы показать
    // читателю не ту ноду.
    expect(f.agent).toBe('First');
    expect(f.otherSources).toEqual(['Mail']);
    expect(f.notes.join(' ')).toContain('дотягивается 2 нод, вызывающих инструменты');
  });

  it('ставит самую серьёзную находку первой', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Draft: draft, Mail: T.emailSend }, [
      ['Hook', 'Agent'],
      ['Agent', 'Draft'],
      ['Agent', 'Mail'],
    ]);
    expect(findings.map((f) => f.severity)).toEqual(['critical', 'high']);
  });

  it('даёт одинаковый вывод дважды для одного документа', () => {
    const once = JSON.stringify(scan(...injectable));
    const twice = JSON.stringify(scan(...injectable));
    expect(once).toBe(twice);
  });
});

// Два случая, по которым меряется фаза, на документах, которые никто не писал ради теста.
describe('настоящие воркфлоу', () => {
  const VULNERABLE = '04057-auto-respond-to-gmail-enquiries-using-gpt-4o-dum.json';
  const GATED = '13216-post-ai-news-to-telegram-with-google-gemini-and-.json';

  it('прослеживает почту на входе, модель посередине, почту на выходе — самую частую форму в корпусе', () => {
    const findings = scanFixture(VULNERABLE);
    const f = findings.find((x) => x.sink.node === 'Send Email Response via Gmail');

    expect(f?.severity).toBe('critical');
    expect(f?.source.node).toBe('Watch Gmail for New Incoming Emails');
    expect(f?.agent).toBe('LangChain Agent Handles Reply Logic');
    expect(traceNodes(f as Finding)).toEqual([
      'Watch Gmail for New Incoming Emails',
      'Classify Email Type with GPT-4o',
      ' Only Proceed if Email is an Enquiry',
      'LangChain Agent Handles Reply Logic',
      'Send Email Response via Gmail',
    ]);
    // Фильтр есть в трассе и назван, но severity он не снизил: он работает до агента и
    // никогда не видит, что тот решил сделать.
    expect(f?.weakGates).toEqual([' Only Proceed if Email is an Enquiry']);
  });

  it('молчит о воркфлоу, который сперва спрашивает человека', () => {
    // RSS на входе, модель, затем `sendAndWait` в Telegram до всякой публикации.
    expect(scanFixture(GATED).filter((f) => f.rule === 'INDIRECT_PROMPT_INJECTION')).toEqual([]);
    // И больше ничто не оценивает это как critical: гейт — единственное, что стоит между
    // враждебным элементом ленты и каналом, и он держит.
    expect(scanFixture(GATED).filter((f) => f.severity === 'critical')).toEqual([]);
  });

  it('сканирует каждую фикстуру без исключений и записывает, как часто срабатывает', () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith('.json') && f !== 'manifest.json');
    let firing = 0;
    let critical = 0;
    const counts: string[] = [];

    for (const file of files) {
      // Частота именно этого правила. Считать находки всех правил под именем одного — верный
      // способ лишить заголовочное число смысла.
      const findings = scanFixture(file).filter((f) => f.rule === 'INDIRECT_PROMPT_INJECTION');
      if (findings.length > 0) firing++;
      critical += findings.filter((f) => f.severity === 'critical').length;
      if (findings.length > 0) counts.push(`${file.slice(0, 5)}×${findings.length}`);
    }

    // Печатается, а не просто проверяется: частоте срабатывания место в README числом. Эти
    // фикстуры по построению переоценивают долю агентов — см. fixtures/real/manifest.json.
    console.log(
      `INDIRECT_PROMPT_INJECTION fires on ${firing}/${files.length} fixtures ` +
        `(${critical} critical findings): ${counts.join(', ')}`,
    );
    expect(firing).toBeGreaterThan(0);
    expect(firing).toBeLessThan(files.length);
  });

  // Настоящая частота, на 794 воркфлоу, которых никто не выбирал за интересность.
  const CACHE = join(REPO_ROOT, '.corpus-cache');
  it.runIf(existsSync(CACHE))('записывает частоту срабатывания по выборке корпуса', () => {
    const files = readdirSync(CACHE).filter((f) => f.endsWith('.json') && f !== '_manifest.json');
    let firing = 0;
    let findings = 0;
    const bySeverity = new Map<string, number>();

    for (const file of files) {
      const record = JSON.parse(readFileSync(join(CACHE, file), 'utf8')) as { workflow?: unknown };
      const result = analyseWorkflow(record.workflow, rules);
      if (result.findings.length > 0) firing++;
      findings += result.findings.length;
      for (const f of result.findings) {
        bySeverity.set(f.severity, (bySeverity.get(f.severity) ?? 0) + 1);
      }
    }

    console.log(
      `corpus: ${firing}/${files.length} workflows (${((firing / files.length) * 100).toFixed(1)}%) ` +
        `have at least one finding of any rule; ${findings} findings total; ` +
        `${[...bySeverity]
          .sort()
          .map(([s, n]) => `${s}=${n}`)
          .join(', ')}`,
    );
    expect(firing).toBeGreaterThan(0);
  });
});
