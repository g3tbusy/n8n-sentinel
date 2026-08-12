import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyseWorkflow } from '../src/analyse.js';
import { defaultRules } from '../src/rules/default-rules.js';
import type { Finding, RuleId } from '../src/checkers/types.js';
import { config, T, workflow } from './build-workflow.js';
import type { Edge, NodeSpec } from './build-workflow.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const FIXTURES = join(REPO_ROOT, 'fixtures', 'real');
const rules = defaultRules();

const scan = (
  nodes: Record<string, string | NodeSpec>,
  edges: readonly Edge[],
): readonly Finding[] => analyseWorkflow(workflow(nodes, edges), rules).findings;

const only = (
  rule: RuleId,
  nodes: Record<string, string | NodeSpec>,
  edges: readonly Edge[],
): Finding[] => [...scan(nodes, edges)].filter((f) => f.rule === rule);

const http = (url: string, extra: Record<string, unknown> = {}): NodeSpec => ({
  type: T.http,
  parameters: { url, method: 'POST', ...extra },
});
const sql = (query: string): NodeSpec => ({
  type: T.postgres,
  parameters: { operation: 'executeQuery', query },
});
const shell = (command: string): NodeSpec => ({ type: T.command, parameters: { command } });
const js = (jsCode: string): NodeSpec => ({ type: T.code, parameters: { jsCode } });
const sendAndWait = { type: T.telegram, parameters: { operation: 'sendAndWait' } };

// ---------------------------------------------------------------- EXPRESSION_SSRF

describe('EXPRESSION_SSRF', () => {
  it('срабатывает, когда недоверенные данные выбирают весь URL', () => {
    const findings = only('EXPRESSION_SSRF', { Hook: T.webhook, Call: http('={{ $json.url }}') }, [
      ['Hook', 'Call'],
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.title).toContain('весь URL');
  });

  it('срабатывает ниже, когда выбирается только сегмент пути', () => {
    // Хост был выбран при написании воркфлоу. Оценивать это так же, как свободный выбор
    // адресата, значило бы похоронить те случаи, где выбор действительно свободен.
    const findings = only(
      'EXPRESSION_SSRF',
      { Hook: T.webhook, Call: http('=https://api.example.com/v1/{{ $json.id }}') },
      [['Hook', 'Call']],
    );
    expect(findings[0]?.severity).toBe('high');
  });

  it('видит хост, склеенный внутри скобок', () => {
    const findings = only(
      'EXPRESSION_SSRF',
      { Hook: T.webhook, Call: http("={{ 'https://api.example.com/v1/' + $json.id }}") },
      [['Hook', 'Call']],
    );
    expect(findings[0]?.severity).toBe('high');
  });

  it('молчит о захардкоженном базовом URL, лежащем в ноде Set', () => {
    // Конфиг в ноде Set — самая частая форма в корпусе, и такая нода стоит ниже триггера,
    // поэтому один только taint на уровне нод её показывает. Пять из первых двенадцати
    // critical по корпусу были именно этим, пока поле не начали разрешать.
    const findings = only(
      'EXPRESSION_SSRF',
      {
        Hook: T.webhook,
        Config: config({ BASE_URL: 'https://api.example.com' }),
        Call: http("={{ $('Config').json.BASE_URL }}/v1/status"),
      },
      [
        ['Hook', 'Config'],
        ['Config', 'Call'],
      ],
    );
    expect(findings).toEqual([]);
  });

  it('всё равно срабатывает, когда это поле Set само является выражением', () => {
    const findings = only(
      'EXPRESSION_SSRF',
      {
        Hook: T.webhook,
        Config: config({ BASE_URL: '={{ $json.host }}' }),
        Call: http("={{ $('Config').json.BASE_URL }}/v1/status"),
      },
      [
        ['Hook', 'Config'],
        ['Config', 'Call'],
      ],
    );
    expect(findings).toHaveLength(1);
  });

  it('молчит о фиксированном URL', () => {
    expect(
      only('EXPRESSION_SSRF', { Hook: T.webhook, Call: http('https://api.example.com/v1') }, [
        ['Hook', 'Call'],
      ]),
    ).toEqual([]);
  });

  it('молчит, когда до ноды не доходит ничего недоверенного', () => {
    expect(
      only('EXPRESSION_SSRF', { Clock: T.schedule, Call: http('={{ $json.url }}') }, [
        ['Clock', 'Call'],
      ]),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------- EXPRESSION_SQLI

describe('EXPRESSION_SQLI', () => {
  it('срабатывает, когда недоверенные данные склеиваются в запрос', () => {
    const findings = only(
      'EXPRESSION_SQLI',
      { Hook: T.webhook, Db: sql('=SELECT * FROM users WHERE id = {{ $json.id }}') },
      [['Hook', 'Db']],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('срабатывает, когда запрос целиком пишет модель', () => {
    // `{{ $fromAI('sql_query') }}` без префикса `=` — ровно так, как это лежит в корпусе.
    const findings = only(
      'EXPRESSION_SQLI',
      {
        Hook: T.chatTrigger,
        Agent: T.agent,
        Db: {
          type: 'n8n-nodes-base.postgresTool',
          parameters: { operation: 'executeQuery', query: "{{ $fromAI('sql_query') }}" },
        },
      },
      [
        ['Hook', 'Agent'],
        ['Db', 'Agent', 'ai_tool'],
      ],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.agent).toBe('Agent');
  });

  it('молчит о запросе без подстановок', () => {
    expect(
      only('EXPRESSION_SQLI', { Hook: T.webhook, Db: sql('SELECT * FROM users') }, [
        ['Hook', 'Db'],
      ]),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------- EXPRESSION_RCE

describe('EXPRESSION_RCE', () => {
  it('срабатывает, когда недоверенные данные склеиваются в команду shell', () => {
    const findings = only(
      'EXPRESSION_RCE',
      { Hook: T.webhook, Run: shell('=ls {{ $json.dir }}') },
      [['Hook', 'Run']],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.confidence).toBe('firm');
  });

  it('показывает ноду Code, вычисляющую строки, и говорит, что не доказано', () => {
    const findings = only(
      'EXPRESSION_RCE',
      { Hook: T.webhook, Run: js('const f = new Function($json.src); return f()') },
      [['Hook', 'Run']],
    );
    expect(findings).toHaveLength(1);
    // Конструкция в коде, данные в ноде. Что первое дотягивается до второго, никто не
    // проверял.
    expect(findings[0]?.confidence).toBe('uncertain');
    expect(findings[0]?.severity).toBe('high');
  });

  it('молчит об обычном коде, как бы он ни был заражён', () => {
    expect(
      only('EXPRESSION_RCE', { Hook: T.webhook, Run: js('return $input.all()') }, [
        ['Hook', 'Run'],
      ]),
    ).toEqual([]);
  });

  it('молчит о фиксированной команде', () => {
    expect(
      only('EXPRESSION_RCE', { Hook: T.webhook, Run: shell('ls -la') }, [['Hook', 'Run']]),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------- SECRET_EXFIL_RISK

describe('SECRET_EXFIL_RISK', () => {
  const withKey = {
    headerParameters: { parameters: [{ name: 'X-Key', value: '={{ $env.API_KEY }}' }] },
  };

  it('срабатывает, когда секрет уходит туда, куда указывают недоверенные данные', () => {
    const findings = only(
      'SECRET_EXFIL_RISK',
      { Hook: T.webhook, Call: http('={{ $json.url }}', withKey) },
      [['Hook', 'Call']],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.confidence).toBe('firm');
  });

  it('случай с фиксированным адресатом показывает ниже и говорит, что это не утечка', () => {
    const findings = only(
      'SECRET_EXFIL_RISK',
      { Hook: T.webhook, Call: http('https://api.example.com/v1', withKey) },
      [['Hook', 'Call']],
    );
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.confidence).toBe('uncertain');
    expect(findings[0]?.detail).toContain('не показанная утечка');
  });

  it('молчит о секрете, уходящем на фиксированный хост, когда рядом нет ничего недоверенного', () => {
    expect(
      only(
        'SECRET_EXFIL_RISK',
        { Clock: T.schedule, Call: http('https://api.example.com', withKey) },
        [['Clock', 'Call']],
      ),
    ).toEqual([]);
  });

  it('не срабатывает просто потому, что у ноды есть доступы', () => {
    // Доступы есть у любой ноды, которая хоть что-то делает. Сказать это про все —
    // инвентаризация, а не находка.
    expect(
      only('SECRET_EXFIL_RISK', { Hook: T.webhook, Mail: T.emailSend }, [['Hook', 'Mail']]),
    ).toEqual([]);
  });
});

// -------------------------------------------------------------- полномочия агента

describe('MISSING_HUMAN_APPROVAL', () => {
  it('срабатывает на агенте, который действует необратимо и без присмотра', () => {
    const findings = only(
      'MISSING_HUMAN_APPROVAL',
      { Clock: T.schedule, Agent: T.agent, Mail: T.emailSend },
      [
        ['Clock', 'Agent'],
        ['Agent', 'Mail'],
      ],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('отступает там, где уже высказалось правило об инъекции', () => {
    // Та же схема связей, но недоверенный триггер. Одна проблема, одна находка — под тем
    // именем, которое описывает её лучше всего.
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Mail: T.emailSend }, [
      ['Hook', 'Agent'],
      ['Agent', 'Mail'],
    ]);
    expect(findings.filter((f) => f.rule === 'MISSING_HUMAN_APPROVAL')).toEqual([]);
    expect(findings.filter((f) => f.rule === 'INDIRECT_PROMPT_INJECTION')).toHaveLength(1);
  });

  it('молчит, когда подтверждает человек', () => {
    expect(
      only('MISSING_HUMAN_APPROVAL', { Clock: T.schedule, Agent: T.agent, Ask: sendAndWait }, [
        ['Clock', 'Agent'],
        ['Agent', 'Ask'],
      ]),
    ).toEqual([]);
  });
});

describe('OVERBROAD_TOOL_ACCESS', () => {
  const deleteTool = {
    type: 'n8n-nodes-base.postgresTool',
    parameters: { operation: 'deleteTable' },
  };

  it('срабатывает на агенте, держащем разрушающий инструмент', () => {
    const findings = only(
      'OVERBROAD_TOOL_ACCESS',
      { Clock: T.schedule, Agent: T.agent, Drop: deleteTool },
      [
        ['Clock', 'Agent'],
        ['Drop', 'Agent', 'ai_tool'],
      ],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('оценивает выше, когда до агента к тому же доходит недоверенный ввод', () => {
    const findings = only(
      'OVERBROAD_TOOL_ACCESS',
      { Hook: T.chatTrigger, Agent: T.agent, Drop: deleteTool },
      [
        ['Hook', 'Agent'],
        ['Drop', 'Agent', 'ai_tool'],
      ],
    );
    expect(findings[0]?.severity).toBe('high');
  });

  it('молчит об агенте, чьи инструменты только читают', () => {
    expect(
      only(
        'OVERBROAD_TOOL_ACCESS',
        {
          Clock: T.schedule,
          Agent: T.agent,
          Read: { type: 'n8n-nodes-base.postgresTool', parameters: { operation: 'select' } },
        },
        [
          ['Clock', 'Agent'],
          ['Read', 'Agent', 'ai_tool'],
        ],
      ),
    ).toEqual([]);
  });

  it('молчит, когда один из инструментов — шаг подтверждения', () => {
    expect(
      only(
        'OVERBROAD_TOOL_ACCESS',
        { Clock: T.schedule, Agent: T.agent, Drop: deleteTool, Ask: sendAndWait },
        [
          ['Clock', 'Agent'],
          ['Drop', 'Agent', 'ai_tool'],
          ['Ask', 'Agent', 'ai_tool'],
        ],
      ),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------- UNGATED_SIDE_EFFECT

describe('UNGATED_SIDE_EFFECT', () => {
  const insert = (params: Record<string, unknown>): NodeSpec => ({
    type: T.postgres,
    parameters: { operation: 'insert', ...params },
  });

  it('срабатывает, когда ввод решает, что сделает действие', () => {
    const findings = only(
      'UNGATED_SIDE_EFFECT',
      { Hook: T.webhook, Db: insert({ table: 'leads', columns: '={{ $json.name }}' }) },
      [['Hook', 'Db']],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.confidence).toBe('firm');
  });

  it('голое «сработал и подействовал» показывает ниже и объясняет почему', () => {
    const findings = only(
      'UNGATED_SIDE_EFFECT',
      { Hook: T.webhook, Db: insert({ table: 'leads' }) },
      [['Hook', 'Db']],
    );
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.confidence).toBe('uncertain');
  });

  it('молчит о собственной таблице, кормящей другую собственную', () => {
    // Прочитать одну таблицу и записать другую — это ETL, а не экспозиция.
    expect(
      only(
        'UNGATED_SIDE_EFFECT',
        {
          Read: { type: T.postgres, parameters: { operation: 'select' } },
          Db: insert({ table: 'leads', columns: '={{ $json.name }}' }),
        },
        [['Read', 'Db']],
      ),
    ).toEqual([]);
  });

  it('отступает там, где на пути стоит открытый агент', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Mail: T.emailSend }, [
      ['Hook', 'Agent'],
      ['Agent', 'Mail'],
    ]);
    expect(findings.filter((f) => f.rule === 'UNGATED_SIDE_EFFECT')).toEqual([]);
  });

  it('молчит за шагом подтверждения', () => {
    expect(
      only(
        'UNGATED_SIDE_EFFECT',
        { Hook: T.webhook, Ask: sendAndWait, Db: insert({ table: 'x' }) },
        [
          ['Hook', 'Ask'],
          ['Ask', 'Db'],
        ],
      ),
    ).toEqual([]);
  });
});

// ------------------------------------------------------------ весь набор вместе

describe('правила вместе', () => {
  it('никогда не показывает одну ноду дважды под двумя именами', () => {
    const findings = scan({ Hook: T.webhook, Agent: T.agent, Call: http('={{ $json.url }}') }, [
      ['Hook', 'Agent'],
      ['Agent', 'Call'],
    ]);
    const perSink = new Map<string, string[]>();
    for (const f of findings) {
      const at = perSink.get(f.sink.node) ?? [];
      at.push(f.rule);
      perSink.set(f.sink.node, at);
    }
    // SSRF и инъекция говорят о `Call` разное — одно про то, что адресата выбирают данные,
    // другое про то, что вызвать его решила модель, — поэтому оба допустимы. Недопустимо
    // одно и то же правило дважды.
    for (const [sink, ruleNames] of perSink) {
      expect(new Set(ruleNames).size, sink).toBe(ruleNames.length);
    }
  });

  it('сканирует каждую фикстуру без исключений и записывает, что находит каждое правило', () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith('.json') && f !== 'manifest.json');
    const perRule = new Map<string, number>();
    const workflowsWithCritical = new Set<string>();

    for (const file of files) {
      const findings = analyseWorkflow(
        JSON.parse(readFileSync(join(FIXTURES, file), 'utf8')),
        rules,
      ).findings;
      for (const f of findings) {
        perRule.set(f.rule, (perRule.get(f.rule) ?? 0) + 1);
        if (f.severity === 'critical') workflowsWithCritical.add(file);
      }
    }

    console.log(
      `fixtures: ${workflowsWithCritical.size}/${files.length} have a critical finding; ` +
        [...perRule]
          .sort()
          .map(([r, n]) => `${r}=${n}`)
          .join(', '),
    );
    // На этих 24 документах срабатывают четыре правила из восьми. Остальные четыре —
    // SQL-инъекция, инъекция команд, утечка секретов, агенты без присмотра — описывают формы,
    // которые действительно редки: во всём корпусе из 794 воркфлоу их 3, 2, 3 и 16. Их
    // покрытие — синтетические пары выше, и сказать это честнее, чем набивать набор фикстур,
    // пока число не станет красивее.
    expect(perRule.size).toBeGreaterThanOrEqual(4);
  });

  it('даёт одинаковый вывод дважды для одного документа', () => {
    const doc = { Hook: T.webhook, Agent: T.agent, Call: http('={{ $json.url }}') };
    const edges: Edge[] = [
      ['Hook', 'Agent'],
      ['Agent', 'Call'],
    ];
    expect(JSON.stringify(scan(doc, edges))).toBe(JSON.stringify(scan(doc, edges)));
  });
});
