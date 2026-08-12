import type { Finding, RuleId, Severity } from '../checkers/types.js';
import { locateNode } from './locate.js';
import type { SourceRegion } from './locate.js';
import type { ScanReport, ScannedFile } from './types.js';

/**
 * SARIF 2.1.0 — для вкладки Security на GitHub.
 *
 * Два решения стоит проговорить, потому что в обоих местах сканер способен выдать корректный
 * и при этом бесполезный SARIF:
 *
 * - **У находок есть строка.** Результат, чьё местоположение — «этот файл», это пометка, по
 *   которой никто не может действовать. Позиция ноды ищется поиском её имени в тексте файла;
 *   почему это обоснованно и что происходит при неудаче — см. `locate.ts`.
 * - **Трасса становится `codeFlow`.** В SARIF есть структура ровно для этого, а taint-анализ,
 *   расплющивающий свой путь в прозу, выбрасывает единственное, что рецензент может
 *   проверить. GitHub рисует их разворачиваемыми шагами.
 *
 * GitHub читает `properties.security-severity` — число в духе CVSS, — а не собственные четыре
 * уровня SARIF, и показывает результат как оповещение безопасности, только когда правило
 * помечено тегом `security`. И то и другое проставляется ниже.
 */
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

type SarifLevel = 'none' | 'note' | 'warning' | 'error';

const LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

/** Полосы GitHub: >=9.0 critical, >=7.0 high, >=4.0 medium, иначе low. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.3',
  high: '7.5',
  medium: '5.0',
  low: '2.0',
};

interface RuleDoc {
  readonly name: string;
  readonly short: string;
  readonly full: string;
}

const RULE_DOCS: Record<RuleId, RuleDoc> = {
  INDIRECT_PROMPT_INJECTION: {
    name: 'IndirectPromptInjection',
    short: 'Untrusted input reaches a tool-calling model that can act irreversibly',
    full:
      'Data from outside the workflow reaches a node that decides which tools to call, and ' +
      'that node reaches an action which cannot be undone, with no approval step in ' +
      'between. To the model, the developer\u2019s instructions and the incoming text are ' +
      'one stream of characters, so the text can choose the action and its arguments.',
  },
  UNGATED_SIDE_EFFECT: {
    name: 'UngatedSideEffect',
    short: 'Untrusted input reaches an irreversible action with no validation',
    full:
      'Data from outside the workflow reaches an action that cannot be undone, with no ' +
      'approval step and no validation between them. The action was chosen by whoever built ' +
      'the workflow; what the input decides is the values it acts on.',
  },
  EXPRESSION_SSRF: {
    name: 'ExpressionSsrf',
    short: 'Untrusted data decides where an HTTP request goes',
    full:
      'The URL of a request node is built from an expression that reads untrusted data. How ' +
      'much of the destination that data decides \u2014 the whole URL, the host, a path ' +
      'segment, a query value \u2014 sets the severity.',
  },
  EXPRESSION_SQLI: {
    name: 'ExpressionSqli',
    short: 'Untrusted data is concatenated into a SQL statement',
    full:
      'A database node takes its statement as text and builds it by interpolation from ' +
      'untrusted data. The value becomes part of the statement rather than a parameter to ' +
      'it, so it can end the intended query and start another one.',
  },
  EXPRESSION_RCE: {
    name: 'ExpressionRce',
    short: 'Untrusted data reaches something that executes it',
    full:
      'Either a shell command is built by interpolation from untrusted data, or a Code node ' +
      'that evaluates strings receives it. The first is concatenation into a command line; ' +
      'the second depends on the code and is reported as a place to look.',
  },
  SECRET_EXFIL_RISK: {
    name: 'SecretExfilRisk',
    short: 'A credential is sent in a request an attacker has a hand in',
    full:
      'A node writes a value read from the environment or the variable store into a request, ' +
      'and either the destination is built from untrusted data or untrusted data reaches the ' +
      'same node.',
  },
  MISSING_HUMAN_APPROVAL: {
    name: 'MissingHumanApproval',
    short: 'An agent can take an irreversible action unattended',
    full:
      'A node that decides which tools to call can reach an action that cannot be undone, ' +
      'with no approval step between them. Nothing untrusted reaches this agent, so this is ' +
      'not an injection \u2014 it is an agent whose worst wrong answer is permanent.',
  },
  OVERBROAD_TOOL_ACCESS: {
    name: 'OverbroadToolAccess',
    short: 'An agent holds tools that destroy, spend or run commands, with no approval step',
    full:
      'An agent\u2019s tool list is its permission set: everything in it is available on ' +
      'every completion, including the wrong one.',
  },
};

export function renderSarif(report: ScanReport, indent = 2): string {
  // Только правила, которые действительно сработали, чтобы драйвер не рекламировал покрытие,
  // которого прогон не задействовал. Порядок фиксирован ради устойчивой разницы между
  // прогонами.
  const fired = [...new Set(report.files.flatMap((f) => f.findings.map((x) => x.rule)))].sort();
  const ruleIndex = new Map(fired.map((rule, i) => [rule, i]));

  const results = report.files.flatMap((file) =>
    file.findings.map((finding) => result(finding, file, ruleIndex.get(finding.rule) ?? 0)),
  );

  return JSON.stringify(
    {
      $schema: SARIF_SCHEMA,
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: report.tool.name,
              version: report.tool.version,
              informationUri: report.tool.informationUri,
              rules: fired.map((rule) => descriptor(rule)),
            },
          },
          results,
        },
      ],
    },
    null,
    indent,
  );
}

function descriptor(rule: RuleId): Record<string, unknown> {
  const doc = RULE_DOCS[rule];
  return {
    id: rule,
    name: doc.name,
    shortDescription: { text: doc.short },
    fullDescription: { text: doc.full },
    help: {
      text: doc.full,
      markdown: `**${doc.short}**\n\n${doc.full}\n\nSee \`docs/scoring.md\` for how severity is decided.`,
    },
    // Дефолт самого правила. Каждый результат несёт ту полосу, которую заработал его путь.
    defaultConfiguration: { level: 'warning' },
    properties: { tags: ['security', 'n8n'] },
  };
}

function result(finding: Finding, file: ScannedFile, ruleIndex: number): Record<string, unknown> {
  const codeFlow = flow(finding, file);

  return {
    ruleId: finding.rule,
    ruleIndex,
    level: LEVEL[finding.severity],
    message: { text: `${finding.title}. ${finding.detail} ${finding.remediation}` },
    locations: [location(file, finding.sink.node)],
    partialFingerprints: {
      // Устойчив между прогонами и при перестановках, чтобы GitHub отличал переехавшую
      // находку от новой. Severity сознательно не входит: путь, потерявший полосу из-за
      // добавленного фильтра, — та же самая находка, просто лучше защищённая.
      n8nSentinelPath: fingerprint(
        `${finding.rule}\u0000${file.path}\u0000${finding.source.node}\u0000${finding.sink.node}`,
      ),
    },
    ...(codeFlow ? { codeFlows: [codeFlow] } : {}),
    properties: {
      'security-severity': SECURITY_SEVERITY[finding.severity],
      severity: finding.severity,
      confidence: finding.confidence,
      tags: ['security', 'n8n'],
      ...(finding.agent !== undefined ? { agent: finding.agent } : {}),
      ...(finding.weakGates.length > 0 ? { weakGates: finding.weakGates } : {}),
    },
  };
}

/** Путь taint в виде структуры, которую SARIF для этого и предусмотрел. */
function flow(finding: Finding, file: ScannedFile): Record<string, unknown> | undefined {
  if (finding.trace.length === 0) return undefined;

  const nodes = [finding.trace[0]?.from ?? finding.source.node, ...finding.trace.map((s) => s.to)];
  return {
    threadFlows: [
      {
        locations: nodes.map((node, i) => ({
          location: {
            ...location(file, node),
            message: {
              text:
                i === 0
                  ? `${node} — untrusted input enters here`
                  : finding.trace[i - 1]?.derived === true
                    ? `${node} — reached through the agent → tool step n8n stores in reverse`
                    : node,
            },
          },
        })),
      },
    ],
  };
}

function location(file: ScannedFile, node: string): Record<string, unknown> {
  const region: SourceRegion | undefined =
    file.text !== undefined ? locateNode(file.text, node) : undefined;

  return {
    physicalLocation: {
      artifactLocation: { uri: file.path.split('\\').join('/') },
      ...(region
        ? {
            region: {
              startLine: region.line,
              startColumn: region.column,
              endColumn: region.column + region.length,
            },
          }
        : {}),
    },
  };
}

/**
 * FNV-1a, написанный руками.
 *
 * `node:crypto` подошёл бы — и заодно означал бы, что этот модуль нельзя вшить в браузерный
 * визуализатор фазы 7. Отпечатку нужно быть устойчивым, а не неподделываемым.
 */
function fingerprint(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}
