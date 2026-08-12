import type { Finding, Severity, TraceStep } from '../checkers/types.js';
import { summarise } from './types.js';
import type { ScanReport, ScannedFile } from './types.js';

export interface HumanOptions {
  /** Цвет ANSI. Решает вызывающий: core не смотрит, терминал ли на том конце. */
  readonly colour?: boolean;
  /** Печатать файлы, о которых нечего сказать. По умолчанию нет: чистый скан должен молчать. */
  readonly showClean?: boolean;
}

/**
 * Отчёт, который читает человек.
 *
 * Построен вокруг трассы. Находка, говорящая «в этом воркфлоу есть prompt injection», — это
 * приговор; находка, показывающая `Gmail Trigger → Classify → Agent ⇢ Send Email`, — это то,
 * что читатель может сверить с холстом перед собой и с чем может не согласиться. Всё
 * остальное на странице — severity, объяснение, починка — расставлено вокруг этого пути.
 */
export function renderHuman(report: ScanReport, options: HumanOptions = {}): string {
  const c = palette(options.colour === true);
  const out: string[] = [];

  for (const file of report.files) {
    if (file.findings.length === 0 && file.warnings.length === 0) {
      if (options.showClean === true) out.push(`${c.dim('✓')} ${file.path}`);
      continue;
    }
    out.push(renderFile(file, c));
  }

  out.push(renderSummary(report, c));
  return out.join('\n');
}

function renderFile(file: ScannedFile, c: Palette): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(c.bold(file.path));
  if (file.workflow !== '') lines.push(`  ${c.dim(file.workflow)}`);

  for (const warning of file.warnings) {
    lines.push(`  ${c.dim(`! ${warning.code}: ${warning.message}`)}`);
  }

  for (const finding of file.findings) {
    lines.push('');
    lines.push(renderFinding(finding, c));
  }
  return lines.join('\n');
}

function renderFinding(finding: Finding, c: Palette): string {
  const lines: string[] = [];
  const badge = c.severity(finding.severity);
  const uncertain = finding.confidence === 'uncertain' ? ` ${c.dim('(не прослежено)')}` : '';

  lines.push(`  ${badge} ${c.bold(finding.rule)}${uncertain}`);
  lines.push(`  ${finding.title}`);
  lines.push('');
  lines.push(...renderTrace(finding, c));
  lines.push('');
  lines.push(...wrap(finding.detail, '    ', c.dim('почему  ')));
  lines.push(...wrap(finding.remediation, '    ', c.dim('чинить  ')));

  for (const note of finding.notes) lines.push(...wrap(note, '    ', c.dim('заметка ')));
  if (finding.otherSources.length > 0) {
    lines.push(
      ...wrap(
        `до той же ноды доходят ещё ${finding.otherSources.length}: ${finding.otherSources.join(', ')}`,
        '    ',
        c.dim('ещё     '),
      ),
    );
  }
  return lines.join('\n');
}

/**
 * Путь, по ноде на строку.
 *
 * `⇢` помечает шаг, который n8n хранит в обратную сторону, — ребро агент → инструмент,
 * которого нет ни на одном холсте. Читателю, сверяющему это с редактором, надо об этом
 * сказать, иначе трасса выглядит неправильной.
 */
function renderTrace(finding: Finding, c: Palette): string[] {
  const gates = new Set(finding.weakGates);
  const annotate = (node: string): string => (gates.has(node) ? ` ${c.dim('— слабый гейт')}` : '');

  if (finding.trace.length === 0) {
    return [`    ${c.node(finding.sink.node)}`];
  }

  const first = finding.trace[0] as TraceStep;
  const lines = [`    ${c.node(first.from)}${annotate(first.from)}`];
  for (const step of finding.trace) {
    const arrow = step.derived ? c.dim('⇢') : c.dim('→');
    const tail = step.derived ? ` ${c.dim('(агент → инструмент, выведено)')}` : '';
    lines.push(`      ${arrow} ${c.node(step.to)}${annotate(step.to)}${tail}`);
  }
  return lines;
}

function renderSummary(report: ScanReport, c: Palette): string {
  const s = summarise(report);
  const lines = ['', c.dim('─'.repeat(60))];

  if (s.findings === 0) {
    lines.push(
      `Просканировано воркфлоу: ${s.files}. Ничего не найдено.`,
      c.dim('Это не справка о здоровье — что именно не проверяется, написано в docs/scoring.md.'),
    );
    return lines.join('\n');
  }

  // Отступы, которыми выравниваются findings, в однострочном итоге читались бы как дыры.
  const bands = (['critical', 'high', 'medium', 'low'] as const)
    .filter((band) => s.bySeverity[band] > 0)
    .map((band) => `${band} ${s.bySeverity[band]}`)
    .join('   ');

  lines.push(
    `Найдено: ${s.findings} в ${s.filesWithFindings} воркфлоу из ${s.files}`,
    bands,
    '',
    ...s.byRule.map(({ rule, count }) => `  ${String(count).padStart(4)}  ${c.dim(rule)}`),
  );
  return lines.join('\n');
}

/** Переносит по 96 колонкам с висячим отступом, чтобы длинное объяснение оставалось читаемым. */
function wrap(text: string, indent: string, label: string): string[] {
  const width = 96 - indent.length;
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (current === '') current = word;
    else if (current.length + 1 + word.length <= width) current += ` ${word}`;
    else {
      lines.push(current);
      current = word;
    }
  }
  if (current !== '') lines.push(current);

  return lines.map((line, i) => (i === 0 ? `${indent}${label}${line}` : `${indent}     ${line}`));
}

interface Palette {
  bold(s: string): string;
  dim(s: string): string;
  node(s: string): string;
  severity(s: Severity): string;
}

const SEVERITY_COLOUR: Record<Severity, string> = {
  critical: '[41;97m',
  high: '[31;1m',
  medium: '[33m',
  low: '[34m',
};

function palette(colour: boolean): Palette {
  if (!colour) {
    return {
      bold: (s) => s,
      dim: (s) => s,
      node: (s) => `"${s}"`,
      severity: (s) => s.padEnd(8),
    };
  }
  const reset = '[0m';
  return {
    bold: (s) => `[1m${s}${reset}`,
    dim: (s) => `[2m${s}${reset}`,
    node: (s) => `[36m${s}${reset}`,
    severity: (s) => `${SEVERITY_COLOUR[s]} ${s} ${reset}`.padEnd(8),
  };
}
