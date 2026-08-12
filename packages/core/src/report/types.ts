import type { Finding, Severity } from '../checkers/types.js';
import type { ParseWarning } from '../parser/warnings.js';

/** Один документ в том виде, в каком его просканировали. */
export interface ScannedFile {
  /** Путь для печати. Относительно места, откуда запустили скан, а не абсолютный. */
  readonly path: string;
  /** Собственное имя воркфлоу: это не имя файла, и часто оно полезнее. */
  readonly workflow: string;
  readonly findings: readonly Finding[];
  readonly warnings: readonly ParseWarning[];
  /**
   * Текст файла, сохранённый, чтобы находкам можно было проставить номера строк.
   * Отсутствует, когда у вызывающего его нет, — отчёт всё равно отрисуется.
   */
  readonly text?: string | undefined;
}

export interface ToolInfo {
  readonly name: string;
  readonly version: string;
  readonly informationUri: string;
}

export interface ScanReport {
  readonly tool: ToolInfo;
  readonly files: readonly ScannedFile[];
}

export interface Summary {
  readonly files: number;
  readonly filesWithFindings: number;
  readonly findings: number;
  readonly bySeverity: Readonly<Record<Severity, number>>;
  readonly byRule: readonly { readonly rule: string; readonly count: number }[];
  readonly warnings: number;
}

export function summarise(report: ScanReport): Summary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byRule = new Map<string, number>();
  let findings = 0;
  let filesWithFindings = 0;
  let warnings = 0;

  for (const file of report.files) {
    if (file.findings.length > 0) filesWithFindings++;
    warnings += file.warnings.length;
    for (const finding of file.findings) {
      findings++;
      bySeverity[finding.severity]++;
      byRule.set(finding.rule, (byRule.get(finding.rule) ?? 0) + 1);
    }
  }

  return {
    files: report.files.length,
    filesWithFindings,
    findings,
    bySeverity,
    byRule: [...byRule]
      .map(([rule, count]) => ({ rule, count }))
      .sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule)),
    warnings,
  };
}

/** Все находки на уровне `threshold` и выше. Именно их считает `--fail-on`. */
export function atOrAbove(report: ScanReport, threshold: Severity): Finding[] {
  const order: Severity[] = ['low', 'medium', 'high', 'critical'];
  const floor = order.indexOf(threshold);
  return report.files.flatMap((f) =>
    f.findings.filter((finding) => order.indexOf(finding.severity) >= floor),
  );
}
