import { summarise } from './types.js';
import type { ScanReport } from './types.js';

/**
 * Машиночитаемый отчёт.
 *
 * Плоский конверт с версией: это будет разбирать что-то дальше по конвейеру, и форма должна
 * уметь меняться, не ломая его молча. Findings выводятся такими, какими вышли из чекеров —
 * схема это тип `Finding`, описанный в `src/checkers/types.ts`, — а текст файла отбрасывается,
 * потому что он был входными данными.
 */
export const JSON_REPORT_VERSION = 1;

export function renderJson(report: ScanReport, indent = 2): string {
  return JSON.stringify(
    {
      version: JSON_REPORT_VERSION,
      tool: report.tool,
      summary: summarise(report),
      files: report.files.map((file) => ({
        path: file.path,
        workflow: file.workflow,
        findings: file.findings,
        warnings: file.warnings,
      })),
    },
    null,
    indent,
  );
}
