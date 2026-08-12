#!/usr/bin/env node
import { main } from './cli.js';

/**
 * Обёртка для bin. Всё, что стоит тестировать, лежит в `cli.ts`, который принимает свои
 * потоки аргументом, а не тянется к `process`, — поэтому тесты гоняют настоящий разбор
 * аргументов и настоящие коды возврата, а не их пересказ.
 */
process.exitCode = main(process.argv.slice(2), {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
  interactive: process.stdout.isTTY === true,
  cwd: process.cwd(),
});

export { main } from './cli.js';
export { scanPaths } from './scan.js';
