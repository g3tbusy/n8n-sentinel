/**
 * Пакет на Node: переносимый анализ плюс файлы правил, прочитанные с диска.
 *
 * Те, кто не может открывать файлы, — визуализатор — импортируют вместо этого `./browser.js`
 * и передают правила сами.
 */

export * from './browser.js';

export { defaultRegistry, defaultRules } from './rules/default-rules.js';
