import type { Placed } from './layout.js';

/**
 * Кривые между портами — в манере редактора.
 *
 * Поток элементов выходит из правого края и приходит в левый, поэтому воркфлоу читается
 * поперёк страницы; AI-sub-нода висит под тем, что кормит, и подключается вверх. Ошибиться
 * здесь — не косметическая проблема: направление связи `ai_tool` это вообще причина, по
 * которой у проекта есть парсер, и картинка, рисующая его наоборот, учит читателя неверному
 * о его собственном воркфлоу.
 */

export interface Point {
  readonly x: number;
  readonly y: number;
}

export interface Curve {
  /** Путь SVG. */
  readonly d: string;
  /** Точка на середине — под подпись. */
  readonly mid: Point;
  readonly from: Point;
  readonly to: Point;
}

const round = (value: number): string => (Math.round(value * 100) / 100).toString();

const clamp = (value: number, min: number, max: number): number =>
  Math.min(Math.max(value, min), max);

/** Откуда связь `main` выходит из ноды: правый край, по порту на каждый выходной слот. */
export function outPort(node: Placed, slot: number, slots: number): Point {
  const count = Math.max(slots, 1);
  const at = clamp(slot, 0, count - 1);
  return { x: node.x + node.w, y: node.y + (node.h * (at + 1)) / (count + 1) };
}

/** Куда связь `main` приходит: левый край, по порту на каждый вход. */
export function inPort(node: Placed, index: number, inputs: number): Point {
  const count = Math.max(inputs, 1);
  const at = clamp(index, 0, count - 1);
  return { x: node.x, y: node.y + (node.h * (at + 1)) / (count + 1) };
}

/** Точка на нижнем крае ноды, ближайшая к висящей под ней sub-ноде. */
export function bottomPort(node: Placed, towards: Placed): Point {
  const inset = Math.min(16, node.w / 3);
  return {
    x: clamp(towards.x + towards.w / 2, node.x + inset, node.x + node.w - inset),
    y: node.y + node.h,
  };
}

export function topPort(node: Placed): Point {
  return { x: node.x + node.w / 2, y: node.y };
}

function cubic(from: Point, c1: Point, c2: Point, to: Point): Curve {
  return {
    d: `M${round(from.x)} ${round(from.y)}C${round(c1.x)} ${round(c1.y)} ${round(c2.x)} ${round(c2.y)} ${round(to.x)} ${round(to.y)}`,
    mid: {
      x: (from.x + 3 * c1.x + 3 * c2.x + to.x) / 8,
      y: (from.y + 3 * c1.y + 3 * c2.y + to.y) / 8,
    },
    from,
    to,
  };
}

/**
 * Поток элементов. Горизонтальная тяга растёт вместе с зазором, поэтому короткие перебежки
 * остаются собранными, а длинный прыжок через холст изгибается, а не режет диагональю всё,
 * что лежит между.
 */
export function dataCurve(from: Point, to: Point): Curve {
  const dx = to.x - from.x;
  const pull = dx >= 0 ? clamp(dx * 0.5, 32, 220) : clamp(-dx * 0.7 + 64, 96, 320);
  return cubic(from, { x: from.x + pull, y: from.y }, { x: to.x - pull, y: to.y }, to);
}

/** Sub-нода, подключающаяся вверх к ноде, которую она кормит. */
export function attachmentCurve(from: Point, to: Point): Curve {
  const dy = from.y - to.y;
  const pull = clamp(Math.abs(dy) * 0.6, 24, 120);
  return cubic(from, { x: from.x, y: from.y - pull }, { x: to.x, y: to.y + pull }, to);
}

/**
 * Нода, заведённая сама на себя: так делает `splitInBatches`, и на это приходится 30%
 * воркфлоу библиотеки, содержащих цикл. Рисуется поверху, где её нельзя спутать со связью с
 * соседом.
 */
export function selfLoopCurve(node: Placed): Curve {
  const from = { x: node.x + node.w, y: node.y + node.h / 2 };
  const to = { x: node.x, y: node.y + node.h / 2 };
  const lift = node.h * 0.95;
  return cubic(
    from,
    { x: from.x + node.w * 0.7, y: from.y - lift },
    { x: to.x - node.w * 0.7, y: to.y - lift },
    to,
  );
}
