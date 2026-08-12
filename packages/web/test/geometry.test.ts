import { describe, expect, it } from 'vitest';
import type { GraphNode } from '@n8n-sentinel/core/browser';
import {
  attachmentCurve,
  bottomPort,
  dataCurve,
  inPort,
  outPort,
  selfLoopCurve,
  topPort,
} from '../src/geometry.js';
import type { Placed } from '../src/layout.js';

const bare: GraphNode = {
  name: 'n',
  type: 't',
  typeVersion: 1,
  disabled: false,
  parameters: {},
  credentials: {},
  hasPinnedData: false,
  raw: {},
};

const at = (x: number, y: number, w = 96, h = 96): Placed => ({
  node: bare,
  x,
  y,
  w,
  h,
  shape: 'node',
});

describe('порты', () => {
  it('ставят единственную связь посередине того края, который она использует', () => {
    expect(outPort(at(0, 0), 0, 1)).toEqual({ x: 96, y: 48 });
    expect(inPort(at(0, 0), 0, 1)).toEqual({ x: 0, y: 48 });
  });

  it('разносят два выхода ноды if по её правой стороне', () => {
    const first = outPort(at(0, 0), 0, 2);
    const second = outPort(at(0, 0), 1, 2);
    expect(first.x).toBe(96);
    expect(first.y).toBeLessThan(second.y);
    expect(second.y).toBeLessThan(96);
  });

  it('зажимают слот, номер которого документ завысил', () => {
    expect(outPort(at(0, 0), 9, 2)).toEqual(outPort(at(0, 0), 1, 2));
  });

  it('встречают sub-ноду под той, которую она кормит', () => {
    const parent = at(0, 0);
    const child = at(200, 200, 72, 72);
    expect(bottomPort(parent, child).y).toBe(96);
    // Прижато к низу родителя, а не указывает в пустоту.
    expect(bottomPort(parent, child).x).toBeLessThanOrEqual(96);
    expect(topPort(child)).toEqual({ x: 236, y: 200 });
  });
});

describe('кривые', () => {
  it('начинаются и заканчиваются на тех портах, которые им дали', () => {
    const curve = dataCurve({ x: 96, y: 48 }, { x: 320, y: 48 });
    expect(curve.d.startsWith('M96 48C')).toBe(true);
    expect(curve.d.endsWith('320 48')).toBe(true);
    expect(curve.mid).toEqual({ x: 208, y: 48 });
  });

  it('изгибают обратные связи сильнее, чем прямые', () => {
    const forward = dataCurve({ x: 0, y: 0 }, { x: 200, y: 0 });
    const backward = dataCurve({ x: 200, y: 0 }, { x: 0, y: 0 });
    // Те же две ноды, обратное направление: обратному участку нужно больше места.
    expect(width(backward.d)).toBeGreaterThan(width(forward.d));
  });

  it('ведут attachment вертикально', () => {
    const curve = attachmentCurve({ x: 100, y: 300 }, { x: 100, y: 100 });
    expect(curve.mid.x).toBe(100);
    expect(curve.mid.y).toBeGreaterThan(100);
    expect(curve.mid.y).toBeLessThan(300);
  });

  it('уводят петлю на себя поверх ноды', () => {
    const curve = selfLoopCurve(at(0, 0));
    expect(curve.from).toEqual({ x: 96, y: 48 });
    expect(curve.to).toEqual({ x: 0, y: 48 });
    expect(curve.mid.y).toBeLessThan(0);
  });
});

/** Насколько далеко за прямую уходят контрольные точки. */
function width(d: string): number {
  const numbers = d.match(/-?\d+(?:\.\d+)?/g)?.map(Number) ?? [];
  return Math.max(...numbers) - Math.min(...numbers);
}
