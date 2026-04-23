// Vendored from perfect-cursors@1.0.5 (MIT) by @steveruizok
// Removed to avoid Vercel npm cache resolution issues.

function dist(A: number[], B: number[]) {
  return Math.hypot(A[1] - B[1], A[0] - B[0]);
}

function lrp(A: number[], B: number[], t: number): number[] {
  return [A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t];
}
lrp; // suppress unused warning — kept for completeness

class Spline {
  points: number[][] = [];
  lengths: number[] = [];
  totalLength = 0;
  private prev?: number[];

  addPoint = (point: number[]) => {
    if (this.prev) {
      const length = dist(this.prev, point);
      this.lengths.push(length);
      this.totalLength += length;
      this.points.push(point);
    }
    this.prev = point;
  };

  clear = () => {
    this.points = this.prev ? [this.prev] : [];
    this.totalLength = 0;
  };

  getSplinePoint = (rt: number): number[] => {
    const { points } = this;
    const l = points.length - 1;
    const d = Math.trunc(rt);
    const p1 = Math.min(d + 1, l);
    const p2 = Math.min(p1 + 1, l);
    const p3 = Math.min(p2 + 1, l);
    const p0 = p1 - 1;
    const t = rt - d;
    const tt = t * t, ttt = tt * t;
    const q1 = -ttt + 2 * tt - t;
    const q2 = 3 * ttt - 5 * tt + 2;
    const q3 = -3 * ttt + 4 * tt + t;
    const q4 = ttt - tt;
    return [
      (points[p0][0] * q1 + points[p1][0] * q2 + points[p2][0] * q3 + points[p3][0] * q4) / 2,
      (points[p0][1] * q1 + points[p1][1] * q2 + points[p2][1] * q3 + points[p3][1] * q4) / 2,
    ];
  };
}

type AnimationState = 'stopped' | 'idle' | 'animating';
type Animation = { from: number[]; to: number[]; start: number; duration: number };

export class PerfectCursor {
  static MAX_INTERVAL = 300;

  private state: AnimationState = 'idle';
  private queue: Animation[] = [];
  private timestamp = performance.now();
  private lastRequestId = 0;
  private timeoutId: ReturnType<typeof setTimeout> | number = 0;
  private prevPoint?: number[];
  private spline = new Spline();
  private cb: (point: number[]) => void;

  constructor(cb: (point: number[]) => void) {
    this.cb = cb;
  }

  addPoint = (point: number[]) => {
    clearTimeout(this.timeoutId as number);
    const now = performance.now();
    const duration = Math.min(now - this.timestamp, PerfectCursor.MAX_INTERVAL);

    if (!this.prevPoint) {
      this.spline.clear();
      this.prevPoint = point;
      this.spline.addPoint(point);
      this.cb(point);
      this.state = 'stopped';
      return;
    }

    if (this.state === 'stopped') {
      if (dist(this.prevPoint, point) < 4) { this.cb(point); return; }
      this.spline.clear();
      this.spline.addPoint(this.prevPoint);
      this.spline.addPoint(this.prevPoint);
      this.spline.addPoint(point);
      this.state = 'idle';
    } else {
      this.spline.addPoint(point);
    }

    if (duration < 16) {
      this.prevPoint = point;
      this.timestamp = now;
      this.cb(point);
      return;
    }

    const animation: Animation = {
      start: this.spline.points.length - 3,
      from: this.prevPoint,
      to: point,
      duration,
    };
    this.prevPoint = point;
    this.timestamp = now;

    if (this.state === 'idle') {
      this.state = 'animating';
      this.animateNext(animation);
    } else if (this.state === 'animating') {
      this.queue.push(animation);
    }
  };

  private animateNext = (animation: Animation) => {
    const start = performance.now();
    const loop = () => {
      const t = (performance.now() - start) / animation.duration;
      if (t <= 1 && this.spline.points.length > 0) {
        try { this.cb(this.spline.getSplinePoint(t + animation.start)); } catch { /* ignore */ }
        this.lastRequestId = requestAnimationFrame(loop);
        return;
      }
      const next = this.queue.shift();
      if (next) {
        this.state = 'animating';
        this.animateNext(next);
      } else {
        this.state = 'idle';
        this.timeoutId = setTimeout(() => { this.state = 'stopped'; }, PerfectCursor.MAX_INTERVAL);
      }
    };
    loop();
  };

  dispose = () => {
    cancelAnimationFrame(this.lastRequestId);
    clearTimeout(this.timeoutId as number);
  };
}
