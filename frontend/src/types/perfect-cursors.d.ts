declare module 'perfect-cursors' {
  export class PerfectCursor {
    constructor(cb: (point: number[]) => void);
    addPoint(point: number[]): void;
    dispose(): void;
    static MAX_INTERVAL: number;
  }
}
