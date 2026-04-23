/**
 * Module-scoped drag signal. Used to suspend heavy per-frame canvas work
 * (e.g. the reactive dot grid) while a node drag is in progress, without
 * incurring React state churn on every pointer move.
 */
type Listener = (dragging: boolean) => void;

const listeners = new Set<Listener>();
let currentlyDragging = false;

export function setCanvasDragging(dragging: boolean): void {
  if (dragging === currentlyDragging) return;
  currentlyDragging = dragging;
  listeners.forEach((l) => l(dragging));
}

export function subscribeCanvasDragging(listener: Listener): () => void {
  listeners.add(listener);
  listener(currentlyDragging);
  return () => {
    listeners.delete(listener);
  };
}

export function isCanvasDragging(): boolean {
  return currentlyDragging;
}
