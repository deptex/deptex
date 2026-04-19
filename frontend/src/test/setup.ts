import '@testing-library/jest-dom';

// jsdom does not provide IntersectionObserver (used by components that rely on infinite scroll or viewport detection).
class MockIntersectionObserver implements IntersectionObserver {
  readonly root: Element | null = null;
  readonly rootMargin: string = '';
  readonly thresholds: readonly number[] = [];
  observe = () => {};
  unobserve = () => {};
  disconnect = () => {};
  takeRecords = (): IntersectionObserverEntry[] => [];
}
globalThis.IntersectionObserver = MockIntersectionObserver as any;

// jsdom does not provide ResizeObserver (e.g. used by ReactFlow in DependencySupplyChainPage)
const MockResizeObserver = class {
  observe = () => {};
  unobserve = () => {};
  disconnect = () => {};
};
(globalThis as any).ResizeObserver = MockResizeObserver;

// Cleanup localStorage after each test
afterEach(() => {
  localStorage.clear();
});
