import '@testing-library/jest-dom/vitest';

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (ResizeObserverMock as unknown as typeof ResizeObserver);

if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}

// React Flow measures nodes with DOMMatrix in some code paths.
if (!('DOMMatrixReadOnly' in window)) {
  (window as unknown as Record<string, unknown>).DOMMatrixReadOnly = class {
    m22 = 1;
    constructor() {}
  };
}

// Animations are visual only; skip them so state assertions are immediate.
import { MotionGlobalConfig } from 'framer-motion';
MotionGlobalConfig.skipAnimations = true;
