import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { webcrypto } from 'node:crypto';

// Polyfill SubtleCrypto in jsdom / Node environment
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: true,
    configurable: true,
  });
}
if (typeof window !== 'undefined' && !window.crypto?.subtle) {
  Object.defineProperty(window, 'crypto', {
    value: webcrypto,
    writable: true,
    configurable: true,
  });
}

afterEach(cleanup);
