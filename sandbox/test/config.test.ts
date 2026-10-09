import { test } from 'node:test';
import assert from 'node:assert';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);

test('should time an action out before the test does, so a missing locator keeps its error', () => {
  const config = require(path.join(import.meta.dirname, '..', 'playwright.config.ts'));
  assert.ok(config.use.actionTimeout > 0);
  assert.ok(config.use.actionTimeout < config.timeout);
});
