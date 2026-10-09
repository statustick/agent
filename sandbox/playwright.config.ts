// CommonJS like the rest of the sandbox folder; Playwright compiles it.
import type * as PlaywrightTest from '@playwright/test';

const { defineConfig }: typeof PlaywrightTest = require('@playwright/test');

const work = process.env.ST_WORK_DIR || '/runner/work';

// Ends the run cleanly before the launcher's 2 minute hard stop.
module.exports = defineConfig({
  testDir: work,
  testMatch: /check\.spec\.(ts|js)$/,
  outputDir: `${work}/out`,
  globalTimeout: 110_000,
  timeout: 60_000,
  retries: 0,
  workers: 1,
  reporter: [['json', { outputFile: `${work}/report.json` }]],
  use: {
    actionTimeout: 15_000,
    browserName: 'chromium',
    headless: true,
    screenshot: 'on',
    trace: 'on',
    proxy: process.env.ST_PROXY ? { server: process.env.ST_PROXY } : undefined
  }
});
