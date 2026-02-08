import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  globalTeardown: './e2e/global.teardown.ts',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['github']]
    : [['html', { open: 'on-failure' }]],

  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'setup',
      testMatch: /global\.setup\.ts/,
    },
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        storageState: './e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
  ],

  webServer: [
    {
      command:
        'rm -f /tmp/vulnforge-e2e.db* && cd ../backend && python3 -m granian --interface asgi --host 0.0.0.0 --port 8789 app.main:app',
      port: 8789,
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
      env: {
        DATABASE_URL: 'sqlite+aiosqlite:////tmp/vulnforge-e2e.db',
        LOG_LEVEL: 'WARNING',
        VULNFORGE_TESTING: 'true',
      },
    },
    {
      command: 'VITE_API_URL=http://localhost:8789 bun run dev',
      port: 5173,
      reuseExistingServer: !process.env.CI,
      timeout: 15000,
    },
  ],
});
