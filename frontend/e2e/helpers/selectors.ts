import type { Page } from '@playwright/test';

/** Navigation links in the top nav bar */
export const nav = {
  dashboard: (page: Page) => page.getByRole('link', { name: 'Dashboard' }),
  containers: (page: Page) => page.getByRole('link', { name: 'Containers' }),
  secrets: (page: Page) => page.getByRole('link', { name: 'Secrets' }),
  compliance: (page: Page) => page.getByRole('link', { name: 'Compliance' }),
  activity: (page: Page) => page.getByRole('link', { name: 'Activity' }),
  settings: (page: Page) => page.getByRole('link', { name: 'Settings' }),
};

/** Sonner toast selectors */
export const toast = {
  any: (page: Page) => page.locator('[data-sonner-toast]'),
  error: (page: Page) => page.locator('[data-sonner-toast][data-type="error"]'),
  success: (page: Page) => page.locator('[data-sonner-toast][data-type="success"]'),
};

/** Admin credentials used in global.setup.ts */
export const ADMIN = {
  username: 'e2e-admin',
  password: 'E2eTest!ng123',
};
