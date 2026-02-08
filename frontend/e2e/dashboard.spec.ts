import { test, expect } from '@playwright/test';
import { nav, toast } from './helpers/selectors';

test.describe('Dashboard', () => {
  test('loads and displays dashboard content', async ({ page }) => {
    await page.goto('/');
    await expect(nav.dashboard(page)).toBeVisible({ timeout: 15000 });

    // All navigation links should be present
    await expect(nav.containers(page)).toBeVisible();
    await expect(nav.secrets(page)).toBeVisible();
    await expect(nav.compliance(page)).toBeVisible();
    await expect(nav.activity(page)).toBeVisible();
    await expect(nav.settings(page)).toBeVisible();
  });

  test('discover containers button triggers discovery', async ({ page }) => {
    await page.goto('/');
    await expect(nav.dashboard(page)).toBeVisible({ timeout: 15000 });

    const discoverButton = page.getByRole('button', { name: /discover/i });
    if (await discoverButton.isVisible({ timeout: 5000 }).catch(() => false)) {
      await discoverButton.click();
      // Should show a toast notification
      await expect(toast.any(page)).toBeVisible({ timeout: 15000 });
    }
  });

  test('displays summary cards', async ({ page }) => {
    await page.goto('/');
    await expect(nav.dashboard(page)).toBeVisible({ timeout: 15000 });

    // Dashboard should show summary stat labels
    await expect(
      page.getByText(/vulnerabilities|containers|secrets/i).first()
    ).toBeVisible({ timeout: 10000 });
  });
});
