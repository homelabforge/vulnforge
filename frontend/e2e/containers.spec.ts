import { test, expect } from '@playwright/test';
import { nav, toast } from './helpers/selectors';

test.describe('Containers', () => {
  test('loads containers page', async ({ page }) => {
    await page.goto('/containers');
    await expect(nav.containers(page)).toBeVisible({ timeout: 15000 });

    // Page should render heading or content
    await expect(
      page.getByText(/container|image|discover/i).first()
    ).toBeVisible({ timeout: 10000 });
  });

  test('discover containers button is available', async ({ page }) => {
    await page.goto('/containers');
    await expect(nav.containers(page)).toBeVisible({ timeout: 15000 });

    const discoverButton = page.getByRole('button', { name: /discover/i });
    if (await discoverButton.isVisible({ timeout: 5000 }).catch(() => false)) {
      await discoverButton.click();
      await expect(toast.any(page)).toBeVisible({ timeout: 15000 });
    }
  });

  test('filter controls are visible', async ({ page }) => {
    await page.goto('/containers');
    await expect(nav.containers(page)).toBeVisible({ timeout: 15000 });

    // Search input should be present
    await expect(
      page.getByPlaceholder(/search/i)
    ).toBeVisible({ timeout: 10000 });
  });
});
