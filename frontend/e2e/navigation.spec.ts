import { test, expect } from '@playwright/test';
import { nav } from './helpers/selectors';

test.describe('Navigation', () => {
  test('can navigate to all main pages via nav bar', async ({ page }) => {
    await page.goto('/');
    await expect(nav.dashboard(page)).toBeVisible({ timeout: 15000 });

    // Containers
    await nav.containers(page).click();
    await expect(page).toHaveURL('/containers');

    // Secrets
    await nav.secrets(page).click();
    await expect(page).toHaveURL('/secrets');

    // Compliance
    await nav.compliance(page).click();
    await expect(page).toHaveURL('/compliance');

    // Activity
    await nav.activity(page).click();
    await expect(page).toHaveURL('/activity');

    // Settings
    await nav.settings(page).click();
    await expect(page).toHaveURL('/settings');

    // Back to Dashboard
    await nav.dashboard(page).click();
    await expect(page).toHaveURL('/');
  });

  test('about page is accessible', async ({ page }) => {
    await page.goto('/about');
    await expect(page.getByText(/VulnForge/i).first()).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(/version/i).first()).toBeVisible({ timeout: 5000 });
  });
});
