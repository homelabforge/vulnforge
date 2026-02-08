import { test, expect } from '@playwright/test';
import { toast } from './helpers/selectors';

test.describe('Settings', () => {
  test('loads settings page with all tabs', async ({ page }) => {
    await page.goto('/settings');

    // All 5 settings tabs should be visible
    await expect(page.getByRole('button', { name: /System/i })).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole('button', { name: /Scanning/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Notifications/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Security/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Data/i })).toBeVisible();
  });

  test('can switch between settings tabs', async ({ page }) => {
    await page.goto('/settings');
    await expect(page.getByRole('button', { name: /System/i })).toBeVisible({ timeout: 15000 });

    // Click Notifications tab
    await page.getByRole('button', { name: /Notifications/i }).click();
    await expect(
      page.getByText(/ntfy|discord|slack|telegram|email|notification/i).first()
    ).toBeVisible({ timeout: 5000 });

    // Click Scanning tab
    await page.getByRole('button', { name: /Scanning/i }).click();
    await expect(
      page.getByText(/schedule|timeout|secrets|scan/i).first()
    ).toBeVisible({ timeout: 5000 });

    // Should not show error toast during tab switches
    await expect(toast.error(page)).not.toBeVisible({ timeout: 1000 });
  });
});
