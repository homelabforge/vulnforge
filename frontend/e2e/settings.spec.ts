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

  test('notification event toggle responds to visual track click and persists state', async ({ page }) => {
    await page.goto('/settings');
    await page.getByRole('button', { name: /Notifications/i }).click();

    // Security Alerts section is expanded by default — find the KEV Detected row
    const kevRow = page.locator('text=KEV Detected').locator('../..');
    const kevInput = kevRow.locator('[role="switch"]');
    const kevTrack = kevRow.locator('.rounded-full').first(); // visual track div

    // Record initial state
    const wasChecked = await kevInput.isChecked();

    // Click the VISUAL TRACK (not the hidden input via role) — this is what real users do.
    // Before the fix: click lands on the non-interactive styled div, input unchanged.
    // After the fix: overlay input covers the full track area, click hits the real input.
    await kevTrack.click();

    // State must have flipped
    if (wasChecked) {
      await expect(kevInput).not.toBeChecked({ timeout: 2000 });
    } else {
      await expect(kevInput).toBeChecked({ timeout: 2000 });
    }

    // Auto-save fires (800ms debounce + network) — success toast confirms persistence
    await expect(toast.success(page)).toBeVisible({ timeout: 5000 });

    // Reload and verify persistence
    await page.reload();
    await page.getByRole('button', { name: /Notifications/i }).click();
    const reloadedInput = page.locator('text=KEV Detected').locator('../..').locator('[role="switch"]');
    if (wasChecked) {
      await expect(reloadedInput).not.toBeChecked({ timeout: 5000 });
    } else {
      await expect(reloadedInput).toBeChecked({ timeout: 5000 });
    }

    // Restore original state
    await kevTrack.click();
    await expect(toast.success(page)).toBeVisible({ timeout: 5000 });
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
