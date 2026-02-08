import { test, expect } from '@playwright/test';
import { nav } from './helpers/selectors';

test.describe('Compliance', () => {
  test('loads compliance page', async ({ page }) => {
    await page.goto('/compliance');
    await expect(nav.compliance(page)).toBeVisible({ timeout: 15000 });

    // Page should show compliance-related content
    await expect(
      page.getByText(/compliance|host|image|score|scan/i).first()
    ).toBeVisible({ timeout: 10000 });
  });

  test('compliance tabs are available', async ({ page }) => {
    await page.goto('/compliance');
    await expect(nav.compliance(page)).toBeVisible({ timeout: 15000 });

    // Should have host compliance and image compliance tabs or sections
    await expect(
      page.getByRole('button', { name: /host|docker/i })
        .or(page.getByText(/host compliance|docker bench/i).first())
    ).toBeVisible({ timeout: 10000 });
  });
});
