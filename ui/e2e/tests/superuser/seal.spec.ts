/**
 * Copyright IBM Corp. 2016, 2025
 * SPDX-License-Identifier: BUSL-1.1
 */

import { test, expect } from '@playwright/test';

test('sealing workflow', async ({ page }) => {
  await page.goto('dashboard');
  await page.getByRole('link', { name: 'Resilience and recovery' }).click();
  await page.getByRole('link', { name: 'Seal Vault' }).click();
  await page.getByRole('button', { name: 'Seal' }).click();
  await page.getByRole('button', { name: 'Confirm' }).click();
  await expect(page.getByText('Vault is sealed')).toBeVisible();
});
