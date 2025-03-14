import { test, expect } from './fixtures';

test.describe('Profile page', () => {
  // Test for authenticated profile page access
  test('shows user profile when authenticated', async ({ page, mockAuthenticatedUser }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    // Mock authentication
    await mockAuthenticatedUser(page);
    
    // Profile page should already be loaded after authentication,
    // but let's explicitly navigate to it to be sure
    await page.goto('/me');
    
    // Check for profile elements
    await expect(page.locator('h1, h2').filter({ hasText: /Your Profile|Profile/i })).toBeVisible();
    
    // Should see the user's Bluesky account info
    await expect(page.locator('text=Bluesky Account')).toBeVisible();
    
    // Should see the fixture user's handle
    await expect(page.locator('text=fixture-user.test')).toBeVisible();
  });
  
  // Test for profile picture progress toggle
  test('can toggle profile picture progress', async ({ page, mockAuthenticatedUser }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    // Mock authentication
    await mockAuthenticatedUser(page);
    
    // Go to profile page
    await page.goto('/me');
    
    // Find the toggle button/checkbox for profile picture progress
    const toggleCheckbox = page.locator('input[name="enabled"]').first();
    await expect(toggleCheckbox).toBeVisible();
    
    // Check initial state
    const initialState = await toggleCheckbox.isChecked();
    
    // Toggle the state
    await toggleCheckbox.click();
    
    // Submit the form
    await page.locator('button:has-text("Save")').click();
    
    // After redirect back to profile page, check that the toggle state has changed
    await page.waitForURL('/me');
    
    // The checkbox should now be in the opposite state
    const newState = await toggleCheckbox.isChecked();
    expect(newState).not.toBe(initialState);
  });
  
  // We can add back the multiple accounts test later when we have fixture support for it
  test.skip('shows all linked accounts when multiple accounts are connected', async ({ page, mockAuthenticatedUser }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    await mockAuthenticatedUser(page);
    await page.goto('/me');
    
    // Check for account section
    const accountSection = page.locator('text=Bluesky Account');
    await expect(accountSection).toBeVisible();
    
    // In a future enhancement, we could update the fixtures to support multiple accounts
  });
});

test.describe('Profile Picture Progress Feature', () => {
  test('can set original profile picture', async ({ page, mockAuthenticatedUser }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    await mockAuthenticatedUser(page);
    await page.goto('/me');
    
    // Find the profile picture progress section
    await expect(page.locator('text=Profile Picture Progress')).toBeVisible();
    
    // Find original picture input (assuming it's a text field for entering a blob CID)
    // This may need to be adjusted based on the exact UI implementation
    const originalPictureInput = page.locator('input[name="originalPicture"], input[name="originalCid"]');
    
    // If there's any existing value, clear it
    await originalPictureInput.clear();
    
    // Enter the fixture blob CID
    await originalPictureInput.fill('bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u');
    
    // Find and click the save button
    await page.locator('button:has-text("Save"), button:has-text("Update")').click();
    
    // After saving, we should still be on the profile page
    await expect(page).toHaveURL('/me');
    
    // The input should still have our value
    await expect(originalPictureInput).toHaveValue('bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u');
  });
  
  test('shows progress indicator', async ({ page, mockAuthenticatedUser }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    await mockAuthenticatedUser(page);
    await page.goto('/me');
    
    // Enable the profile picture progress feature if not already enabled
    const toggleCheckbox = page.locator('input[name="enabled"]').first();
    if (!(await toggleCheckbox.isChecked())) {
      await toggleCheckbox.click();
      await page.locator('button:has-text("Save")').click();
      await page.waitForURL('/me');
    }
    
    // Check if progress indicator is visible
    // This will depend on the exact UI, but could be a progress bar or text
    const progressElement = page.locator('text=/\\d+%/, text=/\\d+\\/\\d+/');
    await expect(progressElement).toBeVisible();
  });
});