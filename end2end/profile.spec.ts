import { test, expect } from './fixtures';

// These tests would require actual authentication or mocking
// Mark them as "todo" to indicate what we plan to test eventually
test.describe('Profile page', () => {
  // Test for authenticated profile page access
  test.skip('shows user profile when authenticated', async ({ page, mockAuthenticatedUser }) => {
    // This is a sketch of the test - it will need to be implemented
    // once the auth fixture is complete
    
    // Mock authentication
    await mockAuthenticatedUser(page);
    
    // Go to profile page
    await page.goto('/me');
    
    // Check for profile elements
    await expect(page.locator('h1:has-text("Your Profile")')).toBeVisible();
    
    // Should see the user's Bluesky account info
    await expect(page.locator('text=Bluesky Account')).toBeVisible();
  });
  
  // Test for profile picture progress toggle
  test.skip('can toggle profile picture progress', async ({ page, mockAuthenticatedUser }) => {
    // Mock authentication
    await mockAuthenticatedUser(page);
    
    // Go to profile page
    await page.goto('/me');
    
    // Find the toggle button/checkbox for profile picture progress
    const toggleCheckbox = page.locator('input[name="enabled"]').first();
    
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
  
  // Test for multiple accounts
  test.skip('shows all linked accounts when multiple accounts are connected', async ({ page, mockAuthenticatedUser }) => {
    // This test would require a more complex fixture setup to create multiple tokens
    // for one user, but here's the skeleton
    
    await mockAuthenticatedUser(page);
    await page.goto('/me');
    
    // Check for multiple account sections
    // This will depend on the actual UI, but could be something like:
    const accountSections = page.locator('.account-section');
    
    // In a real test with multiple accounts, we'd expect more than one
    await expect(accountSections).toHaveCount(1); // Would be changed to >1 when implemented
  });
});

// Sketching out future tests that would be valuable
test.describe('Profile Picture Progress Feature', () => {
  test.skip('can set original profile picture', async ({ page, mockAuthenticatedUser }) => {
    await mockAuthenticatedUser(page);
    await page.goto('/me');
    
    // Find the form or button to set original profile picture
    // Fill in the blob CID
    // Submit and verify
  });
  
  test.skip('shows current progress percentage', async ({ page, mockAuthenticatedUser }) => {
    await mockAuthenticatedUser(page);
    await page.goto('/me');
    
    // Check if progress indicator is visible
    // Verify the percentage shown matches what's expected
  });
});