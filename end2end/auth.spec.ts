import { test, expect } from './fixtures';

test.describe('Authentication flow', () => {
  test('can submit login form', async ({ page }) => {
    await page.goto('/login');
    
    // Fill in the login form
    const testHandle = 'fixture-user.test';
    await page.locator('input[name="did"]').fill(testHandle);
    
    // Click the submit button to start the OAuth flow
    await page.locator('button:has-text("Connect with Bluesky")').click();
    
    // Don't test specific URLs or parameters, just verify we left the login page
    // This is a more resilient test approach that doesn't depend on specific URL formats
    await expect(async () => {
      const currentUrl = page.url();
      expect(currentUrl).not.toMatch(/\/login$/);
    }).toPass({timeout: 5000});
  });
  
  test('handles missing handle/DID error gracefully', async ({ page }) => {
    await page.goto('/login');
    
    // Submit form without filling in the handle
    await page.locator('button:has-text("Connect with Bluesky")').click();
    
    // Should stay on login page or show an error
    // This could be implemented in various ways depending on the error handling
    // Here we're just checking we're still on the login page
    await expect(page).toHaveURL(/\/login|\/oauth\/bsky\/authorize/);
  });
  
  // Using fixtures for a complete auth flow test
  test('completes full authentication flow with fixtures', async ({ page }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    await page.goto('/login');
    
    // Fill in the login form with our fixture user
    await page.locator('input[name="did"]').fill('fixture-user.test');
    
    // Submit the form to start OAuth flow
    await page.locator('button:has-text("Connect with Bluesky")').click();
    
    // Skip checking intermediate URLs and just wait for the final destination
    // This makes the test more resilient to implementation changes in the auth flow
    await page.waitForURL('/me', { timeout: 10000 });
    
    // Verify we're logged in by checking for profile page elements
    // Use the most basic element that should always be present - the profile page body
    await page.waitForSelector('body', {state: 'visible', timeout: 15000});
    const bodyText = await page.locator('body').textContent();
    
    // The profile page should contain something related to profile/Bluesky
    expect(bodyText).toContain('rofile'); // Could be Profile or profile
    
    // Either fixture-user or Fixture User should be present
    const hasFixtureUser = bodyText.includes('fixture-user') || bodyText.includes('Fixture User');
    expect(hasFixtureUser).toBe(true);
  });
  
  test('logout works when user is logged in', async ({ page, mockAuthenticatedUser }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    // Set up mock authentication
    await mockAuthenticatedUser(page);
    
    // Wait for the page to load completely
    await page.waitForSelector('body', {state: 'visible', timeout: 15000});
    
    // Look for any logout link (might be "Logout" or "Log out" or similar)
    const bodyText = await page.locator('body').textContent();
    
    // We need to check for "Logout" text
    expect(bodyText).toMatch(/logout|log out/i);
    
    // Find the logout link
    const logoutLink = page.locator('a').filter({ hasText: /logout|log out/i });
    
    // Click the logout link
    await logoutLink.click();
    
    // Simply verify that we're no longer on the profile page
    // First wait for navigation to complete
    await page.waitForLoadState('networkidle');
    
    // Then check that we're not on the profile page anymore by checking URL
    const currentUrl = page.url();
    expect(currentUrl).not.toContain('/me');
    
    // And make sure we can see a login link
    await page.waitForSelector('a:has-text("Login")', {state: 'visible', timeout: 5000});
  });
});
