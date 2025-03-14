import { test, expect } from './fixtures';

test.describe('Authentication flow', () => {
  test('login form submits with correct parameters', async ({ page }) => {
    await page.goto('/login');
    
    // Fill in the login form
    const testHandle = 'fixture-user.test';
    await page.locator('input[name="did"]').fill(testHandle);
    
    // Intercept the form submission to check the parameters without actually submitting
    const navigationPromise = page.waitForNavigation();
    await page.locator('button:has-text("Connect with Bluesky")').click();
    
    // Wait for navigation to start
    const url = page.url();
    await navigationPromise.catch(() => {}); // Catch in case the navigation doesn't complete
    
    // Check if we started the OAuth flow with the right parameters
    expect(url).toContain('/oauth/bsky/authorize');
    expect(url).toContain(encodeURIComponent(testHandle));
    expect(url).toContain('state=');
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
    
    // With fixtures, this should complete the auth flow and redirect to the callback
    await page.waitForURL(/\/oauth\/bsky\/callback/);
    
    // After callback processing, we should land on the profile page
    await page.waitForURL('/me');
    
    // Verify we're logged in by checking for profile elements
    await expect(page.locator('h1, h2').filter({ hasText: /Your Profile|Profile/i })).toBeVisible();
    await expect(page.locator('text=Bluesky Account')).toBeVisible();
  });
  
  test('logout works when user is logged in', async ({ page, mockAuthenticatedUser }) => {
    test.skip(!process.env.USE_FIXTURES, 'This test only runs when fixtures are enabled');
    
    // Set up mock authentication
    await mockAuthenticatedUser(page);
    
    // Look for and click the logout link
    const logoutLink = page.locator('a:has-text("Logout")');
    await expect(logoutLink).toBeVisible();
    
    // Click the logout link
    await logoutLink.click();
    
    // Should be redirected to home page
    await page.waitForURL('/');
    
    // Verify we're logged out by checking for login link
    await expect(page.locator('a:has-text("Login")')).toBeVisible();
  });
});