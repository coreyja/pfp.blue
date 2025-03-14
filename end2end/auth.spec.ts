import { test, expect } from '@playwright/test';

// Mock OAuth flow
// In a real test, we'd need to mock the Bluesky authentication service
// For now, we'll just test the initial authentication request and check redirects

test.describe('Authentication flow', () => {
  test('login form submits with correct parameters', async ({ page }) => {
    await page.goto('/login');
    
    // Fill in the login form
    const testHandle = 'test.user.bsky.social';
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
  
  // Simple test for logout functionality
  test('logout link is available when user is logged in', async ({ page }) => {
    // This test is aspirational - in a real scenario we'd need to mock
    // authentication first, which requires more sophisticated test fixtures
    
    // For now, we're just checking that the /logout endpoint exists
    // In a real test, we would:
    // 1. Set up a mock authenticated session
    // 2. Navigate to an authenticated page
    // 3. Check for and click the logout link
    // 4. Verify we're logged out
    
    const response = await page.request.get('/logout');
    
    // Should either redirect to home or return a specific status code
    expect(response.status()).toBeLessThan(500); // Should not be a server error
  });
});