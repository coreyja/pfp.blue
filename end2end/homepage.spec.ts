import { test, expect } from './fixtures';

test.describe('Homepage', () => {
  test('has correct title and layout', async ({ page }) => {
    await page.goto('/');
    
    // Check page title
    await expect(page).toHaveTitle(/pfp.blue/);
    
    // Check main heading
    const heading = page.locator('h1:has-text("pfp.blue")');
    await expect(heading).toBeVisible();
    
    // Check for features section
    const featuresHeading = page.locator('h2:has-text("Features")');
    await expect(featuresHeading).toBeVisible();
    
    // Check for navigation links
    const profileLink = page.locator('a:has-text("View Your Profile")');
    await expect(profileLink).toBeVisible();
    await expect(profileLink).toHaveAttribute('href', '/me');
    
    const loginLink = page.locator('a:has-text("Login")');
    await expect(loginLink).toBeVisible();
    await expect(loginLink).toHaveAttribute('href', '/login');
  });
  
  test('navigation to login page works', async ({ page }) => {
    await page.goto('/');
    
    // Click the login button
    await page.locator('a:has-text("Login")').click();
    
    // Verify we're on the login page
    await expect(page).toHaveURL(/\/login/);
    
    // Check for login form elements
    const loginHeading = page.locator('h2:has-text("Login with Bluesky")');
    await expect(loginHeading).toBeVisible();
    
    const didInput = page.locator('input[name="did"]');
    await expect(didInput).toBeVisible();
    
    const connectButton = page.locator('button:has-text("Connect with Bluesky")');
    await expect(connectButton).toBeVisible();
  });
  
  test('navigation to profile page redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/');
    
    // Click the profile link
    await page.locator('a:has-text("View Your Profile")').click();
    
    // Since we're not logged in, we should be redirected to login
    // Wait for redirect to complete
    await page.waitForURL(/\/login/);
    
    // Verify we're on the login page
    await expect(page).toHaveURL(/\/login/);
  });
});