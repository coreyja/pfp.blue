import { test as base } from '@playwright/test';
import { Page } from '@playwright/test';

// Custom test fixture type
type AuthFixture = {
  mockAuthenticatedUser: (page: Page) => Promise<void>;
};

// Extend the basic test with our custom fixture
export const test = base.extend<AuthFixture>({
  mockAuthenticatedUser: async ({ context }, use) => {
    const mockAuth = async (page: Page) => {
      // Check if we're using fixtures or not
      const usingFixtures = process.env.USE_FIXTURES === '1';
      
      if (usingFixtures) {
        // Mock authentication using our fixture servers
        console.log('Setting up mock authentication with fixture servers');
        
        // Step 1: Visit the login page
        await page.goto('/login');
        
        // Step 2: Enter the test handle that our fixtures will recognize
        await page.locator('input[name="did"]').fill('fixture-user.test');
        
        // Step 3: Submit the form to start the OAuth flow
        await page.locator('button:has-text("Connect with Bluesky")').click();
        
        // Step 4: Wait for the redirect to complete - this should use our fixture servers
        await page.waitForURL(/\/oauth\/bsky\/callback/);
        
        // Step 5: Wait for the auth to complete and redirect to profile page
        await page.waitForURL('/me');
        
        // Verify we're logged in by checking for profile elements
        const heading = page.locator('h1:has-text("Your Profile"), h2:has-text("Your Profile")');
        await heading.waitFor({ timeout: 5000 });
      } else {
        // For non-fixture testing, create a warning that auth won't work
        console.warn('Using real server but auth mocking not implemented outside of fixtures');
        await page.goto('/login');
      }
    };
    
    // Provide the fixture implementation to the test
    await use(mockAuth);
  },
});

// Re-export expect
export { expect } from '@playwright/test';