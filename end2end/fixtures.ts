import { test as base, expect } from '@playwright/test';
import { Page } from '@playwright/test';

// Custom test fixture type
type AuthFixture = {
  mockAuthenticatedUser: (page: Page, isAdmin?: boolean) => Promise<void>;
  mockAuthenticatedAdmin: (page: Page) => Promise<void>;
};

// Extend the basic test with our custom fixture
export const test = base.extend<AuthFixture>({
  mockAuthenticatedUser: async ({ context }, use) => {
    const mockAuth = async (page: Page, isAdmin: boolean = false) => {
      // Check if we're using fixtures or not
      const usingFixtures = process.env.USE_FIXTURES === '1';
      
      if (usingFixtures) {
        // Mock authentication using our fixture servers
        console.log(`Setting up mock authentication with fixture servers (admin: ${isAdmin})`);
        
        // Step 1: Visit the login page
        await page.goto('/login');
        
        // Step 2: Enter the test handle that our fixtures will recognize
        // Use different handles for admin vs regular users
        const handle = isAdmin ? 'fixture-admin.test' : 'fixture-user.test';
        await page.locator('input[name="did"]').fill(handle);
        
        // Step 3: Submit the form to start the OAuth flow
        await page.locator('button:has-text("Connect with Bluesky")').click();
        
        // Skip waiting for intermediate redirects and just wait for the final destination
        // This simplifies testing by only asserting the end result
        await page.waitForURL('/me', { timeout: 20000 });
        
        // Verify we're logged in by checking for profile elements
        await page.waitForSelector('body', {state: 'visible', timeout: 15000});
        const bodyText = await page.locator('body').textContent();
        expect(bodyText).toContain('Profile');
      } else {
        // For non-fixture testing, create a warning that auth won't work
        console.warn(`Using real server but auth mocking not implemented outside of fixtures (admin: ${isAdmin})`);
        await page.goto('/login');
      }
    };
    
    // Provide the fixture implementation to the test
    await use(mockAuth);
  },
  
  // Convenience wrapper to authenticate as admin specifically
  mockAuthenticatedAdmin: async ({ mockAuthenticatedUser }, use) => {
    const mockAdminAuth = async (page: Page) => {
      await mockAuthenticatedUser(page, true);
    };
    
    await use(mockAdminAuth);
  },
});

// Re-export expect
export { expect } from '@playwright/test';