// End-to-end tests of the portal (ADR-0020, § 6), against the real binary:
// run by tests/portal/e2e.sh, which starts a core and sets
// OSTENA_E2E_ORIGIN and OSTENA_E2E_USERS. Never part of the offline build.
import { defineConfig, devices } from "@playwright/test";

const origin = process.env.OSTENA_E2E_ORIGIN ?? "https://localhost";
const host = new URL(origin).hostname;

export default defineConfig({
  testDir: "tests",
  forbidOnly: true,
  retries: 0,
  workers: 2,
  reporter: [["list"]],
  timeout: 30_000,
  use: {
    baseURL: origin,
    // The core presents a certificate of the Ostena root, which these
    // browsers do not know; TLS itself (hybrid group) is unchanged.
    ignoreHTTPSErrors: true,
    locale: "fr-FR",
    serviceWorkers: "block",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        // Any name resolution other than the portal's fails as well.
        launchOptions: { args: [`--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE ${host}`] },
      },
    },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
});
