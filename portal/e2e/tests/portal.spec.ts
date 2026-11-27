// The login page end to end (ADR-0020, § 6): login with password and TOTP,
// the WebAssembly client, logout, a refusal; on every page, zero request
// to another origin, zero CSP violation, no console error, and no axe
// violation of the WCAG 2.0 and 2.1 A and AA rules, in both themes.
import { readFileSync } from "node:fs";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type TestInfo } from "@playwright/test";
import { totp } from "./totp.mjs";

interface User {
  name: string;
  password: string;
  secret: string;
}

const origin = process.env.OSTENA_E2E_ORIGIN ?? "";
const users: User[] = JSON.parse(readFileSync(process.env.OSTENA_E2E_USERS ?? "", "utf8"));

/** A user of its own for each test and browser: a TOTP step is accepted
 *  once per user. */
function userFor(info: TestInfo, slot: number): User {
  const name = `e2e-${info.project.name}-${slot}`;
  const user = users.find((u) => u.name === name);
  if (user === undefined) {
    throw new Error(`utilisateur ${name} absent`);
  }
  return user;
}

interface Watch {
  external: string[];
  console: string[];
}

const watched = new WeakMap<Page, Watch>();

test.beforeEach(async ({ context, page }) => {
  const watch: Watch = { external: [], console: [] };
  watched.set(page, watch);
  await context.route("**/*", (route) => {
    const url = route.request().url();
    if (new URL(url).origin === origin) {
      return route.continue();
    }
    watch.external.push(url);
    return route.abort("blockedbyclient");
  });
  await context.routeWebSocket(/.*/, (ws) => {
    if (new URL(ws.url()).origin.replace(/^wss:/, "https:") === origin) {
      ws.connectToServer();
    } else {
      watch.external.push(ws.url());
      void ws.close();
    }
  });
  await context.addInitScript(() => {
    const violations: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = violations;
    document.addEventListener("securitypolicyviolation", (e) => {
      violations.push(`${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  page.on("console", (message) => {
    if (message.type() === "error") {
      watch.console.push(message.text());
    }
  });
  page.on("pageerror", (error) => watch.console.push(error.message));
});

async function cspViolations(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __csp: string[] }).__csp ?? []);
}

/** No request elsewhere, no CSP violation, no console error but the
 *  expected ones. */
async function clean(page: Page, expectedConsole: RegExp[] = []) {
  const watch = watched.get(page);
  expect(watch?.external).toEqual([]);
  expect(await cspViolations(page)).toEqual([]);
  expect(watch?.console.filter((m) => !expectedConsole.some((e) => e.test(m)))).toEqual([]);
}

async function axe(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(", ")}`)).toEqual([]);
}

async function login(page: Page, user: User, password = user.password) {
  await page.getByLabel("Identifiant").fill(user.name);
  await page.getByLabel("Mot de passe").fill(password);
  // The confirmation of the enrolment used the current step.
  await page.getByLabel("Code à usage unique").fill(totp(user.secret, 1));
  await page.getByRole("button", { name: "Se connecter" }).click();
}

for (const scheme of ["light", "dark"] as const) {
  test.describe(`thème ${scheme === "light" ? "clair" : "sombre"}`, () => {
    test.use({ colorScheme: scheme });

    test("connexion, client WebAssembly et déconnexion", async ({ page }, info) => {
      const user = userFor(info, scheme === "light" ? 1 : 2);
      // The portal is cross-origin isolated (COOP same-origin, COEP
      // require-corp): Firefox opens it in a new browsing context, which
      // does not inherit the colour scheme emulated on the blank page. The
      // scheme is set again on the portal's context, then the reload
      // (same origin, same context) shows the first paint in that scheme.
      await page.goto("/");
      await page.emulateMedia({ colorScheme: scheme });
      const response = await page.reload();
      expect(response?.status()).toBe(200);
      expect(response?.headers()["content-security-policy"]).toContain("default-src 'none'");
      expect(await page.evaluate((s) => matchMedia(`(prefers-color-scheme: ${s})`).matches, scheme)).toBe(true);
      await expect(page.getByRole("heading", { name: "Connexion au bastion" })).toBeVisible();
      const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
      expect(background).toBe(scheme === "light" ? "rgb(250, 247, 248)" : "rgb(21, 16, 18)");
      await axe(page);

      await login(page, user);
      await expect(page.getByRole("heading", { name: "Connecté" })).toBeVisible();
      await expect(page.getByText("Client de session prêt (protocole ostena-frame v1).")).toBeVisible();
      await axe(page);

      await page.getByRole("button", { name: "Se déconnecter" }).click();
      await expect(page.getByRole("heading", { name: "Connexion au bastion" })).toBeVisible();
      await clean(page);
    });
  });
}

test("refus sans dire pourquoi, annoncé et accessible", async ({ page }, info) => {
  const user = userFor(info, 3);
  await page.goto("/");
  await login(page, user, "pas le bon mot de passe");
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("AUTH-E001");
  await expect(page.getByLabel("Mot de passe")).toHaveValue("");
  await axe(page);
  // The browser reports the refused login (401) in the console.
  await clean(page, [/401/]);
});

test("thème imposé par l'utilisateur avant le premier affichage", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto("/");
  await page.evaluate(() => window.localStorage.setItem("ostena.theme", "dark"));
  await page.reload();
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("dark");
  const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(background).toBe("rgb(21, 16, 18)");
  await axe(page);
  await clean(page);
});
