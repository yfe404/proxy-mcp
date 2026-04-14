/**
 * Smoke test: verify humanizer_type preserves uppercase + symbols.
 * Launches cloakbrowser, navigates to data: URL with a textarea, types
 * "Hello World! ABC @#$%" and reads the value back.
 */
import { launchContext } from "cloakbrowser";

const HTML = `<!DOCTYPE html><html><body>
<textarea id="t" autofocus style="width:400px;height:200px"></textarea>
</body></html>`;

const TEST_TEXT = "Hello World! ABC @#$%";

async function main() {
  const context = await launchContext({ headless: true, humanize: true });
  const browser = context.browser();
  try {
    const page = await context.newPage();
    await page.goto(`data:text/html;base64,${Buffer.from(HTML).toString("base64")}`);
    await page.focus("#t");

    const start = Date.now();
    await page.keyboard.type(TEST_TEXT);
    const elapsed = Date.now() - start;

    const value = await page.$eval("#t", (el) => (el as HTMLTextAreaElement).value);
    const match = value === TEST_TEXT;
    console.log(JSON.stringify({
      expected: TEST_TEXT,
      actual: value,
      match,
      elapsed_ms: elapsed,
    }, null, 2));
    process.exit(match ? 0 : 1);
  } finally {
    await context.close().catch(() => {});
    await browser?.close().catch(() => {});
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
