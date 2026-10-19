#!/usr/bin/env node

// src/cli.ts
import { existsSync } from "node:fs";
import { dirname, join as join2 } from "node:path";
import { fileURLToPath } from "node:url";

// src/deploy/cloudflare.ts
import { spawn } from "node:child_process";
var log = (message) => console.log(`  ${message}`);
async function deployCloudflare(plan) {
  const { templateDir, secrets, env, dryRun } = plan;
  const childEnv = { ...process.env, CLOUDFLARE_API_TOKEN: env.CLOUDFLARE_API_TOKEN };
  const wrangler = (args, input) => new Promise((resolve, reject) => {
    const child = spawn("npx", ["--yes", "wrangler@4", ...args], {
      cwd: templateDir,
      env: childEnv
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => out += String(chunk));
    child.stderr.on("data", (chunk) => err += String(chunk));
    child.on("error", reject);
    child.on(
      "close",
      (code) => code === 0 ? resolve(out) : reject(new Error(err.trim() || `wrangler exited ${code}`))
    );
    child.stdin.end(input ?? "");
  });
  log(`worker: ${templateDir}`);
  log(`${secrets.length} secrets, ${dryRun ? "dry run" : "uploading"}`);
  for (const name of secrets) {
    if (dryRun) {
      log(`  would set ${name}`);
      continue;
    }
    await wrangler(["secret", "put", name], `${env[name] ?? ""}
`);
    log(`  set ${name}`);
  }
  if (dryRun) {
    log("  would run: wrangler deploy");
    return "";
  }
  const stdout = await wrangler(["deploy"]);
  const url = /https:\/\/[A-Za-z0-9.-]+\.workers\.dev/.exec(stdout)?.[0] ?? "";
  if (!url) {
    log("deployed, but the URL was not in the output \u2014 check the Cloudflare dashboard");
    return "";
  }
  log(`deployed: ${url}`);
  return url;
}
async function checkHealth(baseUrl) {
  if (!baseUrl) return false;
  try {
    const response = await fetch(`${baseUrl.replace(/\/$/, "")}/`, {
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) return false;
    const body = await response.json();
    return body.ok === true && body.service === "gitalk-proxy";
  } catch {
    return false;
  }
}

// src/deploy/cloudbase.ts
import { spawn as spawn2 } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
var log2 = (message) => console.log(`  ${message}`);
function tcb(args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn2("npx", ["--yes", "--package", "@cloudbase/cli@latest", "tcb", ...args], {
      cwd,
      env: process.env
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => out += String(chunk));
    child.stderr.on("data", (chunk) => err += String(chunk));
    child.on("error", reject);
    child.on(
      "close",
      (code) => code === 0 ? resolve(out) : reject(new Error(err.trim() || `tcb exited ${code}`))
    );
    child.stdin.end();
  });
}
async function deployCloudbase(plan) {
  const { templateDir, runtime, env, dryRun } = plan;
  const envId = env.CLOUDBASE_ENV_ID;
  const base = (env.PUBLIC_ORIGIN ?? `https://${envId}.service.tcloudbase.com`).replace(/\/$/, "");
  const functionName = "gitalk-proxy";
  log2(`function: ${functionName} in ${envId}`);
  log2(`${Object.keys(runtime).length} runtime variables`);
  if (dryRun) {
    log2(`  would log in with CLOUDBASE_SECRET_ID / CLOUDBASE_SECRET_KEY`);
    log2(`  would write .env beside cloudbaserc.json`);
    log2(`  would run: tcb fn deploy ${functionName} --force --envId ${envId}`);
    log2(`  would check ${base}/`);
    return "";
  }
  await tcb(
    ["login", "--apiKeyId", env.CLOUDBASE_SECRET_ID ?? "", "--apiKey", env.CLOUDBASE_SECRET_KEY ?? ""],
    templateDir
  );
  log2("  logged in");
  writeFileSync(
    join(templateDir, ".env"),
    Object.entries(runtime).map(([key, value]) => `${key}=${value}`).join("\n") + "\n",
    { mode: 384 }
  );
  await tcb(["fn", "deploy", functionName, "--force", "--envId", envId], templateDir);
  log2(`  deployed: ${base}`);
  return base;
}

// src/env.ts
import { readFileSync } from "node:fs";
var COMMON = [
  { key: "GITHUB_APP_ID", hint: "the App ID from the GitHub App settings page" },
  { key: "GITHUB_CLIENT_ID", hint: "the App's Client ID (Iv1.\u2026 or Iv23li\u2026)" },
  { key: "GITHUB_CLIENT_SECRET", hint: "a generated client secret" },
  { key: "GITHUB_APP_PRIVATE_KEY", hint: "the .pem contents, not the fingerprint" },
  { key: "SESSION_ENCRYPTION_KEY", hint: "run `openssl rand -hex 32`" },
  { key: "GITALK_ALLOWED_ORIGINS", hint: "comma-separated origins, e.g. https://blog.example" }
];
function parseEnvFile(path) {
  const raw = readFileSync(path, "utf8");
  const out = {};
  const re = /^[ \t]*([A-Z0-9_]+)[ \t]*=[ \t]*(?:"([\s\S]*?)"|\'([\s\S]*?)\'|([^\r\n]*))[ \t]*$/gm;
  for (const m of raw.matchAll(re)) {
    out[m[1]] = (m[2] ?? m[3] ?? m[4] ?? "").replace(/\\n/g, "\n").trim();
  }
  return out;
}
function missing(env, required) {
  return required.filter((v) => !env[v.key]?.trim());
}

// src/cli.ts
var USAGE = `gitalk-deploy \u2014 deploy the Gitalk proxy

  gitalk-deploy -c <env-file> -t <target>

Options
  -c, --config <file>   dotenv file holding the App credentials (required)
  -t, --target <name>   cloudflare | cloudbase
  -n, --dry-run         print the steps without running them
  -h, --help            this message
`;
var PLATFORM = {
  cloudflare: {
    required: [
      ...COMMON,
      { key: "CLOUDFLARE_API_TOKEN", hint: "an API token with Workers Scripts: Edit" }
    ]
  },
  cloudbase: {
    required: [
      ...COMMON,
      { key: "CLOUDBASE_ENV_ID", hint: "the CloudBase environment id" },
      { key: "CLOUDBASE_SECRET_ID", hint: "a Tencent Cloud SecretId (use a sub-account)" },
      { key: "CLOUDBASE_SECRET_KEY", hint: "the matching SecretKey" }
    ]
  }
};
function fail(message) {
  console.error(`
\u2717 ${message}
`);
  process.exit(1);
}
function main(argv) {
  let config;
  let target;
  let dryRun = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") {
      console.log(USAGE);
      return;
    }
    if (arg === "-c" || arg === "--config") config = argv[++i];
    else if (arg === "-t" || arg === "--target") target = argv[++i];
    else if (arg === "-n" || arg === "--dry-run") dryRun = true;
    else fail(`unknown argument: ${arg}
${USAGE}`);
  }
  if (!config) fail(`missing -c <env-file>
${USAGE}`);
  if (!target) fail(`missing -t <target>
${USAGE}`);
  const platform = PLATFORM[target];
  if (!platform) fail(`unknown target "${target}" \u2014 expected cloudflare or cloudbase`);
  if (!existsSync(config)) fail(`no such file: ${config}`);
  const env = parseEnvFile(config);
  const gaps = missing(env, platform.required);
  if (gaps.length) {
    fail(
      `${gaps.length} required value(s) missing from ${config}:
` + gaps.map((g) => `  ${g.key}  \u2014 ${g.hint}`).join("\n")
    );
  }
  console.log(`\u2713 ${config} has every value ${target} needs`);
  const here = dirname(fileURLToPath(import.meta.url));
  const templates = join2(here, "..", "templates");
  const required = existsSync(join2(templates, "worker", "index.js"));
  if (target === "cloudbase") {
    if (!existsSync(join2(templates, "functions/gitalk-proxy"))) {
      fail(
        `no CloudBase bundle at ${join2(templates, "functions/gitalk-proxy")} \u2014 rebuild with scripts/bundle.mjs`
      );
    }
    deployCloudbase({
      templateDir: templates,
      // `{{env.X}}` reads these from the .env written beside cloudbaserc.json;
      // the Tencent Cloud keys are for the CLI itself and are excluded.
      runtime: Object.fromEntries(
        platform.required.map((v) => v.key).filter((key) => !key.startsWith("CLOUDBASE_")).map((key) => [key, env[key] ?? ""])
      ),
      env,
      dryRun
    }).then(async (url) => {
      if (dryRun) {
        console.log("\n\u2713 dry run complete \u2014 rerun without -n to deploy");
        return;
      }
      if (await checkHealth(url)) {
        console.log(`
\u2713 healthy: ${url}`);
      } else {
        console.log("\n\u26A0 deployed, but /health did not answer ok \u2014 check the function logs");
      }
    }).catch((error) => fail(error instanceof Error ? error.message : String(error)));
    return;
  }
  if (!required) {
    fail(
      `no worker bundle at ${join2(templates, "worker")}
  this build was packaged without templates \u2014 rebuild with scripts/bundle.mjs`
    );
  }
  deployCloudflare({
    templateDir: join2(templates, "worker"),
    // Everything except the Cloudflare credential itself becomes a worker secret.
    secrets: platform.required.map((v) => v.key).filter((key) => key !== "CLOUDFLARE_API_TOKEN"),
    env,
    dryRun
  }).then(async (url) => {
    if (dryRun) {
      console.log("\n\u2713 dry run complete \u2014 rerun without -n to deploy");
      return;
    }
    if (await checkHealth(url)) {
      console.log(`
\u2713 healthy: ${url}`);
      console.log(`  set proxy: '${url}' in your Gitalk options`);
    } else {
      console.log("\n\u26A0 deployed, but /health did not answer ok \u2014 check the worker logs");
    }
  }).catch((error) => fail(error instanceof Error ? error.message : String(error)));
}
main(process.argv.slice(2));
