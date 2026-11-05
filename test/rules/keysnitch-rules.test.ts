// Scenarios: the credentials keysnitch was built for, through the full set
// of built-in rules (so overlaps between rules are part of the test).
// - Atlassian API tokens of any length, access tokens and app passwords;
// - Google API keys inside URLs (gitleaks misses them before "&"), OAuth
//   client secrets;
// - Azure Storage account keys, SAS signatures, Entra client secrets;
// - formats the simplify-software.org checker finds without a context
//   word: Telegram, Mailgun, Hugging Face, Doppler, Groq, xAI, Replicate,
//   Docker Hub, Figma, Supabase, Square, Mapbox, Notion, Discord;
// - passwords in URLs, secrets in settings and .env files, Authorization
//   headers, curl -u and docker login -p;
// - the reported range is exactly the secret: no quote, no "&", no label;
// - look-alikes and placeholders are not reported.
// Values are built from parts here; none is a real credential.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { scan } from "../../src/scan.ts";
import { random } from "../support/sample.ts";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX = "0123456789abcdef";
const URLSAFE = `${ALNUM}_-`;

/** Deterministic text of `length` characters from `alphabet`. */
function chars(alphabet: string, length: number, seed = 7): string {
  const next = random(seed);
  let out = "";
  for (let index = 0; index < length; index += 1)
    out += alphabet.charAt(Math.floor(next() * alphabet.length));
  return out;
}

/** What scan() reports, as [rule id, value] pairs. */
function found(text: string): [string, string][] {
  return scan(text).findings.map((finding) => [finding.ruleId, text.slice(finding.start, finding.end)]);
}

function values(text: string): string[] {
  return found(text).map(([, value]) => value);
}

function assertFound(text: string, secret: string, ruleId?: string): void {
  const list = found(text);
  const hit = list.find(([, value]) => value === secret);
  assert.ok(
    hit !== undefined,
    `expected ${secret.slice(0, 12)}... in ${JSON.stringify(list.map(([id]) => id))}`,
  );
  if (ruleId !== undefined) assert.equal(hit[0], ruleId);
}

/** The secret is inside one finding (which may be wider), named by the given rule. */
function assertCovered(text: string, secret: string, ruleId: string): void {
  const list = found(text);
  const hit = list.find(([, value]) => value.includes(secret));
  assert.ok(
    hit !== undefined,
    `expected ${secret.slice(0, 12)}... covered in ${JSON.stringify(list.map(([id]) => id))}`,
  );
  assert.equal(hit[0], ruleId);
}

function assertNothing(text: string): void {
  assert.deepEqual(found(text), [], text);
}

describe("Atlassian", () => {
  const apiToken = (length: number): string =>
    `ATATT3xFfGF0${chars(URLSAFE, length - 21, 11)}=${chars(HEX, 8, 3).toUpperCase()}`;

  it("finds an API token of the usual length in prose, JSON, a URL and a curl command", () => {
    const token = apiToken(192);
    assertFound(`Use ${token} for the bot.`, token, "atlassian-api-token");
    assertFound(`{"token": "${token}"}`, token, "atlassian-api-token");
    // In a URL query the setting rule also takes "&next=1" (a password may hold "&"),
    // so the range is wider than the token; it is still named as an Atlassian token.
    assertCovered(`https://x.test/hook?token=${token}&next=1`, token, "atlassian-api-token");
    assertCovered(
      `curl -u me@company.test:${token} https://site.atlassian.net`,
      token,
      "atlassian-api-token",
    );
  });

  it("finds API tokens of other lengths (Atlassian says the length varies)", () => {
    for (const length of [120, 150, 192, 230]) {
      const token = apiToken(length);
      assertFound(`token ${token}`, token, "atlassian-api-token");
    }
  });

  it("finds an access token and an app password", () => {
    const access = `ATCTT3xFfGN0${chars(URLSAFE, 171, 5)}=${chars(HEX, 8, 9).toUpperCase()}`;
    assertFound(`BITBUCKET_ACCESS_TOKEN: ${access}`, access);
    assert.ok(found(`x ${access} y`).some(([id]) => id === "atlassian-access-token"));
    const appPassword = `ATBB${chars(ALNUM, 32, 13)}`;
    assertFound(`app password ${appPassword}`, appPassword, "bitbucket-app-password");
  });

  it("does not report words or short strings with the same start", () => {
    assertNothing("ATATTACK at dawn, ATBB is a band, ATCTT.");
    assertNothing(`ATATT3xFfGF0${chars(URLSAFE, 40)}`);
  });
});

describe("Google", () => {
  const key = `AIzaSy${chars(URLSAFE, 33, 21)}`;

  it("finds an API key inside a URL, before & and after =", () => {
    const text = `<script src="https://maps.googleapis.com/maps/api/js?key=${key}&callback=init"></script>`;
    assertFound(text, key);
  });

  it("finds an API key in a Firebase config", () => {
    assertFound(`const firebaseConfig = { apiKey: "${key}", authDomain: "x.firebaseapp.com" };`, key);
  });

  it("finds an OAuth client secret", () => {
    const secret = `GOCSPX-${chars(URLSAFE, 28, 4)}`;
    assertFound(`"client_secret":"${secret}"`, secret);
  });

  it("does not report the documented example key", () => {
    assertNothing("key=AIzaSyabcdefghijklmnopqrstuvwxyz1234567 ");
  });
});

describe("Microsoft", () => {
  it("finds an Azure Storage account key in a connection string", () => {
    const accountKey = `${chars(`${ALNUM}+/`, 86, 8)}==`;
    const text = `DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=${accountKey};EndpointSuffix=core.windows.net`;
    assertFound(text, accountKey, "azure-storage-account-key");
  });

  it("finds a SAS signature in a blob URL", () => {
    const sig = `${chars(ALNUM, 43, 2)}%3D`;
    const text = `https://acme.blob.core.windows.net/c/f.txt?sv=2023-11-03&ss=b&srt=o&sp=r&se=2026-12-01&sig=${sig}`;
    assertFound(text, sig, "azure-sas-token");
  });

  it("finds an Entra client secret", () => {
    const secret = `Xy78Q~${chars(`${ALNUM}_~.-`, 34, 6)}`;
    assert.ok(values(`client secret: ${secret}`).some((value) => value.includes(secret)));
  });
});

describe("formats found without a context word", () => {
  const cases: [string, string][] = [
    ["Telegram bot token", `7234567890:AA${chars(URLSAFE, 33, 1)}`],
    ["Mailgun key", `key-${chars(HEX, 32, 2)}`],
    ["Hugging Face token", `hf_${chars(ALNUM, 34, 3)}`],
    ["Doppler service token", `dp.st.${chars(ALNUM, 44, 4)}`],
    ["Groq key", `gsk_${chars(ALNUM, 52, 5)}`],
    ["xAI key", `xai-${chars(ALNUM, 80, 6)}`],
    ["Replicate token", `r8_${chars(ALNUM, 37, 7)}`],
    ["Docker Hub token", `dckr_pat_${chars(URLSAFE, 27, 8)}`],
    ["Figma token", `figd_${chars(URLSAFE, 40, 9)}`],
    ["Supabase token", `sbp_${chars(HEX, 40, 10)}`],
    ["Square OAuth secret", `sq0csp-${chars(URLSAFE, 43, 11)}`],
    ["Mapbox secret token", `sk.eyJ${chars(URLSAFE, 60, 12)}.${chars(URLSAFE, 22, 13)}`],
    ["Notion token", `secret_${chars(ALNUM, 43, 14)}`],
  ];
  for (const [name, secret] of cases) {
    it(name, () => {
      assertFound(`here it is: ${secret}\n`, secret);
      assertFound(`"${secret}"`, secret);
    });
  }

  it("Discord webhook URL", () => {
    const url = `https://discord.com/api/webhooks/123456789012345678/${chars(URLSAFE, 68, 15)}`;
    assertFound(`post to ${url} now`, url, "discord-webhook-url");
  });
});

describe("passwords in URLs", () => {
  it("finds the password of a database URL, not the user or host", () => {
    for (const scheme of ["postgres", "postgresql", "mysql", "mongodb+srv", "redis", "amqps", "https"]) {
      assertFound(
        `DATABASE_URL="${scheme}://app_user:Pz9k2LmQx8@db.internal:5432/app"`,
        "Pz9k2LmQx8",
        "url-credentials",
      );
    }
  });

  it("does not report placeholders in URLs", () => {
    assertNothing("postgres://user:password@localhost/db");
    assertNothing("postgres://user:${DB_PASS}@localhost/db");
    assertNothing("https://user:********@example.test/");
  });
});

describe("secrets in settings", () => {
  it("finds values of named settings in .env, YAML, JSON and code", () => {
    assertFound("DB_PASSWORD=Pz9k2LmQx8w\n", "Pz9k2LmQx8w");
    assertFound("JIRA_API_TOKEN=Q8w2Er4Ty6Ui\n", "Q8w2Er4Ty6Ui");
    assertFound("app_key=k9J3h7G5f1D2\n", "k9J3h7G5f1D2");
    assertFound("APP_SECRET: m4N8b2V6c0X3\n", "m4N8b2V6c0X3");
    assertFound('{"appKey": "w3E5r7T9y1U2"}', "w3E5r7T9y1U2");
    assertFound("clientSecret: 'z8X6c4V2b0N9'", "z8X6c4V2b0N9");
    assertFound("_authToken=npmToken123456\n", "npmToken123456");
    assertFound("export DB_PASSWORD=s3cr3tPassw0rd\n", "s3cr3tPassw0rd");
  });

  it("does not report types, code, references and look-alike names", () => {
    for (const text of [
      "password: string;",
      "token: this.token,",
      "const password = getPassword();",
      "password = os.getenv('DB_PASSWORD')",
      "passport=12345678",
      "tokenUrl=https://auth.example.test/token",
      "api_key=${API_KEY}",
      'password: "********"',
      "PASSWORD=changeme123",
      "secret: process.env.APP_SECRET",
      "Reset your password: click the link below.",
    ]) {
      assertNothing(text);
    }
  });
});

describe("headers and commands", () => {
  it("finds a bearer token and a Basic header that holds user:password", () => {
    const bearer = chars(URLSAFE, 40, 21);
    assertFound(`Authorization: Bearer ${bearer}`, bearer);
    const basic = "YWxpY2U6d29uZGVybGFuZDEy"; // "alice:wonderland12" in Base64
    assertFound(`Authorization: Basic ${basic}`, basic, "generic-basic-auth");
  });

  it("does not report a Basic header that is not user:password, or prose", () => {
    assertNothing("Authorization: Basic aGVsbG8gd29ybGQ=");
    assertNothing("The basic idea of a bearer token is simple.");
  });

  it("finds the password of curl -u and docker login -p", () => {
    assertFound("curl -u admin:Pz9k2LmQx8 https://x.test", "admin:Pz9k2LmQx8");
    assertFound("docker login -u bot -p Pz9k2LmQx8 registry.test", "Pz9k2LmQx8", "docker-login-password");
  });

  it("does not report curl and docker without a secret", () => {
    assertNothing("curl -u user:password https://x.test");
    assertNothing("docker login -u bot --password-stdin registry.test");
  });
});
