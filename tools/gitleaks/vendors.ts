// Company names, aliases and label words for the rules imported from
// gitleaks. gitleaks ids start with a slug of the company; the longest
// matching slug wins. A label is the company name plus the rest of the id
// in plain words, unless LABELS names it.

import type { Severity } from "../../src/types.ts";

export const VENDORS: readonly (readonly [slug: string, vendor: string])[] = [
  ["1password", "1Password"],
  ["adafruit", "Adafruit"],
  ["adobe", "Adobe"],
  ["age", "age"],
  ["airtable", "Airtable"],
  ["algolia", "Algolia"],
  ["alibaba", "Alibaba Cloud"],
  ["anthropic", "Anthropic"],
  ["artifactory", "JFrog"],
  ["asana", "Asana"],
  ["atlassian", "Atlassian"],
  ["authress", "Authress"],
  ["aws", "AWS"],
  ["azure", "Microsoft"],
  ["beamer", "Beamer"],
  ["bitbucket", "Atlassian"],
  ["bittrex", "Bittrex"],
  ["cisco-meraki", "Cisco Meraki"],
  ["clickhouse", "ClickHouse"],
  ["clojars", "Clojars"],
  ["cloudflare", "Cloudflare"],
  ["codecov", "Codecov"],
  ["cohere", "Cohere"],
  ["coinbase", "Coinbase"],
  ["confluent", "Confluent"],
  ["contentful", "Contentful"],
  ["curl", "Generic"],
  ["databricks", "Databricks"],
  ["datadog", "Datadog"],
  ["defined-networking", "Defined Networking"],
  ["digitalocean", "DigitalOcean"],
  ["discord", "Discord"],
  ["doppler", "Doppler"],
  ["droneci", "Drone CI"],
  ["dropbox", "Dropbox"],
  ["duffel", "Duffel"],
  ["dynatrace", "Dynatrace"],
  ["easypost", "EasyPost"],
  ["etsy", "Etsy"],
  ["facebook", "Meta"],
  ["fastly", "Fastly"],
  ["finicity", "Finicity"],
  ["finnhub", "Finnhub"],
  ["flickr", "Flickr"],
  ["flutterwave", "Flutterwave"],
  ["flyio", "Fly.io"],
  ["frameio", "Frame.io"],
  ["freemius", "Freemius"],
  ["freshbooks", "FreshBooks"],
  ["gcp", "Google"],
  ["generic", "Generic"],
  ["github", "GitHub"],
  ["gitlab", "GitLab"],
  ["gitter", "Gitter"],
  ["gocardless", "GoCardless"],
  ["grafana", "Grafana"],
  ["harness", "Harness"],
  ["hashicorp", "HashiCorp"],
  ["heroku", "Heroku"],
  ["hubspot", "HubSpot"],
  ["huggingface", "Hugging Face"],
  ["infracost", "Infracost"],
  ["intercom", "Intercom"],
  ["intra42", "42"],
  ["jfrog", "JFrog"],
  ["jwt", "Generic"],
  ["kraken", "Kraken"],
  ["kubernetes", "Kubernetes"],
  ["kucoin", "KuCoin"],
  ["launchdarkly", "LaunchDarkly"],
  ["linear", "Linear"],
  ["linkedin", "LinkedIn"],
  ["lob", "Lob"],
  ["looker", "Google"],
  ["mailchimp", "Mailchimp"],
  ["mailgun", "Mailgun"],
  ["mapbox", "Mapbox"],
  ["mattermost", "Mattermost"],
  ["maxmind", "MaxMind"],
  ["messagebird", "MessageBird"],
  ["microsoft-teams", "Microsoft"],
  ["netlify", "Netlify"],
  ["new-relic", "New Relic"],
  ["notion", "Notion"],
  ["npm", "npm"],
  ["nuget", "NuGet"],
  ["nytimes", "The New York Times"],
  ["octopus-deploy", "Octopus Deploy"],
  ["okta", "Okta"],
  ["openai", "OpenAI"],
  ["openshift", "Red Hat"],
  ["perplexity", "Perplexity"],
  ["pkcs12", "Generic"],
  ["plaid", "Plaid"],
  ["planetscale", "PlanetScale"],
  ["postman", "Postman"],
  ["prefect", "Prefect"],
  ["private-key", "Generic"],
  ["privateai", "Private AI"],
  ["pulumi", "Pulumi"],
  ["pypi", "PyPI"],
  ["rapidapi", "RapidAPI"],
  ["readme", "ReadMe"],
  ["rubygems", "RubyGems"],
  ["scalingo", "Scalingo"],
  ["sendbird", "Sendbird"],
  ["sendgrid", "Twilio SendGrid"],
  ["sendinblue", "Brevo"],
  ["sentry", "Sentry"],
  ["settlemint", "SettleMint"],
  ["shippo", "Shippo"],
  ["shopify", "Shopify"],
  ["sidekiq", "Sidekiq"],
  ["slack", "Slack"],
  ["snyk", "Snyk"],
  ["sonar", "SonarSource"],
  ["sourcegraph", "Sourcegraph"],
  ["square", "Square"],
  ["squarespace", "Squarespace"],
  ["stripe", "Stripe"],
  ["sumologic", "Sumo Logic"],
  ["telegram", "Telegram"],
  ["travisci", "Travis CI"],
  ["twilio", "Twilio"],
  ["twitch", "Twitch"],
  ["twitter", "X"],
  ["typeform", "Typeform"],
  ["vault", "HashiCorp"],
  ["yandex", "Yandex"],
  ["zendesk", "Zendesk"],
];

/** Other names people search for, per company. */
export const ALIASES: Readonly<Record<string, readonly string[]>> = {
  AWS: ["Amazon", "Amazon Web Services", "Bedrock"],
  Atlassian: ["Jira", "Confluence", "Bitbucket", "Trello"],
  Google: ["GCP", "Google Cloud", "Firebase", "Gemini", "Looker"],
  Microsoft: ["Azure", "Entra", "Teams", "Office 365"],
  Meta: ["Facebook", "Instagram", "WhatsApp"],
  X: ["Twitter"],
  Brevo: ["Sendinblue"],
  "Twilio SendGrid": ["SendGrid", "Twilio"],
  HashiCorp: ["Terraform", "Vault"],
  JFrog: ["Artifactory"],
  "Red Hat": ["OpenShift", "Kubernetes"],
  GitHub: ["Git"],
  GitLab: ["Git"],
  Slack: ["Salesforce"],
};

/** Labels that plain words from the id would get wrong. */
export const LABELS: Readonly<Record<string, string>> = {
  "1password-secret-key": "1Password secret key",
  "1password-service-account-token": "1Password service account token",
  "age-secret-key": "age encryption secret key",
  "airtable-personnal-access-token": "Airtable personal access token",
  "artifactory-api-key": "Artifactory API key",
  "artifactory-reference-token": "Artifactory reference token",
  "azure-ad-client-secret": "Azure (Entra ID) client secret",
  "bitbucket-client-id": "Bitbucket OAuth client ID",
  "bitbucket-client-secret": "Bitbucket OAuth client secret",
  "curl-auth-header": "Credential in a curl header",
  "curl-auth-user": "Credential in curl -u",
  "facebook-access-token": "Facebook access token",
  "facebook-page-access-token": "Facebook page access token",
  "facebook-secret": "Facebook app secret",
  "gcp-api-key": "Google API key",
  "generic-api-key": "Generic API key",
  jwt: "JSON Web Token",
  "jwt-base64": "JSON Web Token (Base64)",
  "kubernetes-secret-yaml": "Kubernetes Secret in YAML",
  "looker-client-id": "Looker client ID",
  "looker-client-secret": "Looker client secret",
  "microsoft-teams-webhook": "Microsoft Teams webhook",
  "pkcs12-file": "PKCS#12 file",
  "private-key": "Private key",
  "sendinblue-api-token": "Brevo (Sendinblue) API key",
  "sendgrid-api-token": "SendGrid API key",
  "twitter-access-secret": "X (Twitter) access secret",
  "twitter-access-token": "X (Twitter) access token",
  "twitter-api-key": "X (Twitter) API key",
  "twitter-api-secret": "X (Twitter) API secret",
  "twitter-bearer-token": "X (Twitter) bearer token",
  "vault-batch-token": "Vault batch token",
  "vault-service-token": "Vault service token",
};

const WORDS: Readonly<Record<string, string>> = {
  api: "API",
  id: "ID",
  pat: "personal access token",
  oauth: "OAuth",
  url: "URL",
  ca: "CA",
  ci: "CI",
  cicd: "CI/CD",
  scim: "SCIM",
  ptt: "pipeline trigger token",
  rrt: "runner registration token",
  aws: "AWS",
  tf: "Terraform",
  yaml: "YAML",
  pub: "public",
  v2: "v2",
};

export function vendorOf(id: string): { vendor: string; slug: string } {
  let best: readonly [string, string] | undefined;
  for (const entry of VENDORS) {
    const [slug] = entry;
    if ((id === slug || id.startsWith(`${slug}-`)) && (best === undefined || slug.length > best[0].length)) {
      best = entry;
    }
  }
  if (best === undefined) {
    throw new Error(`no vendor for gitleaks rule ${id}`);
  }
  return { slug: best[0], vendor: best[1] };
}

export function labelOf(id: string): string {
  const named = LABELS[id];
  if (named !== undefined) {
    return named;
  }
  const { slug, vendor } = vendorOf(id);
  const rest = id
    .slice(slug.length + 1)
    .split("-")
    .map((word) => WORDS[word] ?? word)
    .join(" ");
  return rest === "" ? vendor : `${vendor} ${rest}`;
}

/** Public identifiers are not secrets on their own: low. Bare key ids and JWTs: medium. */
export function severityOf(id: string): Severity {
  const low =
    id.endsWith("-id") || id.includes("-pub-") || id.endsWith("-public-key") || id.endsWith("-pub-key");
  if (low) {
    return "low";
  }
  if (id === "aws-access-token" || id === "jwt" || id === "jwt-base64" || id === "alibaba-access-key-id") {
    return "medium";
  }
  return "high";
}
