// Scenarios: a settings screen lets people find rules by company.
// - findRules matches the vendor, the label, the id and the aliases, in
//   any case, in part ("atlas" finds Atlassian);
// - several words must all match (AND), in any field;
// - an empty or blank query returns every rule;
// - results are sorted by vendor, then label, and never include a rule twice;
// - vendors() counts rules per company, sorted by name.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { defineRule } from "../src/rule.ts";
import { findRules, vendors } from "../src/search.ts";

const make = (id: string, vendor: string, label: string, aliases: string[] = []) =>
  defineRule({ id, vendor, label, aliases, severity: "high", keywords: [], pattern: "x[0-9]{4}" });

const list = [
  make("google-api-key", "Google", "Google API key", ["Firebase", "GCP"]),
  make("atlassian-api-token", "Atlassian", "Atlassian API token", ["Jira", "Confluence"]),
  make("bitbucket-app-password", "Atlassian", "Bitbucket app password", ["Bitbucket"]),
  make("azure-entra-secret", "Microsoft", "Entra client secret", ["Azure"]),
];

const ids = (query: string): string[] => findRules(query, list).map((rule) => rule.id);

describe("findRules", () => {
  it("finds by vendor in part and in any case", () => {
    assert.deepEqual(ids("atlas"), ["atlassian-api-token", "bitbucket-app-password"]);
    assert.deepEqual(ids("ATLASSIAN"), ["atlassian-api-token", "bitbucket-app-password"]);
  });

  it("finds by alias, label and id", () => {
    assert.deepEqual(ids("firebase"), ["google-api-key"]);
    assert.deepEqual(ids("entra"), ["azure-entra-secret"]);
    assert.deepEqual(ids("app password"), ["bitbucket-app-password"]);
    assert.deepEqual(ids("api-token"), ["atlassian-api-token"]);
    assert.deepEqual(ids("jira"), ["atlassian-api-token"]);
  });

  it("needs every word to match somewhere", () => {
    assert.deepEqual(ids("atlassian bitbucket"), ["bitbucket-app-password"]);
    assert.deepEqual(ids("google azure"), []);
  });

  it("returns every rule for a blank query, sorted by vendor and label", () => {
    assert.deepEqual(ids("  "), [
      "atlassian-api-token",
      "bitbucket-app-password",
      "google-api-key",
      "azure-entra-secret",
    ]);
  });

  it("returns nothing for an unknown company", () => {
    assert.deepEqual(ids("nonexistent vendor"), []);
  });

  it("uses the built-in rules by default", () => {
    assert.ok(Array.isArray(findRules("")));
  });
});

describe("vendors", () => {
  it("counts rules per company", () => {
    assert.deepEqual(vendors(list), [
      { vendor: "Atlassian", count: 2 },
      { vendor: "Google", count: 1 },
      { vendor: "Microsoft", count: 1 },
    ]);
  });

  it("uses the built-in rules by default", () => {
    assert.ok(Array.isArray(vendors()));
  });
});
