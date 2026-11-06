# Changelog

All notable changes to this project are written here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-06

First version.

### Added

- `scan(text, options)` finds credentials and returns their ranges, never their values.
- 248 built-in rules from 129 companies and projects: every gitleaks v8.30.1 rule for text (220 of 222) and 28 of keysnitch's own, among them Atlassian access tokens, Bitbucket app passwords, Azure Storage keys and SAS signatures, passwords in URLs, secrets in settings and `.env` files, and Authorization headers.
- A pattern parser and safety check: every rule is proven free of slow backtracking before it runs.
- `defineRule()` for your own rules, custom matchers for patterns run by another engine.
- `findRules()` and `vendors()` to find rules by company, name or alias.
- `mask()` to show a value safely.
