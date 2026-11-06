# Changelog

All notable changes to this project are written here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-06

### Fixed

- `jwt-base64` no longer takes the first word of the next line. A Base64 JWT without `=` padding ran over the line break, so a redaction removed text after it (`kind` in a Kubernetes Secret). A JWT wrapped at 76 or 64 characters per line is still covered line by line.
- A long value in a setting, an export, a sentence, a table, `docker login -p` or `curl -u` is covered whole. Values were cut at 200 characters, so the rest of a longer secret stayed readable after a redaction. Now a value is covered whole up to 2,048 characters after `=` (4,096 for the other rules); a longer one is not reported rather than cut.

## [0.1.0] - 2026-11-06

First version.

### Added

- `scan(text, options)` finds credentials and returns their ranges, never their values.
- 250 built-in rules from 129 companies and projects: every gitleaks v8.30.1 rule for text (220 of 222) and 30 of keysnitch's own, among them Atlassian access tokens, Bitbucket app passwords, Azure Storage keys and SAS signatures, passwords in URLs, secrets in settings and `.env` files, and Authorization headers.
- A pattern parser and safety check: every rule is proven free of slow backtracking before it runs.
- `defineRule()` for your own rules, custom matchers for patterns run by another engine.
- `findRules()` and `vendors()` to find rules by company, name or alias.
- `mask()` to show a value safely.

[Unreleased]: https://github.com/roman-kolpachev/keysnitch/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/roman-kolpachev/keysnitch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/roman-kolpachev/keysnitch/releases/tag/v0.1.0
