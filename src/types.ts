export type Severity = "high" | "medium" | "low";

/** What a rule author writes. `defineRule` checks it and returns a `Rule`. */
export interface RuleSpec {
  /** Stable, kebab-case. Where a gitleaks rule exists, its id. */
  readonly id: string;
  /** The company or project the credential belongs to, for example "Atlassian". */
  readonly vendor: string;
  /** A short human name, for example "Atlassian API token". */
  readonly label: string;
  readonly severity: Severity;
  /** Lower-case words. The rule runs only if one of them is in the text (in any case). Empty: always runs. */
  readonly keywords: readonly string[];
  /** The pattern in RE2 syntax. It must pass the safety check. */
  readonly pattern: string;
  /**
   * Which capture group holds the secret: a number (0 is the whole match) or
   * "first", the first group that took part in the match. Default: "first"
   * if the pattern has groups, else the whole match.
   */
  readonly secretGroup?: number | "first";
  /** Minimum Shannon entropy (bits per character) of the secret. Default 0. */
  readonly minEntropy?: number;
  /** Other names people search for, for example "Firebase" for a Google key. */
  readonly aliases?: readonly string[];
  /** Patterns for values that are never secrets. A secret that matches one completely is skipped. */
  readonly allow?: readonly string[];
  /** A catch-all rule (a setting named "password", say). A specific rule wins over it on equal ranges. */
  readonly generic?: boolean;
  /** Where to revoke or rotate the credential. */
  readonly rotate?: string;
  /** Where the rule comes from, for example "gitleaks:aws-access-token". */
  readonly source?: string;
  /** An extra check on the secret, for example a checksum. Return false to skip it. */
  readonly validate?: (secret: string) => boolean;
}

export interface Rule {
  readonly id: string;
  readonly vendor: string;
  readonly label: string;
  readonly severity: Severity;
  readonly keywords: readonly string[];
  readonly pattern: string;
  readonly secretGroup: number | "first";
  readonly minEntropy: number;
  readonly aliases: readonly string[];
  readonly allow: readonly string[];
  readonly generic: boolean;
  readonly rotate?: string;
  readonly source?: string;
  readonly validate?: (secret: string) => boolean;
}

/** A credential found in the text. The value is text.slice(start, end); it is never stored here. */
export interface Finding {
  readonly ruleId: string;
  readonly vendor: string;
  readonly label: string;
  readonly severity: Severity;
  /** UTF-16 offsets, like String.prototype.slice. */
  readonly start: number;
  readonly end: number;
}

/** A matcher written in code, for shapes a pattern cannot express or for patterns run by another engine. */
export interface CustomMatcher {
  readonly id: string;
  readonly vendor: string;
  readonly label: string;
  readonly severity: Severity;
  readonly find: (text: string) => Iterable<{ readonly start: number; readonly end: number }>;
}
