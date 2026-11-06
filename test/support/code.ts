// Reads TypeScript source well enough for the repository tests: it blanks
// out comments and the text of strings and templates (keeping lengths and
// line breaks) and lists the regex literals. It is not a full parser; it
// only has to be right for this repository's own code, and its tests say
// where the line between a regex and a division is.

export interface Code {
  /** The source with comments and string text replaced by spaces. */
  readonly code: string;
  /** Every regex literal, as written. */
  readonly regexes: readonly string[];
}

const KEYWORDS_BEFORE_EXPRESSION = new Set([
  "return",
  "typeof",
  "case",
  "do",
  "else",
  "in",
  "of",
  "new",
  "delete",
  "void",
  "throw",
  "yield",
  "await",
]);

const isWordChar = (char: string): boolean => /[A-Za-z0-9_$]/u.test(char);

export function readCode(source: string): Code {
  const out: string[] = [];
  const regexes: string[] = [];
  let index = 0;

  const blank = (char: string): string => (char === "\n" || char === "\r" ? char : " ");

  // The last character of code written so far, and the word it ends, if any.
  const previous = (): { char: string; word: string } => {
    let end = out.length - 1;
    while (end >= 0 && /\s/u.test(out[end] ?? "")) {
      end -= 1;
    }
    const char = out[end] ?? "";
    let start = end;
    while (start >= 0 && isWordChar(out[start] ?? "")) {
      start -= 1;
    }
    return { char, word: out.slice(start + 1, end + 1).join("") };
  };

  const regexCanStart = (): boolean => {
    const { char, word } = previous();
    if (char === "") {
      return true;
    }
    if (isWordChar(char)) {
      return KEYWORDS_BEFORE_EXPRESSION.has(word);
    }
    return char !== ")" && char !== "]";
  };

  const skipQuoted = (quote: string): void => {
    out.push(quote);
    index += 1;
    while (index < source.length && source[index] !== quote) {
      if (source[index] === "\\") {
        out.push(" ");
        index += 1;
      }
      out.push(blank(source[index] ?? ""));
      index += 1;
    }
    out.push(source[index] ?? "");
    index += 1;
  };

  // Reads code until the end, or until the "}" that closes a template's ${.
  const readUntilBrace = (insideTemplate: boolean): void => {
    let depth = 0;
    while (index < source.length) {
      const char = source[index] ?? "";
      const next = source[index + 1] ?? "";
      if (char === "/" && next === "/") {
        while (index < source.length && source[index] !== "\n") {
          out.push(" ");
          index += 1;
        }
      } else if (char === "/" && next === "*") {
        const end = source.indexOf("*/", index + 2);
        const stop = end === -1 ? source.length : end + 2;
        for (; index < stop; index += 1) {
          out.push(blank(source[index] ?? ""));
        }
      } else if (char === '"' || char === "'") {
        skipQuoted(char);
      } else if (char === "`") {
        readTemplate();
      } else if (char === "/" && regexCanStart()) {
        readRegex();
      } else {
        if (char === "{") {
          depth += 1;
        } else if (char === "}") {
          if (insideTemplate && depth === 0) {
            return;
          }
          depth -= 1;
        }
        out.push(char);
        index += 1;
      }
    }
  };

  const readTemplate = (): void => {
    out.push("`");
    index += 1;
    while (index < source.length && source[index] !== "`") {
      if (source[index] === "\\") {
        out.push(" ", blank(source[index + 1] ?? ""));
        index += 2;
      } else if (source[index] === "$" && source[index + 1] === "{") {
        out.push("${");
        index += 2;
        readUntilBrace(true);
        out.push(source[index] ?? "");
        index += 1;
      } else {
        out.push(blank(source[index] ?? ""));
        index += 1;
      }
    }
    out.push(source[index] ?? "");
    index += 1;
  };

  const readRegex = (): void => {
    const start = index;
    let inClass = false;
    index += 1;
    while (index < source.length && source[index] !== "\n") {
      const char = source[index];
      if (char === "\\") {
        index += 2;
        continue;
      }
      if (char === "[") {
        inClass = true;
      } else if (char === "]") {
        inClass = false;
      } else if (char === "/" && !inClass) {
        break;
      }
      index += 1;
    }
    index += 1;
    while (index < source.length && /[a-z]/u.test(source[index] ?? "")) {
      index += 1;
    }
    const literal = source.slice(start, index);
    regexes.push(literal);
    // Written as a value that ends like ")", so a slash after it reads as a division.
    for (let at = 1; at < literal.length; at += 1) {
      out.push(" ");
    }
    out.push(")");
  };

  readUntilBrace(false);
  return { code: out.join(""), regexes };
}
