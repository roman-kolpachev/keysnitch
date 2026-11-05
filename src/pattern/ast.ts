import type { CharSet } from "./charset.ts";

/** One parsed pattern. Case folding is already applied to every `char` set. */
export type Node =
  | { readonly kind: "char"; readonly set: CharSet }
  | { readonly kind: "seq"; readonly items: readonly Node[] }
  | { readonly kind: "alt"; readonly options: readonly Node[] }
  | {
      readonly kind: "group";
      readonly capture: boolean;
      /** 1-based number of a capturing group, 0 for a non-capturing one. */
      readonly index: number;
      readonly name?: string;
      readonly node: Node;
    }
  | {
      readonly kind: "repeat";
      readonly node: Node;
      readonly min: number;
      /** null means no upper bound. */
      readonly max: number | null;
      readonly lazy: boolean;
    }
  | { readonly kind: "assert"; readonly what: "start" | "end" | "wordBoundary" | "notWordBoundary" }
  | { readonly kind: "look"; readonly negative: boolean; readonly node: Node };
