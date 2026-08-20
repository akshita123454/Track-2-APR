const CONFUSABLES: Readonly<Record<string, string>> = Object.freeze({
  "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
  "а": "a", "ɑ": "a", "α": "a",
  "с": "c", "ϲ": "c",
  "е": "e", "ε": "e",
  "і": "i", "ı": "i", "ι": "i",
  "ј": "j",
  "κ": "k",
  "ⅼ": "l",
  "м": "m",
  "ո": "n",
  "о": "o", "ο": "o",
  "р": "p", "ρ": "p",
  "ѕ": "s",
  "т": "t", "τ": "t",
  "υ": "u",
  "ν": "v",
  "х": "x", "χ": "x",
  "у": "y", "γ": "y",
});

export function confusableSkeleton(value: string): string {
  return Array.from(value.normalize("NFC").toLocaleLowerCase("en-US"))
    .map((character) => CONFUSABLES[character] ?? character)
    .join("");
}

export function hasConfusableDifference(left: string, right: string): boolean {
  return left !== right && confusableSkeleton(left) === confusableSkeleton(right);
}
