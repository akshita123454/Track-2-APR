const TOKEN_PATTERN = /[\p{L}]+|[\p{N}]+/gu;

export function tokenizeComponent(component: string): readonly string[] {
  return component.match(TOKEN_PATTERN) ?? [];
}

export function tokenizePackageName(
  scope: string | undefined,
  basename: string,
): readonly string[] {
  return [
    ...(scope === undefined ? [] : tokenizeComponent(scope)),
    ...tokenizeComponent(basename),
  ];
}
