const fs = require('fs');
const files = [
  'src/db/persistence-smoke.ts',
  'src/db/persistence-service-smoke.ts',
  'src/analysis/fixtures/live-analysis-smoke.ts'
];
const template = \unction requireNumber(
  value: unknown,
  description: string,
): number {
  let converted = value;

  if (
    typeof value === 'object' &&
    value !== null &&
    'toNumber' in value &&
    typeof value.toNumber === 'function'
  ) {
    converted = value.toNumber();
  }

  if (
    typeof converted !== 'number' ||
    !Number.isSafeInteger(converted) ||
    converted < 0
  ) {
    throw new TypeError(
      \\\\\\ must be a nonnegative safe integer\\\,
    );
  }

  return converted as number;
}\;

files.forEach(f => {
  if (!fs.existsSync(f)) return;
  let content = fs.readFileSync(f, 'utf8');
  content = content.replace(/function requireNumber\([\s\S]*?return value as number;\n\}/m, template);
  content = content.replace(/function requireNumber\([\s\S]*?return value;\n\}/m, template);
  content = content.replace(/function requireSafeInteger\([\s\S]*?return value as number;\n\}/m, template.replace(/requireNumber/g, 'requireSafeInteger'));
  fs.writeFileSync(f, content);
});
