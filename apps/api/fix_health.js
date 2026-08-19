const fs = require('fs');
let c = fs.readFileSync('src/api/routes/health.ts', 'utf8');
const start = c.indexOf('async function checkDatabase(');
const end = c.indexOf('export async function', start);
c = c.substring(0, start) + \sync function checkDatabase(
  database: Pick<Driver, 'session'>,
  timeoutMs: number,
): Promise<boolean> {
  const session =
    database.session();

  try {
    await session.run(
      'MATCH (n) RETURN n.id AS id LIMIT 1',
      {},
      {
        timeout: timeoutMs,
      },
    );

    return true;
  } catch {
    return false;
  } finally {
    await session.close();
  }
}

\ + c.substring(end);
fs.writeFileSync('src/api/routes/health.ts', c);
