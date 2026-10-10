import { readFileSync } from 'node:fs';
import { createSettlementObserver } from '../src/settlement-observer.mjs';

// Only public transaction metadata belongs in this JSON. No wallet keys needed.
const [network, path] = process.argv.slice(2);
if (!['testnet', 'mainnet'].includes(network) || !path || process.argv.length !== 4) {
  console.error('Usage: node examples/observe.mjs testnet expected-public-transaction.json');
  process.exitCode = 2;
} else {
  try {
    const raw = readFileSync(path);
    if (raw.length > 16384) throw new Error('Input too large');
    const expected = JSON.parse(raw.toString('utf8'));
    const result = await createSettlementObserver({ network }).observe(expected);
    console.log(JSON.stringify(result, null, 2));
    if (result.status !== 'CONFIRMED') process.exitCode = 1;
  } catch {
    console.error('Could not read a bounded public transaction expectation JSON.');
    process.exitCode = 2;
  }
}
