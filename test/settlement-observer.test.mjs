import test from 'node:test';
import assert from 'node:assert/strict';
import { createSettlementObserver } from '../src/settlement-observer.mjs';

const digest = Buffer.alloc(48, 7).toString('base64');
const expected = { transactionId: '0.0.123@1700000000.42', feePayer: '0.0.123',
  buyer: '0.0.456', recipient: '0.0.789', asset: '0.0.0', amount: '100', expectedTransactionHash: digest };
const record = { transaction_id: '0.0.123-1700000000-000000042', transaction_hash: digest,
  scheduled: false, nonce: 0, name: 'CRYPTOTRANSFER', result: 'SUCCESS', consensus_timestamp: '1700000001.000000001' };
const json = data => new Response(JSON.stringify(data), { status: 200 });
const run = (data, exp = expected, options = {}) => createSettlementObserver({ network: 'testnet',
  fetchImpl: async () => json(data), ...options }).observe(exp);

test('confirmed receipt remains unproven economic settlement; pinned GET and abort', async () => {
  let seen;
  const output = await run({ transactions: [record] }, expected, { fetchImpl: async (url, options) => {
    seen = { url, options }; return json({ transactions: [record] });
  } });
  assert.equal(output.status, 'CONFIRMED');
  assert.equal(output.transferVerification, 'UNPROVEN');
  assert.equal(output.settlementVerified, false);
  assert.equal(output.releaseReservation, false);
  assert.match(output.trustModel, /not_cryptographic/);
  assert.equal(seen.url, 'https://testnet.mirrornode.hedera.com/api/v1/transactions/0.0.123-1700000000-000000042');
  assert.equal(seen.options.method, 'GET');
  assert.equal(seen.options.redirect, 'error');
  assert.equal(seen.options.credentials, 'omit');
  assert.equal(seen.options.signal.aborted, true);
  assert.deepEqual(seen.options.headers, { Accept: 'application/json' });
});
test('canonical mirror ID and mainnet mapping', async () => {
  let url;
  const output = await run({ transactions: [record] }, { ...expected, transactionId: record.transaction_id }, {
    network: 'mainnet', fetchImpl: async value => { url = value; return json({ transactions: [record] }); },
  });
  assert.equal(output.status, 'CONFIRMED');
  assert.match(url, /^https:\/\/mainnet-public\.mirrornode\.hedera\.com\//);
});
test('missing or malformed final hash never performs network request', async () => {
  for (const value of [undefined, '', 'a', `${digest}=`, Buffer.alloc(32).toString('base64')]) {
    let calls = 0;
    const output = await run({}, { ...expected, expectedTransactionHash: value }, {
      fetchImpl: async () => { calls++; throw Error('must not fetch'); },
    });
    assert.equal(output.status, 'UNKNOWN'); assert.equal(calls, 0);
  }
});
for (const [name, patch] of Object.entries({
  differentId: { transaction_id: '0.0.124-1700000000-000000042' },
  differentHash: { transaction_hash: Buffer.alloc(48, 8).toString('base64') },
  scheduled: { scheduled: true }, missingScheduled: { scheduled: undefined },
  child: { nonce: 1 }, missingNonce: { nonce: undefined },
  otherOperation: { name: 'CONTRACTCALL' }, noConsensus: { consensus_timestamp: undefined },
})) test(`reject record binding: ${name}`, async () => {
  assert.equal((await run({ transactions: [{ ...record, ...patch }] })).status, 'UNKNOWN');
});
test('duplicate submissions, empty records and pagination remain unknown', async () => {
  for (const data of [{ transactions: [] }, { transactions: [record, { ...record, result: 'DUPLICATE_TRANSACTION' }] },
    { transactions: [record], links: { next: '/more' } }, {}, { transactions: [null] }]) {
    assert.equal((await run(data)).status, 'UNKNOWN');
  }
});
test('explicit failure observed without releasing reservation; unknown results not final', async () => {
  const failed = await run({ transactions: [{ ...record, result: 'INSUFFICIENT_ACCOUNT_BALANCE' }] });
  assert.equal(failed.status, 'OBSERVED_FAILURE'); assert.equal(failed.releaseReservation, false);
  for (const result of ['UNKNOWN', 'BUSY', 'DUPLICATE_TRANSACTION', 'EVIL_PRIVATE_RESPONSE']) {
    const output = await run({ transactions: [{ ...record, result }] });
    assert.equal(output.status, 'UNKNOWN'); assert.equal(output.observedResult, undefined);
    assert.ok(!JSON.stringify(output).includes('EVIL_PRIVATE_RESPONSE'));
  }
});
test('transfer arrays cannot turn receipt observation into proof, including HTS', async () => {
  const output = await run({ transactions: [{ ...record, token_transfers: [], transfers: [] }] },
    { ...expected, asset: '0.0.999' });
  assert.equal(output.status, 'CONFIRMED'); assert.equal(output.transferVerification, 'UNPROVEN');
});
test('invalid inputs and fee payer mismatch rejected before transport', async () => {
  for (const patch of [{ transactionId: 'https://evil/' }, { transactionId: `${expected.transactionId}?scheduled=true` },
    { feePayer: '0.0.999' }, { amount: '-1' }, { amount: 100 }, { amount: '9223372036854775808' },
    { recipient: expected.buyer }, { asset: '0.0.alias' }, { buyer: '0.0.0' }]) {
    const output = await run({}, { ...expected, ...patch }, { fetchImpl: () => { throw Error('no'); } });
    assert.equal(output.reason, 'invalid_expectation');
  }
});
test('HTTP failures, redirects and exception secrets are not exposed', async () => {
  for (const fetchImpl of [async () => new Response('', { status: 404 }),
    async () => new Response('', { status: 429 }), async () => new Response('', { status: 302 }),
    async () => ({ redirected: true }), async () => { throw Error('SECRET_TOKEN_PRIVATE'); }]) {
    const output = await run({}, expected, { fetchImpl });
    assert.equal(output.status, 'UNKNOWN'); assert.ok(!JSON.stringify(output).includes('SECRET'));
  }
});
test('caps declared and streamed response sizes and rejects invalid JSON', async () => {
  for (const fetchImpl of [async () => new Response('private', { headers: { 'content-length': '1000' } }),
    async () => new Response('x'.repeat(1000)), async () => new Response('{private')]) {
    const output = await run({}, expected, { fetchImpl, maxResponseBytes: 32 });
    assert.equal(output.status, 'UNKNOWN'); assert.ok(!JSON.stringify(output).includes('private'));
  }
});
test('timeout covers transport that ignores abort and a stalled body stream', async () => {
  for (const fetchImpl of [() => new Promise(() => {}), async () => new Response(new ReadableStream({ start() {} }))]) {
    const output = await run({}, expected, { fetchImpl, timeoutMs: 10 });
    assert.equal(output.reason, 'timeout');
  }
});
test('invalid configuration rejected', () => {
  for (const options of [{ network: 'previewnet' }, { network: 'https://evil' }, { timeoutMs: 0 },
    { maxResponseBytes: Infinity }, { fetchImpl: null }]) {
    assert.throws(() => createSettlementObserver({ network: 'testnet', ...options }), /Invalid observer configuration/);
  }
});

test('caller hash mutation during fetch cannot replace snapshotted authorization', async () => {
  const input = { ...expected };
  const replacementHash = Buffer.alloc(48, 9).toString('base64');
  let finish;
  const observer = createSettlementObserver({ network: 'testnet', fetchImpl: () => new Promise(resolve => {
    finish = resolve;
  }) });
  const pending = observer.observe(input);
  input.expectedTransactionHash = replacementHash;
  const callerState = structuredClone(input);
  finish(json({ transactions: [{ ...record, transaction_hash: replacementHash }] }));
  const output = await pending;
  assert.equal(output.status, 'UNKNOWN');
  assert.equal(output.reason, 'record_binding_mismatch');
  assert.deepEqual(input, callerState);
});

test('non-cloneable expectations fail before transport without modifying input', async () => {
  const input = { ...expected, extra: () => {} };
  let calls = 0;
  const output = await run({}, input, { fetchImpl: () => { calls++; throw Error('must not fetch'); } });
  assert.equal(output.reason, 'invalid_expectation');
  assert.equal(calls, 0);
  assert.equal(input.expectedTransactionHash, digest);
  assert.equal(typeof input.extra, 'function');
});
