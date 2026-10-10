import test from 'node:test';
import assert from 'node:assert/strict';
import { proto } from '@hashgraph/proto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { verifyNativeHederaPayment } from '../src/index.mjs';
import { createSettlementObserver } from '../src/settlement-observer.mjs';

// Public fixture key. These tests never connect to a network or hold funds.
const key = new Uint8Array(32).fill(19);
const pub = ed25519.getPublicKey(key);
const body = proto.TransactionBody.encode({
  transactionID: { accountID: { accountNum: 789 }, transactionValidStart: { seconds: 1700000000 } },
  nodeAccountID: { accountNum: 3 }, transactionFee: 100000,
  transactionValidDuration: { seconds: 120 },
  cryptoTransfer: { transfers: { accountAmounts: [
    { accountID: { accountNum: 123 }, amount: -60 },
    { accountID: { accountNum: 456 }, amount: 60 },
  ] } },
}).finish();
const raw = Buffer.from(proto.TransactionList.encode({ transactionList: [{
  signedTransactionBytes: proto.SignedTransaction.encode({ bodyBytes: body,
    sigMap: { sigPair: [{ pubKeyPrefix: pub, ed25519: ed25519.sign(body, key) }] },
  }).finish(),
}] }).finish());
const policy = { expectedNetwork: 'hedera:testnet', allowedNodeAccountIds: ['0.0.3'],
  buyerAccountId: '0.0.123', buyerPublicKeyHex: Buffer.from(pub).toString('hex'),
  maxFeeTinybar: '100000', nowSeconds: 1700000001 };
const requirements = { scheme: 'exact', network: 'hedera:testnet', asset: '0.0.0',
  amount: '60', payTo: '0.0.456', extra: { feePayer: '0.0.789' } };
const verify = bytes => verifyNativeHederaPayment({ transactionBase64: bytes.toString('base64'), requirements }, policy);

test('every single-bit mutation of this signed envelope fails closed', t => {
  assert.equal(verify(raw).valid, true);
  for (let i = 0; i < raw.length; i++) {
    for (let bit = 0; bit < 8; bit++) {
      const changed = Buffer.from(raw); changed[i] ^= 1 << bit;
      assert.equal(verify(changed).valid, false, `accepted byte ${i}, bit ${bit}`);
    }
  }
  t.diagnostic(`${raw.length * 8} single-bit mutations rejected; one fixture, not exhaustive fuzzing`);
});

test('every truncation and every single-byte suffix is rejected', t => {
  for (let length = 0; length < raw.length; length++) assert.equal(verify(raw.subarray(0, length)).valid, false);
  for (let byte = 0; byte < 256; byte++) assert.equal(verify(Buffer.concat([raw, Buffer.from([byte])])).valid, false);
  t.diagnostic(`${raw.length} truncations and 256 suffixes rejected`);
});

test('deterministic malformed-byte corpus never escapes the verifier', t => {
  let seed = 0x4022026;
  const next = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; };
  for (let sample = 0; sample < 500; sample++) {
    const bytes = Buffer.alloc(next() % 1024);
    for (let i = 0; i < bytes.length; i++) bytes[i] = next() & 255;
    assert.equal(verify(bytes).valid, false);
  }
  t.diagnostic('500 seeded malformed inputs rejected');
});

test('concurrent observations cannot accept a different request hash or release budget', async () => {
  const hash = Buffer.alloc(48, 7).toString('base64');
  const expected = { transactionId: '0.0.789@1700000000.0', feePayer: '0.0.789',
    buyer: '0.0.123', recipient: '0.0.456', asset: '0.0.0', amount: '60', expectedTransactionHash: hash };
  const observer = createSettlementObserver({ network: 'testnet', fetchImpl: async () => {
    await new Promise(resolve => setTimeout(resolve, 1));
    return new Response(JSON.stringify({ transactions: [{ transaction_id: '0.0.789-1700000000-000000000',
      transaction_hash: hash, scheduled: false, nonce: 0, name: 'CRYPTOTRANSFER',
      result: 'SUCCESS', consensus_timestamp: '1700000001.000000000' }] }));
  } });
  const outputs = await Promise.all(Array.from({ length: 100 }, (_, i) => observer.observe({ ...expected,
    expectedTransactionHash: i % 2 ? hash : Buffer.alloc(48, 8).toString('base64') })));
  outputs.forEach((output, i) => {
    assert.equal(output.status, i % 2 ? 'CONFIRMED' : 'UNKNOWN');
    assert.equal(output.releaseReservation, false);
    assert.equal(output.settlementVerified, false);
  });
});
