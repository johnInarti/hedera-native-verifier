import { test } from 'node:test';
import assert from 'node:assert/strict';
import { proto } from '@hashgraph/proto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { verifyNativeHederaPayment } from '../src/index.mjs';

// Official protobuf encoding and real native signatures; no network or real funds.
const secret = new Uint8Array(32).fill(7);
const pub = ed25519.getPublicKey(secret);
const account = (n) => ({ accountNum: n });
const policy = { expectedNetwork: 'hedera:testnet', allowedNodeAccountIds: ['0.0.3'],
  buyerAccountId: '0.0.123', buyerPublicKeyHex: Buffer.from(pub).toString('hex'),
  maxFeeTinybar: '100000', nowSeconds: 1700000001 };
const requirements = { scheme: 'exact', network: 'hedera:testnet', asset: '0.0.0',
  amount: '60', payTo: '0.0.456', extra: { feePayer: '0.0.789' } };
function body() {
  return { transactionID: { accountID: account(789), transactionValidStart: { seconds: 1700000000, nanos: 0 } },
    nodeAccountID: account(3), transactionFee: 100000, transactionValidDuration: { seconds: 120 },
    cryptoTransfer: { transfers: { accountAmounts: [
      { accountID: account(123), amount: -60 }, { accountID: account(456), amount: 60 },
    ] } } };
}
function encode(b, { signer = secret, rawBody, mutateSigned, mutateEnvelope, count = 1 } = {}) {
  const bodyBytes = rawBody ?? proto.TransactionBody.encode(b).finish();
  const signed = { bodyBytes, sigMap: { sigPair: [{ pubKeyPrefix: pub, ed25519: ed25519.sign(bodyBytes, signer) }] } };
  mutateSigned?.(signed);
  const tx = { signedTransactionBytes: proto.SignedTransaction.encode(signed).finish() };
  mutateEnvelope?.(tx);
  return Buffer.from(proto.TransactionList.encode({ transactionList: Array.from({ length: count }, () => tx) }).finish()).toString('base64');
}
function run(b = body(), options = {}, r = requirements, p = policy) {
  return verifyNativeHederaPayment({ transactionBase64: encode(b, options), requirements: r }, p);
}
test('valid native HBAR with real Ed25519 signature; settlement remains unproven', () => {
  const result = run(); assert.equal(result.valid, true, JSON.stringify(result));
  assert.equal(result.settlement, 'UNPROVEN');
});
test('valid single HTS fungible transfer', () => {
  const b = body(); const transfers = b.cryptoTransfer.transfers.accountAmounts;
  b.cryptoTransfer = { tokenTransfers: [{ token: { tokenNum: 999 }, transfers }] };
  const result = run(b, {}, { ...requirements, asset: '0.0.999' });
  assert.equal(result.valid, true, JSON.stringify(result));
});
for (const [name, mutate] of [
  ['wrong recipient', b => { b.cryptoTransfer.transfers.accountAmounts[1].accountID = account(457); }],
  ['extra recipient', b => { b.cryptoTransfer.transfers.accountAmounts.push({ accountID: account(457), amount: 1 }); }],
  ['wrong amount', b => { b.cryptoTransfer.transfers.accountAmounts[0].amount = -61; b.cryptoTransfer.transfers.accountAmounts[1].amount = 61; }],
  ['sponsor debited', b => { b.cryptoTransfer.transfers.accountAmounts[0].accountID = account(789); }],
  ['wrong fee payer', b => { b.transactionID.accountID = account(124); }],
  ['fee above maximum', b => { b.transactionFee = 100001; }],
  ['unapproved node', b => { b.nodeAccountID = account(4); }],
  ['scheduled', b => { b.transactionID.scheduled = true; }],
  ['child nonce', b => { b.transactionID.nonce = 1; }],
  ['expired', b => { b.transactionID.transactionValidStart.seconds -= 200; }],
  ['future', b => { b.transactionID.transactionValidStart.seconds += 200; }],
  ['duration exceeded', b => { b.transactionValidDuration.seconds = 121; }],
  ['NFT hidden', b => { b.cryptoTransfer.tokenTransfers = [{ token: { tokenNum: 999 }, nftTransfers: [{ senderAccountID: account(123), receiverAccountID: account(456), serialNumber: 1 }] }]; }],
  ['allowance', b => { b.cryptoTransfer.transfers.accountAmounts[0].isApproval = true; }],
  ['alias', b => { b.cryptoTransfer.transfers.accountAmounts[1].accountID = { alias: new Uint8Array(20).fill(1) }; }],
  ['mixed operation oneof', b => { b.cryptoCreateAccount = { initialBalance: 1 }; }],
]) test('reject ' + name + ' even when correctly signed', () => {
  const b = body(); mutate(b); assert.equal(run(b).valid, false);
});
test('wrong signature key is rejected', () => assert.equal(run(body(), { signer: new Uint8Array(32).fill(8) }).valid, false));
test('unsigned body rejected', () => assert.equal(run(body(), { mutateSigned: s => { s.sigMap.sigPair = []; } }).valid, false));
test('short key prefix rejected', () => assert.equal(run(body(), { mutateSigned: s => { s.sigMap.sigPair[0].pubKeyPrefix = pub.slice(0, 4); } }).valid, false));
test('multiple node variants explicitly unsupported', () => assert.equal(run(body(), { count: 2 }).valid, false));
test('deprecated mixed envelope rejected', () => assert.equal(run(body(), { mutateEnvelope: t => { t.bodyBytes = new Uint8Array([0]); } }).valid, false));
test('unknown body protobuf field rejected even with a valid signature', () => {
  const raw = proto.TransactionBody.encode(body()).finish();
  // Unknown field127 varint1. Canonical decoder roundtrip must not silently discard it.
  const rawBody = Buffer.concat([raw, Buffer.from([0xf8, 0x07, 0x01])]);
  assert.equal(run(body(), { rawBody }).valid, false);
});
test('duplicate body scalar rejected', () => {
  const raw = proto.TransactionBody.encode(body()).finish();
  const extra = proto.TransactionBody.encode({ transactionFee: 100000 }).finish();
  assert.equal(run(body(), { rawBody: Buffer.concat([raw, extra]) }).valid, false);
});
test('network and method cannot silently change', () => {
  assert.equal(run(body(), {}, { ...requirements, network: 'hedera:mainnet' }).valid, false);
  assert.equal(run(body(), {}, { ...requirements, extra: { ...requirements.extra, assetTransferMethod: 'transferExecutor' }, assetTransferMethod: 'transferExecutor' }).valid, false);
});
test('caller cannot supply its own trusted buyer key', () => {
  assert.equal(run(body(), {}, requirements, { ...policy, buyerPublicKeyHex: Buffer.from(ed25519.getPublicKey(new Uint8Array(32).fill(8))).toString('hex') }).valid, false);
});
test('malformed or excessive base64 rejects without throwing', () => {
  for (const transactionBase64 of ['', 'AA', '!!!', 'A'.repeat(140000)]) {
    assert.equal(verifyNativeHederaPayment({ transactionBase64, requirements }, policy).valid, false);
  }
});
