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

const genuine=run(); assert.equal(genuine.valid,true);
const forged=run(body(),{signer:new Uint8Array(32).fill(8)}); assert.equal(forged.valid,false);
console.log(JSON.stringify({demo:'offline fixture, never fund these public test keys',genuine:genuine.valid,wrongSignature:forged.valid,settlement:genuine.settlement,broadcasts:0},null,2));
