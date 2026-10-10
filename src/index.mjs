/**
 * Restricted native Hedera verifier. One TransactionList variant; numeric IDs;
 * two-party HBAR or one fungible HTS token; one full-prefix Ed25519 buyer signature.
 * No signing, submission, settlement proof, live key lookup or native PQC claim.
 * Sponsor/recipient signatures, balances, associations, custom token fees and
 * consensus acceptance are NOT verified. Caller supplies trusted account-key map,
 * expected network/node allowlist, clock and fee limit independently of the payload.
 * Network is policy-pinned: TransactionBody itself does not encode a network ID.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { proto } from '@hashgraph/proto';
import { ed25519 } from '@noble/curves/ed25519.js';

const MAX = (1n << 63n) - 1n;
const BODY_FIELDS = new Set(['transactionID', 'nodeAccountID', 'transactionFee', 'transactionValidDuration', 'memo', 'cryptoTransfer']);
class Rejected extends Error {}
const fail = (reason) => { throw new Rejected(reason); };
function allowed(object, fields, generatedEmptyArrays = []) {
  if (!object || typeof object !== 'object') fail('required_message_missing');
  for (const key of Object.keys(object)) {
    if (fields.has(key)) continue;
    // protobufjs constructors materialize empty repeated fields even when absent.
    if (generatedEmptyArrays.includes(key) && Array.isArray(object[key]) && object[key].length === 0) continue;
    fail('unsupported_message_field');
  }
}
function number(value, { positive = false, signed = false } = {}) {
  let text;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('invalid_integer');
    text = String(value);
  } else if (typeof value === 'bigint' || typeof value === 'string') text = String(value);
  else if (value && typeof value.toString === 'function') text = value.toString();
  else fail('invalid_integer');
  if (!/^-?(?:0|[1-9][0-9]*)$/.test(text) || text.length > 21) fail('invalid_integer');
  const n = BigInt(text);
  if (n > MAX || n < (signed ? -MAX : 0n) || (positive && n <= 0n)) fail('integer_out_of_range');
  return n;
}
function entityString(text, { zero = false } = {}) {
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(text)) fail('numeric_entity_required');
  const pieces = text.split('.').map(part => number(part));
  if (!zero && pieces[2] === 0n) fail('zero_entity_forbidden');
  return pieces.join('.');
}
function account(id) {
  allowed(id, new Set(['shardNum', 'realmNum', 'accountNum']));
  if (!Object.hasOwn(id, 'accountNum')) fail('numeric_account_required');
  return entityString(`${number(id.shardNum ?? 0)}.${number(id.realmNum ?? 0)}.${number(id.accountNum)}`);
}
function token(id) {
  allowed(id, new Set(['shardNum', 'realmNum', 'tokenNum']));
  if (!Object.hasOwn(id, 'tokenNum')) fail('numeric_token_required');
  return entityString(`${number(id.shardNum ?? 0)}.${number(id.realmNum ?? 0)}.${number(id.tokenNum)}`);
}
function decode(type, bytes, code) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 6144) fail('transaction_size_invalid');
  let value;
  try { value = type.decode(bytes); } catch { fail('protobuf_decode_failed'); }
  const encoded = type.encode(value).finish();
  if (encoded.length !== bytes.length || !timingSafeEqual(encoded, bytes)) fail(code);
  return value;
}
function transfers(entries, buyer, recipient, amount) {
  if (!Array.isArray(entries) || entries.length !== 2) fail('exact_two_transfers_required');
  const observed = entries.map(entry => {
    allowed(entry, new Set(['accountID', 'amount']));
    return { account: account(entry.accountID), amount: number(entry.amount, { signed: true }) };
  });
  if (observed.filter(entry => entry.account === buyer && entry.amount === -amount).length !== 1
      || observed.filter(entry => entry.account === recipient && entry.amount === amount).length !== 1) fail('transfer_purchase_mismatch');
}

export function verifyNativeHederaPayment(request, policy) {
  try {
    request = structuredClone(request);
    policy = structuredClone(policy);
    const requirements = request?.requirements;
    if (!policy || !['hedera:mainnet', 'hedera:testnet'].includes(policy.expectedNetwork)
      || requirements?.scheme !== 'exact' || requirements.network !== policy.expectedNetwork) fail('network_policy_mismatch');
    for (const method of [requirements.assetTransferMethod, requirements.extra?.assetTransferMethod]) {
      if (method !== undefined && method !== 'cryptoTransfer') fail('unsupported_asset_transfer_method');
    }
    if (typeof requirements.amount !== 'string' || !/^[1-9][0-9]*$/.test(requirements.amount)) fail('canonical_amount_required');
    const buyer = entityString(policy.buyerAccountId);
    const recipient = entityString(requirements.payTo);
    const sponsor = entityString(requirements.extra?.feePayer);
    const asset = entityString(requirements.asset, { zero: true });
    if (buyer === recipient || sponsor === buyer) fail('sponsored_two_party_profile_required');
    const amount = number(requirements.amount, { positive: true });
    const feeLimit = number(policy.maxFeeTinybar);
    if (!Number.isSafeInteger(policy.nowSeconds) || policy.nowSeconds < 0) fail('explicit_clock_required');
    if (!Array.isArray(policy.allowedNodeAccountIds) || policy.allowedNodeAccountIds.length < 1 || policy.allowedNodeAccountIds.length > 100) fail('node_allowlist_required');
    const nodes = policy.allowedNodeAccountIds.map(id => entityString(id));
    if (typeof policy.buyerPublicKeyHex !== 'string' || !/^[a-f0-9]{64}$/i.test(policy.buyerPublicKeyHex)) fail('pinned_buyer_key_required');
    const publicKey = Buffer.from(policy.buyerPublicKeyHex, 'hex');
    const text = request.transactionBase64;
    if (typeof text !== 'string' || text.length === 0 || text.length > 32768 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) fail('canonical_transaction_base64_required');
    const raw = Buffer.from(text, 'base64');
    if (raw.toString('base64') !== text) fail('canonical_transaction_base64_required');
    const list = decode(proto.TransactionList, raw, 'noncanonical_transaction_list');
    allowed(list, new Set(['transactionList']));
    if (list.transactionList.length !== 1) fail('single_transaction_variant_required');
    const transaction = list.transactionList[0];
    allowed(transaction, new Set(['signedTransactionBytes']));
    const signedBytes = transaction.signedTransactionBytes;
    const signed = decode(proto.SignedTransaction, signedBytes, 'noncanonical_signed_transaction');
    allowed(signed, new Set(['bodyBytes', 'sigMap']));
    const bodyBytes = signed.bodyBytes;
    const body = decode(proto.TransactionBody, bodyBytes, 'noncanonical_transaction_body');
    allowed(body, BODY_FIELDS, ['maxCustomFees']);
    const txid = body.transactionID;
    allowed(txid, new Set(['transactionValidStart', 'accountID']));
    if (account(txid.accountID) !== sponsor) fail('fee_sponsor_mismatch');
    const node = account(body.nodeAccountID);
    if (!nodes.includes(node)) fail('node_not_allowed');
    const fee = number(body.transactionFee);
    if (fee > feeLimit) fail('transaction_fee_limit_exceeded');
    const start = txid.transactionValidStart;
    allowed(start, new Set(['seconds', 'nanos']));
    const seconds = number(start.seconds ?? 0);
    const nanos = start.nanos ?? 0;
    if (!Number.isInteger(nanos) || nanos < 0 || nanos > 999999999) fail('invalid_transaction_timestamp');
    allowed(body.transactionValidDuration, new Set(['seconds']));
    const duration = number(body.transactionValidDuration.seconds, { positive: true });
    if (duration > 120n) fail('duration_outside_restricted_profile');
    if (requirements.maxTimeoutSeconds !== undefined &&
      (!Number.isSafeInteger(requirements.maxTimeoutSeconds) || requirements.maxTimeoutSeconds < 1 ||
        duration > BigInt(requirements.maxTimeoutSeconds))) fail('duration_exceeds_requirements');
    const nowNs = BigInt(policy.nowSeconds) * 1000000000n;
    const startNs = seconds * 1000000000n + BigInt(nanos);
    if (startNs > nowNs || nowNs >= startNs + duration * 1000000000n) fail('transaction_outside_valid_window');
    if (typeof body.memo !== 'string' || Buffer.byteLength(body.memo, 'utf8') > 100 || body.memo.includes('\0')) fail('memo_outside_restricted_profile');
    const movement = body.cryptoTransfer;
    allowed(movement, new Set(['transfers', 'tokenTransfers']));
    if (asset === '0.0.0') {
      if (movement.tokenTransfers.length !== 0) fail('unexpected_token_transfers');
      allowed(movement.transfers, new Set(['accountAmounts']));
      transfers(movement.transfers.accountAmounts, buyer, recipient, amount);
    } else {
      if (Object.hasOwn(movement, 'transfers')) fail('unexpected_hbar_transfers');
      if (movement.tokenTransfers.length !== 1) fail('single_token_transfer_required');
      const ft = movement.tokenTransfers[0];
      allowed(ft, new Set(['token', 'transfers']), ['nftTransfers']);
      if (token(ft.token) !== asset) fail('token_asset_mismatch');
      transfers(ft.transfers, buyer, recipient, amount);
    }
    allowed(signed.sigMap, new Set(['sigPair']));
    if (signed.sigMap.sigPair.length !== 1) fail('single_buyer_signature_required');
    const pair = signed.sigMap.sigPair[0];
    allowed(pair, new Set(['pubKeyPrefix', 'ed25519']));
    if (!(pair.pubKeyPrefix instanceof Uint8Array) || pair.pubKeyPrefix.length !== 32 || !timingSafeEqual(pair.pubKeyPrefix, publicKey)) fail('buyer_signature_key_mismatch');
    if (!(pair.ed25519 instanceof Uint8Array) || pair.ed25519.length !== 64
      || !ed25519.verify(pair.ed25519, bodyBytes, publicKey, { zip215: false })) fail('buyer_signature_invalid');
    return Object.freeze({ valid: true, native_transaction: 'VERIFIED_RESTRICTED_PROFILE', settlement: 'UNPROVEN',
      account_key_source: 'OPERATOR_PINNED_NOT_LIVE', network_binding: 'POLICY_PINNED_NOT_ENCODED',
      network: policy.expectedNetwork, buyer, recipient, sponsor, asset, amount: amount.toString(),
      nodeAccountId: node, transactionFeeTinybar: fee.toString(),
      transactionId: `${sponsor}@${seconds}.${String(nanos).padStart(9, '0')}`,
      bodySha384: createHash('sha384').update(bodyBytes).digest('hex'),
      signedTransactionSha384: createHash('sha384').update(signedBytes).digest('hex'),
      sponsor_signature: 'UNPROVEN', token_custom_fees: 'UNPROVEN', consensus_acceptance: 'UNPROVEN' });
  } catch (error) {
    return Object.freeze({ valid: false, reason: error instanceof Rejected ? error.message : 'malformed_or_unsupported_transaction' });
  }
}
