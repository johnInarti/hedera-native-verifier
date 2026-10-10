/**
 * Read-only receipt observation, NOT transfer verification or a consensus proof.
 * Reference: https://docs.hedera.com/reference/rest-api/transactions
 * Duplicate submissions can produce multiple records with the same ID. This
 * bounded observer rejects ambiguous responses rather than choosing one.
 * expectedTransactionHash MUST be the FINAL submitted transaction's SHA-384
 * (canonical base64), never a preflight body hash. Missing hash means UNKNOWN.
 * HBAR transfer lists include network fees; neither HBAR nor HTS economic effects
 * are validated here. No result authorizes delivery, signing or budget release.
 */
const BASES = Object.freeze({
  mainnet: 'https://mainnet-public.mirrornode.hedera.com',
  testnet: 'https://testnet.mirrornode.hedera.com',
});
const FAILURE_RESULTS = new Set([
  'INSUFFICIENT_ACCOUNT_BALANCE', 'INSUFFICIENT_PAYER_BALANCE',
  'INVALID_SIGNATURE', 'INVALID_ACCOUNT_ID', 'ACCOUNT_DELETED',
  'TOKEN_NOT_ASSOCIATED_TO_ACCOUNT', 'INSUFFICIENT_TOKEN_BALANCE',
  'ACCOUNT_FROZEN_FOR_TOKEN', 'ACCOUNT_KYC_NOT_GRANTED_FOR_TOKEN',
  'TOKEN_IS_PAUSED', 'TOKEN_WAS_DELETED', 'TRANSACTION_EXPIRED',
]);
const MAX_INT = (1n << 63n) - 1n;
function numeric(text) {
  return typeof text === 'string' && /^(0|[1-9][0-9]{0,18})$/.test(text) && BigInt(text) <= MAX_INT;
}
function entity(text, zero = false) {
  if (typeof text !== 'string') return false;
  const parts = text.split('.');
  return parts.length === 3 && parts.every(numeric) && (zero || parts[2] !== '0');
}
function canonicalId(text) {
  if (typeof text !== 'string' || text.length > 100) return null;
  const match = /^(\d+\.\d+\.\d+)(?:@(\d+)\.(\d{1,9})|-(\d+)-(\d{9}))$/.exec(text);
  if (!match || !entity(match[1])) return null;
  const seconds = match[2] ?? match[4];
  const nanos = match[3] ?? match[5];
  if (!numeric(seconds)) return null;
  // SDK's numeric nanos field is an integer, not a decimal fractional second.
  return { id: `${match[1]}-${seconds}-${nanos.padStart(9, '0')}`, payer: match[1] };
}
function hash(value) {
  return typeof value === 'string' && /^[A-Za-z0-9+/]{64}$/.test(value) &&
    Buffer.from(value, 'base64').length === 48 && Buffer.from(value, 'base64').toString('base64') === value;
}
function result(status, reason, network, extra = {}) {
  return Object.freeze({ status, reason, network,
    trustModel: 'trusted_mirror_index_not_cryptographic_consensus_proof',
    confirmationScope: 'transaction_receipt_only', transferVerification: 'UNPROVEN',
    settlementVerified: false, releaseReservation: false, ...extra });
}
async function boundedJson(response, cap) {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > cap)) throw new Error('response_limit');
  if (!response.body || typeof response.body.getReader !== 'function') throw new Error('invalid_response');
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('invalid_response');
      size += value.byteLength;
      if (size > cap) throw new Error('response_limit');
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  } finally {
    // Do not let a hostile/injected stream make cleanup wait indefinitely.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function createSettlementObserver({ network, fetchImpl = globalThis.fetch,
  timeoutMs = 5000, maxResponseBytes = 262144 } = {}) {
  if (!Object.hasOwn(BASES, network) || typeof fetchImpl !== 'function' ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 ||
      !Number.isInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 1048576) {
    throw new TypeError('Invalid observer configuration');
  }
  return Object.freeze({ async observe(expected) {
    const unknown = reason => result('UNKNOWN', reason, network);
    // Snapshot caller-owned policy before the first await. A concurrent caller
    // must not change the expected final hash while the mirror query is pending.
    try { expected = structuredClone(expected); }
    catch { return unknown('invalid_expectation'); }
    if (!expected || typeof expected !== 'object') return unknown('invalid_expectation');
    const parsed = canonicalId(expected.transactionId);
    if (!parsed || !entity(expected.feePayer) || parsed.payer !== expected.feePayer ||
        !entity(expected.buyer) || !entity(expected.recipient) || !entity(expected.asset, true) ||
        !numeric(expected.amount) || expected.amount === '0' || expected.buyer === expected.recipient) {
      return unknown('invalid_expectation');
    }
    if (expected.expectedTransactionHash === undefined) return unknown('final_submitted_hash_required');
    if (!hash(expected.expectedTransactionHash)) return unknown('invalid_final_submitted_hash');
    const controller = new AbortController();
    let timer;
    try {
      const work = async () => {
        const response = await fetchImpl(`${BASES[network]}/api/v1/transactions/${encodeURIComponent(parsed.id)}`, {
          method: 'GET', redirect: 'error', credentials: 'omit',
          headers: { Accept: 'application/json' }, signal: controller.signal,
        });
        if (response.redirected) return unknown('redirect_rejected');
        if (response.status === 404) return unknown('not_indexed');
        if (response.status !== 200) return unknown('mirror_unavailable');
        const data = await boundedJson(response, maxResponseBytes);
        if (!data || !Array.isArray(data.transactions) || data.transactions.length !== 1 ||
            (data.links?.next !== undefined && data.links.next !== null)) return unknown('ambiguous_response');
        const record = data.transactions[0];
        if (!record || record.transaction_id !== parsed.id || record.scheduled !== false || record.nonce !== 0 ||
            record.name !== 'CRYPTOTRANSFER' || !/^\d+\.\d{9}$/.test(record.consensus_timestamp ?? '') ||
            record.transaction_hash !== expected.expectedTransactionHash) return unknown('record_binding_mismatch');
        const extra = { transactionId: parsed.id, transactionHash: expected.expectedTransactionHash,
          consensusTimestamp: record.consensus_timestamp };
        if (record.result === 'SUCCESS') return result('CONFIRMED', 'mirror_success_receipt', network, extra);
        if (FAILURE_RESULTS.has(record.result)) return result('OBSERVED_FAILURE', 'mirror_failure_receipt', network,
          { ...extra, observedResult: record.result });
        return unknown('unrecognized_or_nonfinal_result');
      };
      return await Promise.race([work(), new Promise(resolve => {
        timer = setTimeout(() => { controller.abort(); resolve(unknown('timeout')); }, timeoutMs);
      })]);
    } catch {
      // Never echo remote response, URL details or exception text.
      return unknown('observation_unavailable');
    } finally { clearTimeout(timer); controller.abort(); }
  } });
}
