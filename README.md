# FractalAI Hedera native verifier — experimental beta

Restricted native transaction checks for an x402 Hedera `cryptoTransfer`, plus a read-only Mirror receipt observer. Uses the official `@hashgraph/proto`2.25.0 encoder/decoder and real Ed25519 verification. No wallet keys, signing, sponsorship or broadcast API is provided. This is not a complete facilitator or an official Hedera product.

Publication status: local release candidate; npm publication not completed. Do not assume an npm install command for this name/version works until the registry confirms publication. Node>=20.19.0.

## Run the candidate

From this directory:

```sh
npm ci --ignore-scripts
npm test
npm run demo
npm pack --ignore-scripts
```

The demo uses public development keys and protobuf fixtures: genuine native signatures, no network, no funds. Never fund those keys. A consumer can install the generated `fractalai-hedera-native-verifier-0.1.0-beta.1.tgz` locally with `npm install /path/to/file.tgz --ignore-scripts`.

Local validation: 53 passing tests, including 1,280 single-bit changes to one signed fixture, 160 truncations, 256 suffixes, 500 seeded malformed inputs and 100 concurrent receipt observations. These bounded cases are not an exhaustive audit. The separate repository integration harness additionally exercises real ML-DSA authority with native Ed25519; that authority module is not bundled here.

## Native SDK

```js
import { verifyNativeHederaPayment } from '@fractalai/hedera-native-verifier';
const native = verifyNativeHederaPayment({
  transactionBase64: paymentPayload.payload.transaction,
  requirements,
}, {
  expectedNetwork: 'hedera:testnet',
  allowedNodeAccountIds: ['0.0.3'],
  buyerAccountId: trustedBuyerAccountId,
  buyerPublicKeyHex: independentlyVerifiedBuyerEd25519Key,
  maxFeeTinybar: '100000',
  nowSeconds: Math.floor(Date.now() / 1000),
});
if (!native.valid) throw new Error(native.reason);
```

Use operator-controlled policy, node allowlists and account-key bindings obtained independently of the buyer payload. A key supplied by the requester cannot establish ownership of a Hedera account. The package does not refresh keys from the network: account rotation and current account authority must be checked by the integrating facilitator.

Supported profile: one TransactionList variant, numeric entity IDs, exactly one buyer debit and one recipient credit, HBAR or one HTS fungible token, exact atomic amount, fee maximum, node allowlist, validity duration<=120seconds, one full-prefix Ed25519 buyer signature over the original bodyBytes. Unknown/duplicate/noncanonical protobuf fields, aliases, allowances, NFTs, extra recipients/assets, multi-node variants, contract methods, threshold keys and other signature formats are rejected rather than guessed. This restrictive profile will reject some otherwise valid Hedera transactions.

The transaction body has no native network identifier: network binding relies on the operator's selected network, node/account configuration and eventual submission route. It is not cryptographic cross-network replay protection. Body and partially-signed-transaction SHA384 values are returned separately. Adding the sponsor signature changes the final transaction hash.

## Compose with Fractal PQC authority

The existing x402 witness SDK's `authorizeHederaPayment(request, policy)` verifies the ML-DSA mandate and exact payment binding. The new verifier adds native transaction checks. A relying party must require **both** results before reserving authoritative budget and forwarding the exact same immutable bytes to a configured facilitator. Do not pass changed payloads between gates. This candidate does not replace the authority ledger, authenticate arbitrary callback results, or provide durable reservations.

Native Hedera Ed25519 is classical cryptography. Fractal's separate PQC mandate/evidence layer does not convert Hedera consensus or account keys into post-quantum cryptography. This package itself verifies native Ed25519, not ML-DSA.

## Read-only receipt observation

```js
import { createSettlementObserver } from '@fractalai/hedera-native-verifier/settlement-observer';
const observer = createSettlementObserver({ network: 'testnet' });
const receipt = await observer.observe({
  transactionId: finalSubmittedTransactionId,
  feePayer: sponsorAccountId, buyer: buyerAccountId,
  asset: requirements.asset, amount: requirements.amount, recipient: requirements.payTo,
  expectedTransactionHash: finalSubmittedSha384Base64,
});
```

Supply the **final submitted** SHA384 hash, not the pre-sponsor hash or body hash. `CONFIRMED` means the configured Mirror index returned one matching SUCCESS receipt, not that this package independently validated consensus or reconstructed net transfers. Transfer verification remains UNPROVEN and `releaseReservation` stays false. Timeout, missing hash, absence, duplicate records and ambiguity remain UNKNOWN. Do not turn them into refunds, new payments or released budget automatically.

For a read-only live query, save the expectation object above as JSON (public metadata only) and run `node examples/observe.mjs testnet expected-public-transaction.json`. No account key is needed. A successful lookup is not evidence that this SDK submitted or economically verified that payment.

Still required before production sponsorship: live account-key lookup and recipient-signature requirements, balance/token-association/custom-fee checks, replay protection, durable concurrency/recovery, official facilitator integration, controlled network transaction evidence, independent security review and monitoring.

## Primary references

- [x402 Hedera exact specification](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_hedera.md)
- [Hiero JavaScript SDK/protobufs](https://github.com/hiero-ledger/hiero-sdk-js)
- [Hedera Mirror transaction REST API](https://docs.hedera.com/reference/rest-api/transactions)

The profile is deliberately narrower than the specification. No affiliation, adoption, audit or certification is claimed.
