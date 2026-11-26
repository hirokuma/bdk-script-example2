//! HTLCのテスト(オフライン)。
//! `Htlc::new()`内のトランザクションサイズ見積りが、実際に署名した
//! トランザクションのサイズと一致すること、feeがそれと整合することを確認する。

use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{
        Amount, Network, NetworkKind, OutPoint, Sequence, Transaction, TxOut,
        bip32::Xpriv,
        hashes::{Hash, sha256},
        secp256k1::XOnlyPublicKey,
    },
    template::{Bip86, DescriptorTemplate},
};

use super::{Htlc, HtlcError};

const NETWORK: Network = Network::Regtest;
const HTLC_CSV: u32 = 16;
const CLAIM_INDEX: u32 = 0;
const REFUND_INDEX: u32 = 10;
const PREV_VALUE_SATS: u64 = 100_000;

/// claimルートのwitness各要素長(sig, preimage, leaf script, control block)。
/// control blockは33byte + leafパス32byte(leaf2本・深さ1) = 65byte。
const EXPECTED_CLAIM_WITNESS_LENS: [usize; 4] = [64, 32, 73, 65];
/// refundルートのwitness各要素長(sig, leaf script, control block)
const EXPECTED_REFUND_WITNESS_LENS: [usize; 3] = [64, 37, 65];

/// 見積もりweight(new()で計算)。実トランザクションと一致するかテストで確認する。
/// claim: base 94byte×4 + witness 239byte + segment 2byte = 617wu
const EXPECTED_CLAIM_WEIGHT: u64 = 617;
/// refund: base 94byte×4 + witness 170byte + segment 2byte = 548wu
const EXPECTED_REFUND_WEIGHT: u64 = 548;

/// 署名後のvsize(回帰確認用)
const EXPECTED_CLAIM_VSIZE: u64 = 155;
const EXPECTED_REFUND_VSIZE: u64 = 137;

/// 1.0 sat/vB時のfee。ceil(250 sat/kwu × weight / 1000)
const EXPECTED_CLAIM_FEE_SATS: u64 = 155;
const EXPECTED_REFUND_FEE_SATS: u64 = 137;

struct Fixtures {
    claim_wallet: Wallet,
    refund_wallet: Wallet,
    claim_xonly: XOnlyPublicKey,
    refund_xonly: XOnlyPublicKey,
    preimage: [u8; 32],
    preimage_hash: sha256::Hash,
}

fn fixtures() -> Fixtures {
    let claim_wallet = wallet([1u8; 32]);
    let refund_wallet = wallet([2u8; 32]);
    let claim_xonly = xonly_of(&claim_wallet, CLAIM_INDEX);
    let refund_xonly = xonly_of(&refund_wallet, REFUND_INDEX);
    let preimage = [0x42u8; 32];
    let preimage_hash = sha256::Hash::hash(&preimage);

    Fixtures {
        claim_wallet,
        refund_wallet,
        claim_xonly,
        refund_xonly,
        preimage,
        preimage_hash,
    }
}

fn wallet(seed: [u8; 32]) -> Wallet {
    let kind = NetworkKind::from(NETWORK);
    let xprv = Xpriv::new_master(NETWORK, &seed).expect("master key");
    let (descriptor, key_map, _) = Bip86(xprv, KeychainKind::External)
        .build(kind)
        .expect("external descriptor");
    let (change_descriptor, change_key_map, _) = Bip86(xprv, KeychainKind::Internal)
        .build(kind)
        .expect("internal descriptor");

    Wallet::create(
        descriptor.to_string_with_secret(&key_map),
        change_descriptor.to_string_with_secret(&change_key_map),
    )
    .network(NETWORK)
    .create_wallet_no_persist()
    .expect("wallet")
}

fn xonly_of(wallet: &Wallet, index: u32) -> XOnlyPublicKey {
    let addr_info = wallet.peek_address(KeychainKind::External, index);
    super::convert_xonly_pubkey(wallet, &addr_info).expect("xonly pubkey")
}

fn witness_item_lens(tx: &Transaction) -> Vec<usize> {
    let witness = &tx.input[0].witness;
    (0..witness.len())
        .map(|i| witness.nth(i).expect("witness item").len())
        .collect()
}

/// HTLCアドレスへの入金を模したutxo(前出力)
fn prev_txout_of(htlc: &Htlc<'_>) -> TxOut {
    let htlc_address = htlc.address(NETWORK).expect("address");
    TxOut {
        value: Amount::from_sat(PREV_VALUE_SATS),
        script_pubkey: htlc_address.script_pubkey(),
    }
}

#[test]
fn claim_tx_vsize_and_fee() {
    let f = fixtures();
    let htlc = Htlc::new(
        &f.claim_wallet,
        f.preimage_hash,
        HTLC_CSV,
        CLAIM_INDEX,
        f.claim_xonly,
        REFUND_INDEX,
        f.refund_xonly,
    )
    .expect("htlc");
    let prev_txout = prev_txout_of(&htlc);

    let tx = htlc
        .create_claim_tx(OutPoint::null(), &prev_txout, 0, f.preimage, 1.0)
        .expect("claim tx");

    assert_eq!(tx.input[0].sequence, Sequence::MAX);
    assert_eq!(witness_item_lens(&tx), EXPECTED_CLAIM_WITNESS_LENS);

    // new()での見積もり(weight)と署名後の実weightが一致すること
    assert_eq!(tx.weight().to_wu(), EXPECTED_CLAIM_WEIGHT);
    assert_eq!(tx.vsize() as u64, EXPECTED_CLAIM_VSIZE);

    // feeは実weight基準(ceil(sat/kwu × wu / 1000))で控除される
    assert_eq!(
        tx.output[0].value.to_sat(),
        PREV_VALUE_SATS - EXPECTED_CLAIM_FEE_SATS
    );
}

#[test]
fn refund_tx_vsize_and_fee() {
    let f = fixtures();
    // main.rsと同じく、refundルートではHTLCをrefundウォレット側に持たせる
    let htlc = Htlc::new(
        &f.refund_wallet,
        f.preimage_hash,
        HTLC_CSV,
        CLAIM_INDEX,
        f.claim_xonly,
        REFUND_INDEX,
        f.refund_xonly,
    )
    .expect("htlc");
    let prev_txout = prev_txout_of(&htlc);

    let tx = htlc
        .create_refund_tx(OutPoint::null(), &prev_txout, 0, 1.0)
        .expect("refund tx");

    assert_eq!(tx.input[0].sequence, Sequence(HTLC_CSV));
    assert_eq!(witness_item_lens(&tx), EXPECTED_REFUND_WITNESS_LENS);

    assert_eq!(tx.weight().to_wu(), EXPECTED_REFUND_WEIGHT);
    assert_eq!(tx.vsize() as u64, EXPECTED_REFUND_VSIZE);

    assert_eq!(
        tx.output[0].value.to_sat(),
        PREV_VALUE_SATS - EXPECTED_REFUND_FEE_SATS
    );
}

#[test]
fn fee_follows_fee_rate_using_estimated_weight() {
    let f = fixtures();
    let htlc = Htlc::new(
        &f.claim_wallet,
        f.preimage_hash,
        HTLC_CSV,
        CLAIM_INDEX,
        f.claim_xonly,
        REFUND_INDEX,
        f.refund_xonly,
    )
    .expect("htlc");
    let prev_txout = prev_txout_of(&htlc);

    for fee_rate in [0.5, 1.0, 2.5, 10.0] {
        let tx = htlc
            .create_claim_tx(OutPoint::null(), &prev_txout, 0, f.preimage, fee_rate)
            .expect("claim tx");

        // weight基準のfeeは ceil(sat/kwu × wu / 1000)。丸めは切り上げ。
        let expected_fee = (fee_rate * tx.weight().to_wu() as f64 / 4.0).ceil() as u64;
        assert_eq!(
            PREV_VALUE_SATS - tx.output[0].value.to_sat(),
            expected_fee,
            "fee_rate={fee_rate}"
        );
    }
}

#[test]
fn claim_tx_with_wrong_preimage_fails() {
    let f = fixtures();
    let htlc = Htlc::new(
        &f.claim_wallet,
        f.preimage_hash,
        HTLC_CSV,
        CLAIM_INDEX,
        f.claim_xonly,
        REFUND_INDEX,
        f.refund_xonly,
    )
    .expect("htlc");
    let prev_txout = prev_txout_of(&htlc);

    let result = htlc.create_claim_tx(OutPoint::null(), &prev_txout, 0, [0u8; 32], 1.0);
    assert!(matches!(result, Err(HtlcError::Witness(_))));
}
