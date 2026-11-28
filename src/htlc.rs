use std::str::FromStr;

use bdk_wallet::{
    AddressInfo, KeychainKind, Wallet,
    bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
        Transaction, TxIn, TxOut, Weight, Witness, absolute,
        bip32::{ChildNumber, DerivationPath, Error as Bip32Error},
        hashes::{Hash, sha256},
        key::{
            Keypair,
            rand::{self, RngCore},
        },
        opcodes,
        script::Builder,
        secp256k1::{self, Message, XOnlyPublicKey},
        sighash::{Prevouts, SighashCache, TaprootError},
        taproot::{
            ControlBlock, LeafVersion, Signature as TaprootSig, TaprootBuilder,
            TaprootBuilderError, TaprootSpendInfo,
        },
        transaction,
    },
    keys::DescriptorSecretKey,
};
use hex::FromHexError;
use thiserror::Error;
use tracing::*;

use wallet_utils::log_err;

#[derive(Error, Debug)]
pub enum HtlcError {
    #[error("{0}")]
    FromHex(#[source] FromHexError),

    #[error("{0}")]
    TaprootBuilder(#[source] TaprootBuilderError),

    #[error("taproot builder is incomplete (no merkle root)")]
    TaprootBuilderIncomplete,

    #[error("{0}")]
    Taproot(#[source] TaprootError),

    #[error("{0}")]
    Secp(#[source] secp256k1::Error),

    #[error("{0}")]
    Bip32(#[source] Bip32Error),

    #[error("key error: {0}")]
    NoKey(&'static str),

    #[error("witness error: leaf_name={0}")]
    Witness(&'static str),
}

// pick as internal key a "Nothing Up My Sleeve" (NUMS) point
// TODO H + rG
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
const NUMS_XPUBKEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// 署名で使うsighashタイプ。署名とサイズ見積りの両方でこの値を使う。
const SIGHASH_TYPE: TapSighashType = TapSighashType::Default;

/// witnessに置くpreimageの長さ(claimルート)
const WITNESS_PREIMAGE_LEN: usize = 32;

/// tapscriptのwitnessに置くSchnorr署名の長さ(BIP341)。
/// SIGHASH_DEFAULT(0x00)はsighash byteなしの64byte、それ以外はsighash byte付きの65byte。
/// rust-bitcoinはこのルールを公開定数として持たないため、署名と同じSIGHASH_TYPEから導く。
const WITNESS_SIG_LEN: usize = match SIGHASH_TYPE {
    TapSighashType::Default => 64,
    _ => 65,
};

/// taprootのleaf 1本分。スクリプトと、そのleafで支払うために必要な情報をまとめる。
struct LeafSpend {
    script: ScriptBuf,
    control_block: ControlBlock,
    /// 署名に使うアドレス(ウォレットのExternal keychain)のindex
    addr_index: u32,
    /// 支払い先のP2TR出力スクリプト
    dest_script: ScriptBuf,
    /// 支払いトランザクションのnSequence
    sequence: Sequence,
    /// claimルートだけwitnessにpreimageを追加する
    with_preimage: bool,
    /// 支払いトランザクション(入力1・出力1・P2TR出力)のweight。
    /// witnessの長さはleafから決まるのでnew()で見積もっておく。
    weight: Weight,
}

impl LeafSpend {
    fn new(
        spend_info: &TaprootSpendInfo,
        name: &'static str,
        script: ScriptBuf,
        addr_index: u32,
        dest_script: ScriptBuf,
        sequence: Sequence,
        with_preimage: bool,
    ) -> Result<Self, HtlcError> {
        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| log_err!(HtlcError::Witness(name), "control block"))?;

        // fee計算に使うトランザクションサイズ(weight)はここで確定させる。
        // outpoint・前出力のscript_pubkey/valueはサイズに影響しない。
        let weight = estimate_spend_tx_weight(
            &dest_script,
            sequence,
            &witness_item_lens(script.len(), control_block.size(), with_preimage),
        );

        Ok(Self {
            script,
            control_block,
            addr_index,
            dest_script,
            sequence,
            with_preimage,
            weight,
        })
    }

    fn leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(&self.script, LeafVersion::TapScript)
    }
}

/// このleafを満たすwitnessの各要素の長さ(本体のみ)。
/// compact sizeプレフィックスはWitnessのシリアライズが付けるので扱わない。
fn witness_item_lens(
    script_len: usize,
    control_block_len: usize,
    with_preimage: bool,
) -> Vec<usize> {
    let mut lens = vec![WITNESS_SIG_LEN];
    if with_preimage {
        lens.push(WITNESS_PREIMAGE_LEN);
    }
    lens.push(script_len);
    lens.push(control_block_len);
    lens
}

/// HTLC。
/// スクリプトはminiscript / descriptorを使わず、生のオペコードで直接作る。
/// 内部鍵はNUMSを使う。
///
/// claim leaf (73byte)
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY
/// OP_SHA256 <preimage_hash> OP_EQUALVERIFY
/// <claim_xonly_pubkey> OP_CHECKSIG
/// ```
///
/// refund leaf (csv_blocks=16で37byte)
/// ```text
/// <csv_blocks> OP_CSV OP_DROP
/// <refund_xonly_pubkey> OP_CHECKSIG
/// ```
pub struct Htlc<'a> {
    pub preimage_hash: sha256::Hash,
    pub csv_blocks: u32,

    wallet: &'a Wallet,

    spend_info: TaprootSpendInfo,
    claim_leaf: LeafSpend,
    refund_leaf: LeafSpend,
}

impl<'a> Htlc<'a> {
    pub fn new(
        wallet: &'a Wallet,
        preimage_hash: sha256::Hash,
        csv_blocks: u32,
        claim_addr_index: u32,
        claim_xonly_pubkey: XOnlyPublicKey,
        refund_addr_index: u32,
        refund_xonly_pubkey: XOnlyPublicKey,
    ) -> Result<Self, HtlcError> {
        let secp = wallet.secp_ctx();
        let internal_key = XOnlyPublicKey::from_str(NUMS_XPUBKEY)
            .map_err(|e| log_err!(HtlcError::Secp(e), "internal key"))?;

        let claim_script = claim_leaf_script(&preimage_hash, &claim_xonly_pubkey);
        let refund_script = refund_leaf_script(csv_blocks, &refund_xonly_pubkey);

        // 2つのleafを同じ深さ(=1)に置く
        let spend_info = TaprootBuilder::new()
            .add_leaf(1, claim_script.clone())
            .map_err(|e| log_err!(HtlcError::TaprootBuilder(e), "add claim leaf"))?
            .add_leaf(1, refund_script.clone())
            .map_err(|e| log_err!(HtlcError::TaprootBuilder(e), "add refund leaf"))?
            .finalize(secp, internal_key)
            .map_err(|_| log_err!(HtlcError::TaprootBuilderIncomplete, "finalize"))?;

        let claim_leaf = LeafSpend::new(
            &spend_info,
            "claim",
            claim_script,
            claim_addr_index,
            ScriptBuf::new_p2tr(secp, claim_xonly_pubkey, None),
            Sequence::MAX,
            true,
        )?;
        let refund_leaf = LeafSpend::new(
            &spend_info,
            "refund",
            refund_script,
            refund_addr_index,
            ScriptBuf::new_p2tr(secp, refund_xonly_pubkey, None),
            Sequence(csv_blocks),
            false,
        )?;

        Ok(Self {
            wallet,
            preimage_hash,
            csv_blocks,
            spend_info,
            claim_leaf,
            refund_leaf,
        })
    }

    pub fn address(&self, network: Network) -> Result<Address, HtlcError> {
        Ok(Address::p2tr_tweaked(self.spend_info.output_key(), network))
    }

    pub fn create_claim_tx(
        &self,
        prev_outpoint: OutPoint,
        prev_txout: &TxOut,
        vin_index: usize,
        preimage: [u8; 32],
        fee_rate: f64,
    ) -> Result<Transaction, HtlcError> {
        self.create_spend_tx(
            &self.claim_leaf,
            prev_outpoint,
            prev_txout,
            vin_index,
            Some(preimage),
            fee_rate,
        )
    }

    pub fn create_refund_tx(
        &self,
        prev_outpoint: OutPoint,
        prev_txout: &TxOut,
        vin_index: usize,
        fee_rate: f64,
    ) -> Result<Transaction, HtlcError> {
        self.create_spend_tx(
            &self.refund_leaf,
            prev_outpoint,
            prev_txout,
            vin_index,
            None,
            fee_rate,
        )
    }

    /// leafを使う支払いトランザクションを作る。
    /// fee計算に必要なサイズはleaf生成時に見積もってあるので、
    /// 署名はfee(output value)が確定した後に1回だけ行う。
    fn create_spend_tx(
        &self,
        leaf: &LeafSpend,
        prev_outpoint: OutPoint,
        prev_txout: &TxOut,
        vin_index: usize,
        preimage: Option<[u8; 32]>,
        fee_rate: f64,
    ) -> Result<Transaction, HtlcError> {
        let mut spend_tx = build_spend_tx(
            leaf.dest_script.clone(),
            prev_outpoint,
            Amount::ZERO,
            leaf.sequence,
        );

        spend_tx.output[0].value = prev_txout.value - fee_from_rate(fee_rate, leaf.weight);

        let witness = self.leaf_witness(leaf, &spend_tx, vin_index, prev_txout, preimage)?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        Ok(spend_tx)
    }

    /// このleafで使うwitness stack(署名, [preimage], leaf script, control block)
    fn leaf_witness(
        &self,
        leaf: &LeafSpend,
        spend_tx: &Transaction,
        vin_index: usize,
        prev_txout: &TxOut,
        preimage: Option<[u8; 32]>,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let taproot_sig = sign_taproot_script_spend(
            self.wallet,
            leaf.addr_index,
            spend_tx,
            vin_index,
            prev_txout,
            leaf.leaf_hash(),
        )?;

        // SIGHASH_TYPE(Default)なのでsighash byteは付加しない
        let mut witness = vec![taproot_sig.signature.serialize().to_vec()];

        if leaf.with_preimage {
            let preimage = preimage
                .ok_or_else(|| log_err!(HtlcError::Witness("claim"), "missing preimage"))?;
            if sha256::Hash::hash(&preimage) != self.preimage_hash {
                return Err(log_err!(
                    HtlcError::Witness("claim"),
                    "preimage hash mismatch"
                ));
            }
            witness.push(preimage.to_vec());
        }

        witness.push(leaf.script.to_bytes());
        witness.push(leaf.control_block.serialize());
        Ok(witness)
    }
}

/// claim(preimage)ルートのleafスクリプト
/// len(x) = 32 and SHA256(x) = preimage_hash
fn claim_leaf_script(
    preimage_hash: &sha256::Hash,
    claim_xonly_pubkey: &XOnlyPublicKey,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(opcodes::all::OP_SIZE)
        .push_int(32)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_SHA256)
        .push_slice(preimage_hash.to_byte_array())
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_slice(claim_xonly_pubkey.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

/// refund(CSV)ルートのleafスクリプト
/// nSequence >= csv_blocks (and compatible)
fn refund_leaf_script(csv_blocks: u32, refund_xonly_pubkey: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(csv_blocks as i64)
        .push_opcode(opcodes::all::OP_CSV)
        .push_opcode(opcodes::all::OP_DROP) // OP_CSVはスタックエントリを消費しない
        .push_slice(refund_xonly_pubkey.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

/// 支払いトランザクションの骨組み(入力1・出力1・P2TR出力、witnessは空)。
fn build_spend_tx(
    dest_script: ScriptBuf,
    prev_outpoint: OutPoint,
    value: Amount,
    sequence: Sequence,
) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev_outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::default(),
        }],
        output: vec![transaction::TxOut {
            value,
            script_pubkey: dest_script,
        }],
    }
}

/// 支払いトランザクション(入力1・出力1・P2TR出力)のweightを見積もる。
/// 前の出力のscript_pubkey/value、outpointの実体はサイズに影響しない。
/// 前提: 入力1・出力1。入出力数を変えるならこの見積りは使えない。
fn estimate_spend_tx_weight(
    dest_script: &ScriptBuf,
    sequence: Sequence,
    witness_item_lens: &[usize],
) -> Weight {
    let mut tx = build_spend_tx(
        dest_script.clone(),
        OutPoint::null(),
        Amount::ZERO,
        sequence,
    );
    // サイズを決めるために、要素の長さだけ本物と同じダミーwitness(中身は0)を入れる。
    // compact sizeプレフィックスやsegment(=2byte)/要素数はWitnessのシリアライズが払う。
    let dummy: Vec<Vec<u8>> = witness_item_lens
        .iter()
        .map(|&len| vec![0u8; len])
        .collect();
    tx.input[0].witness = Witness::from_slice(&dummy);
    tx.weight()
}

fn sign_taproot_script_spend(
    wallet: &Wallet,
    addr_index: u32,
    spend_tx: &Transaction,
    vin_index: usize,
    prev_txout: &TxOut,
    leaf_hash: TapLeafHash,
) -> Result<TaprootSig, HtlcError> {
    let prevouts = [prev_txout];
    let mut sighash_cache = SighashCache::new(spend_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            vin_index,
            &Prevouts::All(&prevouts),
            leaf_hash,
            SIGHASH_TYPE,
        )
        .map_err(|e| log_err!(HtlcError::Taproot(e), "taproot_script_spend_signature_hash"))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let keypair = derive_keypair(wallet, addr_index)?;
    let signature = wallet.secp_ctx().sign_schnorr(&msg, &keypair);

    Ok(TaprootSig {
        signature,
        sighash_type: SIGHASH_TYPE,
    })
}

/// ウォレット(External keychain)のxprvから`addr_index`に対応するKeypairを導出する。
fn derive_keypair(wallet: &Wallet, addr_index: u32) -> Result<Keypair, HtlcError> {
    let signers = wallet.get_signers(KeychainKind::External);
    let xprv = signers
        .signers()
        .iter()
        .find_map(|&s| match s.descriptor_secret_key() {
            Some(DescriptorSecretKey::XPrv(xprv)) => Some(xprv),
            _ => None,
        })
        .ok_or_else(|| {
            log_err!(
                HtlcError::NoKey("no secret key in wallet"),
                "derive_keypair"
            )
        })?;

    let child = ChildNumber::from_normal_idx(addr_index)
        .map_err(|e| log_err!(HtlcError::Bip32(e), "from_normal_idx"))?;
    let mut path_vec: Vec<ChildNumber> = xprv.derivation_path.into_iter().copied().collect();
    path_vec.push(child);
    let full_path = DerivationPath::from(path_vec);

    let secp = wallet.secp_ctx();
    let sec_key = xprv
        .xkey
        .derive_priv(secp, &full_path)
        .map_err(|e| log_err!(HtlcError::Bip32(e), "derive_priv"))?
        .private_key;

    Ok(Keypair::from_secret_key(secp, &sec_key))
}

pub fn xonly_pubkey(hex_str: &str) -> Result<XOnlyPublicKey, HtlcError> {
    let bytes =
        hex::decode(hex_str).map_err(|e| log_err!(HtlcError::FromHex(e), "xonly_pubkey"))?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|e| log_err!(HtlcError::Secp(e), "xonly_pubkey"))
}

pub fn convert_xonly_pubkey(
    wallet: &Wallet,
    addr_info: &AddressInfo,
) -> Result<XOnlyPublicKey, HtlcError> {
    let keypair = derive_keypair(wallet, addr_info.index)?;
    Ok(keypair.x_only_public_key().0)
}

pub fn generate_preimage() -> ([u8; 32], sha256::Hash) {
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let hash: sha256::Hash = sha256::Hash::hash(&preimage);
    (preimage, hash)
}

/// sat/vB のレートとトランザクションweightからfeeを求める。
/// feeは実際のweight(wu)に対して計算する(vBへの切り上げを挟まない)。
/// 浮動小数のまま計算せず、整数演算にして丸めの位置と方向を明示する。
fn fee_from_rate(fee_rate: f64, weight: Weight) -> Amount {
    // sat/vB → sat/kwu (1 sat/vB = 250 sat/kwu)。
    // FeeRateの格子は0.004 sat/vBなので、小数第1位までの値は丸め誤差なしに変換できる。
    let sat_per_kwu = (fee_rate * 250.0).round() as u64;

    // sat/kwu * wu / 1000 を切り上げてfeeを確定する(過少支払いを避ける)。
    let fee = sat_per_kwu.saturating_mul(weight.to_wu()).div_ceil(1000);

    debug!("fee_rate = {}", fee_rate);
    debug!("weight = {} wu", weight.to_wu());
    debug!("fee = {}", fee);
    Amount::from_sat(fee)
}

#[cfg(test)]
mod tests;
