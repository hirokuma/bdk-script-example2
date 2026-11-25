use std::str::FromStr;

use bdk_wallet::{
    AddressInfo, KeychainKind, Wallet,
    bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
        Transaction, TxIn, TxOut, Witness, absolute,
        bip32::{ChildNumber, DerivationPath, Error as Bip32Error},
        hashes::{Hash, sha256},
        key::{
            Keypair, Secp256k1,
            rand::{self, RngCore},
        },
        opcodes,
        script::Builder,
        secp256k1::{self, All as Secp256k1All, Message, XOnlyPublicKey, schnorr::Signature},
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
    NoKey(String),

    #[error("witness error: leaf_name={0}")]
    Witness(String),
}

// pick as internal key a "Nothing Up My Sleeve" (NUMS) point
// TODO H + rG
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
const NUMS_XPUBKEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// taprootのleafスクリプトと、それを使って支払うために必要な情報。
struct TapLeafSpend {
    script: ScriptBuf,
    leaf_hash: TapLeafHash,
    control_block: ControlBlock,
}

/// 支払い経路。claimはpreimageルート、refundはCSVルート。
#[derive(Clone, Copy)]
enum SpendLeaf {
    Claim,
    Refund,
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
    secp: &'a Secp256k1<Secp256k1All>,
    claim_xonly_pubkey: XOnlyPublicKey,
    refund_xonly_pubkey: XOnlyPublicKey,

    claim_addr_index: u32,
    refund_addr_index: u32,

    spend_info: TaprootSpendInfo,
    claim_leaf: TapLeafSpend,
    refund_leaf: TapLeafSpend,
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

        let claim_leaf = leaf_spend(&spend_info, claim_script, "claim")?;
        let refund_leaf = leaf_spend(&spend_info, refund_script, "refund")?;

        Ok(Self {
            wallet,
            secp,
            preimage_hash,
            csv_blocks,
            claim_addr_index,
            claim_xonly_pubkey,
            refund_addr_index,
            refund_xonly_pubkey,
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
        let mut spend_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![transaction::TxOut {
                value: Amount::ZERO, // fee計算後に設定
                script_pubkey: ScriptBuf::new_p2tr(self.secp, self.claim_xonly_pubkey, None),
            }],
        };

        // dummy witness stack for calculate fee
        let witness = self.htlc_witness_stack(
            true, // dummy
            &spend_tx,
            vin_index,
            prev_txout,
            SpendLeaf::Claim,
            Some(preimage),
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        let fee = fee_from_rate(fee_rate, spend_tx.vsize());
        spend_tx.output[0].value = prev_txout.value - fee;

        let witness = self.htlc_witness_stack(
            false,
            &spend_tx,
            vin_index,
            prev_txout,
            SpendLeaf::Claim,
            Some(preimage),
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        Ok(spend_tx)
    }

    pub fn create_refund_tx(
        &self,
        prev_outpoint: OutPoint,
        prev_txout: &TxOut,
        vin_index: usize,
        fee_rate: f64,
    ) -> Result<Transaction, HtlcError> {
        let mut spend_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(self.csv_blocks),
                witness: Witness::default(),
            }],
            output: vec![transaction::TxOut {
                value: Amount::ZERO, // fee計算後に設定
                script_pubkey: ScriptBuf::new_p2tr(self.secp, self.refund_xonly_pubkey, None),
            }],
        };

        // dummy witness stack for calculate fee
        let witness = self.htlc_witness_stack(
            true, // dummy
            &spend_tx,
            vin_index,
            prev_txout,
            SpendLeaf::Refund,
            None,
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        let fee = fee_from_rate(fee_rate, spend_tx.vsize());
        spend_tx.output[0].value = prev_txout.value - fee;

        let witness = self.htlc_witness_stack(
            false,
            &spend_tx,
            vin_index,
            prev_txout,
            SpendLeaf::Refund,
            None,
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        Ok(spend_tx)
    }

    fn htlc_witness_stack(
        &self,
        is_dummy: bool,
        spend_tx: &Transaction,
        vin_index: usize,
        prev_txout: &TxOut,
        leaf: SpendLeaf,
        preimage: Option<[u8; 32]>,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let (leaf_data, addr_index) = match leaf {
            SpendLeaf::Claim => (&self.claim_leaf, self.claim_addr_index),
            SpendLeaf::Refund => (&self.refund_leaf, self.refund_addr_index),
        };

        let taproot_sig = sign_taproot_script_spend(
            self.wallet,
            is_dummy,
            addr_index,
            spend_tx,
            vin_index,
            prev_txout,
            leaf_data.leaf_hash,
        )?;

        // TapSighashType::Defaultなのでsighash byteは付加しない(64byte)
        let mut witness = vec![taproot_sig.signature.serialize().to_vec()];

        if let SpendLeaf::Claim = leaf {
            let preimage = preimage.ok_or_else(|| {
                log_err!(HtlcError::Witness("claim".to_string()), "missing preimage")
            })?;
            if sha256::Hash::hash(&preimage) != self.preimage_hash {
                return Err(log_err!(
                    HtlcError::Witness("claim".to_string()),
                    "preimage hash mismatch"
                ));
            }
            witness.push(preimage.to_vec());
        }

        witness.push(leaf_data.script.to_bytes());
        witness.push(leaf_data.control_block.serialize());
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

/// TaprootSpendInfoからleafスクリプトの支払い情報を取り出す。
fn leaf_spend(
    spend_info: &TaprootSpendInfo,
    script: ScriptBuf,
    name: &str,
) -> Result<TapLeafSpend, HtlcError> {
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| log_err!(HtlcError::Witness(name.to_string()), "control block"))?;
    Ok(TapLeafSpend {
        script,
        leaf_hash,
        control_block,
    })
}

fn sign_taproot_script_spend(
    wallet: &Wallet,
    is_dummy: bool,
    addr_index: u32,
    spend_tx: &Transaction,
    vin_index: usize,
    prev_txout: &TxOut,
    leaf_hash: TapLeafHash,
) -> Result<TaprootSig, HtlcError> {
    if is_dummy {
        let dummy = Signature::from_slice(&[0u8; 64]).unwrap();
        return Ok(TaprootSig {
            signature: dummy,
            sighash_type: TapSighashType::Default,
        });
    }
    let prevouts = [prev_txout];
    let mut sighash_cache = SighashCache::new(spend_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            vin_index,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| log_err!(HtlcError::Taproot(e), "taproot_script_spend_signature_hash"))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = sign_schnorr(wallet, addr_index, &msg)?;

    Ok(TaprootSig {
        signature,
        sighash_type: TapSighashType::Default,
    })
}

fn sign_schnorr(wallet: &Wallet, addr_index: u32, msg: &Message) -> Result<Signature, HtlcError> {
    let keypair = derive_keypair(wallet, addr_index)?;
    Ok(wallet.secp_ctx().sign_schnorr(msg, &keypair))
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
                HtlcError::NoKey("no secret key in wallet".to_string()),
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

fn fee_from_rate(fee_rate: f64, vsize: usize) -> Amount {
    let fee = (fee_rate * vsize as f64 + 0.5) as u64;
    debug!("fee_rate = {}", fee_rate);
    debug!("fee = {}", fee);
    Amount::from_sat(fee)
}
