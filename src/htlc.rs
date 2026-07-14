use std::{collections::BTreeMap, result::Result, str::FromStr};

use bdk_wallet::{
    AddressInfo, KeychainKind, Wallet, bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness, absolute, bip32::{ChildNumber, DerivationPath, Error as Bip32Error}, hashes::{Hash, sha256}, key::{
            Keypair, Secp256k1,
            rand::{self, RngCore},
        }, relative::LockTime, secp256k1::{
            self, All as Secp256k1All, Message, Parity, XOnlyPublicKey, schnorr::Signature,
        }, sighash::{Prevouts, SighashCache, TaprootError}, taproot::{ControlBlock, LeafVersion, Signature as TaprootSig}, transaction,
    }, descriptor::DescriptorError, keys::{DescriptorPublicKey, DescriptorSecretKey}, miniscript::{
        DefiniteDescriptorKey, Descriptor, Error as MiniscriptError, Preimage32, Satisfier,
        descriptor::{ConversionError, DescriptorKeyParseError},
    },
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
    Conversion(#[source] ConversionError),

    #[error("{0}")]
    Descriptor(#[source] DescriptorError),

    #[error("{0}")]
    DescriptorKeyParse(#[source] DescriptorKeyParseError),

    #[error("{0}")]
    Bip32(#[source] Bip32Error),

    #[error("{0}")]
    Taproot(#[source] TaprootError),

    #[error("{0}")]
    Miniscript(#[source] MiniscriptError),

    #[error("{0}")]
    Secp(#[source] secp256k1::Error),

    #[error("descriptor error: {0}")]
    NoKey(String),

    #[error("witness error: leaf_name={0}")]
    Witness(String),

    #[error("sign error")]
    Sign,
}

// pick as internal key a "Nothing Up My Sleeve" (NUMS) point
// TODO H + rG
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
const NUMS_XPUBKEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

struct TaprootSpendData {
    leaf_script: ScriptBuf,
    control_block: ControlBlock,
    leaf_hash: TapLeafHash,
}

struct HtlcSatisfier {
    sigs: BTreeMap<(PublicKey, TapLeafHash), TaprootSig>,
    preimages: BTreeMap<sha256::Hash, Preimage32>,
    control_blocks: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,
    sequence: Option<u32>,
}

impl Satisfier<PublicKey> for HtlcSatisfier {
    fn lookup_tap_leaf_script_sig(&self, pk: &PublicKey, lh: &TapLeafHash) -> Option<TaprootSig> {
        self.sigs.get(&(*pk, *lh)).copied()
    }

    fn lookup_sha256(&self, h: &sha256::Hash) -> Option<Preimage32> {
        self.preimages.get(h).copied()
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>> {
        Some(&self.control_blocks)
    }

    fn check_older(&self, csv: LockTime) -> bool {
        self.sequence
            .is_some_and(|sequence| csv.to_consensus_u32() >= sequence)
    }
}

pub struct Htlc<'a> {
    pub preimage_hash: sha256::Hash,
    pub csv_blocks: u32,

    wallet: &'a Wallet,
    secp: &'a Secp256k1<Secp256k1All>,
    claim_xonly_pubkey: XOnlyPublicKey,
    refund_xonly_pubkey: XOnlyPublicKey,

    claim_addr_index: u32,
    refund_addr_index: u32,
    derived: Descriptor<DefiniteDescriptorKey>,
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
        let desc = generate_descriptor(
            &preimage_hash,
            csv_blocks,
            &claim_xonly_pubkey,
            &refund_xonly_pubkey,
        )?;
        let derived = desc
            .at_derivation_index(0)
            .map_err(|e| log_err!(HtlcError::Conversion(e), "new"))?;
        Ok(Self {
            wallet,
            secp: wallet.secp_ctx(),
            preimage_hash,
            csv_blocks,
            claim_addr_index,
            claim_xonly_pubkey,
            refund_addr_index,
            refund_xonly_pubkey,
            derived,
        })
    }

    pub fn address(&self, network: Network) -> Result<Address, HtlcError> {
        self.derived
            .address(network)
            .map_err(|e| log_err!(HtlcError::Miniscript(e), "address"))
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
                script_pubkey: ScriptBuf::new_p2tr(&self.secp, self.claim_xonly_pubkey, None),
            }],
        };

        // dummy witness stack for calculate fee
        let witness = self.witness_stack(
            true, // dummy
            &spend_tx,
            vin_index,
            prev_txout,
            self.claim_addr_index,
            self.claim_xonly_pubkey,
            Some(preimage),
            None,
            "claim",
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        let fee = fee_from_rate(fee_rate, spend_tx.vsize());
        spend_tx.output[0].value = prev_txout.value - fee;

        let witness = self.witness_stack(
            false,
            &spend_tx,
            vin_index,
            prev_txout,
            self.claim_addr_index,
            self.claim_xonly_pubkey,
            Some(preimage),
            None,
            "claim",
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
                script_pubkey: ScriptBuf::new_p2tr(&self.secp, self.refund_xonly_pubkey, None),
            }],
        };

        let witness = self.witness_stack(
            true, // dummy
            &spend_tx,
            vin_index,
            prev_txout,
            self.refund_addr_index,
            self.refund_xonly_pubkey,
            None,
            Some(spend_tx.input[vin_index].sequence.to_consensus_u32()),
            "refund",
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        let fee = fee_from_rate(fee_rate, spend_tx.vsize());
        spend_tx.output[0].value = prev_txout.value - fee;

        let witness = self.witness_stack(
            false,
            &spend_tx,
            vin_index,
            prev_txout,
            self.refund_addr_index,
            self.refund_xonly_pubkey,
            None,
            Some(spend_tx.input[vin_index].sequence.to_consensus_u32()),
            "refund",
        )?;
        spend_tx.input[vin_index].witness = Witness::from_slice(&witness);

        Ok(spend_tx)
    }

    #[allow(clippy::too_many_arguments)]
    fn witness_stack(
        &self,
        is_dummy: bool,
        spend_tx: &Transaction,
        vin_index: usize,
        prev_txout: &TxOut,
        addr_index: u32,
        xonly_pubkey: XOnlyPublicKey,
        preimage: Option<[u8; 32]>,
        sequence: Option<u32>,
        leaf_name: &str,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let preimages: BTreeMap<sha256::Hash, Preimage32> = if let Some(preimage) = preimage {
            let mut preimages = BTreeMap::new();
            preimages.insert(self.preimage_hash, preimage);
            preimages
        } else {
            BTreeMap::new()
        };

        let spend_data = build_taproot_leaf_spend_data(&self.derived, xonly_pubkey, leaf_name)?;
        let taproot_sig = self.sign_taproot_script_spend(
            is_dummy,
            addr_index,
            spend_tx,
            vin_index,
            prev_txout,
            spend_data.leaf_hash,
        )?;

        let pk = PublicKey::from(xonly_pubkey.public_key(Parity::Even));

        let mut sigs = BTreeMap::new();
        sigs.insert((pk, spend_data.leaf_hash), taproot_sig);

        let mut control_blocks = BTreeMap::new();
        control_blocks.insert(
            spend_data.control_block,
            (spend_data.leaf_script, LeafVersion::TapScript),
        );

        let satisfier = HtlcSatisfier {
            sigs,
            preimages,
            control_blocks,
            sequence,
        };

        let htlc_definite = self
            .derived
            .derived_descriptor(self.secp)
            .map_err(|e| log_err!(HtlcError::Conversion(e), "witness_stack"))?;
        let (witness_stack, _script_sig) = htlc_definite
            .get_satisfaction(satisfier)
            .map_err(|e| log_err!(HtlcError::Miniscript(e), "get_satisfaction"))?;
        Ok(witness_stack)
    }

    fn sign_taproot_script_spend(
        &self,
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
        let signature = self.sign_schnorr(addr_index, &msg)?;

        Ok(TaprootSig {
            signature,
            sighash_type: TapSighashType::Default,
        })
    }

    fn sign_schnorr(&self, addr_index: u32, msg: &Message) -> Result<Signature, HtlcError> {
        let signers = self.wallet.get_signers(KeychainKind::External);
        let xprv = signers
            .signers()
            .iter()
            .find_map(|&s| match s.descriptor_secret_key() {
                Some(DescriptorSecretKey::XPrv(xprv)) => Some(xprv),
                _ => None,
            })
            .ok_or_else(|| log_err!(HtlcError::Sign, "no secret key in wallet"))?;

        let child = ChildNumber::from_normal_idx(addr_index)
            .map_err(|e| log_err!(HtlcError::Bip32(e), "from_normal_idx"))?;
        let mut path_vec: Vec<ChildNumber> = xprv.derivation_path.into_iter().copied().collect();
        path_vec.push(child);
        let full_path = DerivationPath::from(path_vec);

        let sec_key = xprv
            .xkey
            .derive_priv(self.secp, &full_path)
            .map_err(|e| log_err!(HtlcError::Bip32(e), "derive_priv"))?
            .private_key;

        let keypair = Keypair::from_secret_key(self.secp, &sec_key);
        Ok(self.secp.sign_schnorr(msg, &keypair))
    }
}

fn build_taproot_leaf_spend_data(
    htlc_derived: &Descriptor<DefiniteDescriptorKey>,
    xonly: XOnlyPublicKey,
    leaf_name: &str,
) -> Result<TaprootSpendData, HtlcError> {
    let Descriptor::Tr(tr) = htlc_derived else {
        return Err(log_err!(
            HtlcError::Witness(leaf_name.to_string()),
            "expected Taproot descriptor"
        ));
    };

    let spend_info = tr.spend_info();
    let xonly_bytes = xonly.serialize();
    let (leaf_script, control_block) = spend_info
        .script_map()
        .keys()
        .find_map(|(script, ver)| {
            if script.as_bytes().windows(32).any(|w| w == xonly_bytes) {
                spend_info
                    .control_block(&(script.clone(), *ver))
                    .map(|cb| (script.clone(), cb))
            } else {
                None
            }
        })
        .ok_or_else(|| log_err!(HtlcError::Witness(leaf_name.to_string()), "leaf not found"))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    Ok(TaprootSpendData {
        leaf_script,
        control_block,
        leaf_hash,
    })
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
    let xonly: XOnlyPublicKey = {
        let desc = wallet
            .public_descriptor(KeychainKind::External)
            .at_derivation_index(addr_info.index)
            .map_err(|e| log_err!(HtlcError::Conversion(e), "at_derivation_index"))?
            .derived_descriptor(wallet.secp_ctx())
            .map_err(|e| log_err!(HtlcError::Conversion(e), "derived_descriptor"))?;
        match desc {
            Descriptor::Tr(tr) => tr.internal_key().inner.x_only_public_key().0,
            _ => Err(HtlcError::NoKey("Expected Taproot descriptor".into()))?,
        }
    };
    Ok(xonly)
}

pub fn generate_preimage() -> ([u8; 32], sha256::Hash) {
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let hash: sha256::Hash = sha256::Hash::hash(&preimage);
    (preimage, hash)
}

fn generate_descriptor(
    preimage_hash: &sha256::Hash,
    csv_blocks: u32,
    claim_xonly_pubkey: &XOnlyPublicKey,
    refund_xonly_pubkey: &XOnlyPublicKey,
) -> Result<Descriptor<DescriptorPublicKey>, HtlcError> {
    let intr_ext = DescriptorPublicKey::from_str(NUMS_XPUBKEY)
        .map_err(|e| log_err!(HtlcError::DescriptorKeyParse(e), "internal key"))?;
    let (htlc_descriptor, _key_map, _networks) = bdk_wallet::descriptor!(
        tr(
            intr_ext,
            {
                and_v(v:sha256(*preimage_hash), pk(*claim_xonly_pubkey)),
                and_v(v:older(csv_blocks), pk(*refund_xonly_pubkey))
            }
        )
    )
    .map_err(|e| log_err!(HtlcError::Descriptor(e), "desc! macro"))?;
    Ok(htlc_descriptor)
}

fn fee_from_rate(fee_rate: f64, vsize: usize) -> Amount {
    let fee = (fee_rate * vsize as f64 + 0.5) as u64;
    debug!("fee_rate = {}", fee_rate);
    debug!("fee = {}", fee);
    Amount::from_sat(fee)
}
