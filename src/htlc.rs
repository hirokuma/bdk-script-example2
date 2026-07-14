use std::{collections::BTreeMap, result::Result, str::FromStr};

use bdk_wallet::{
    AddressInfo, KeychainKind, Wallet,
    bitcoin::{
        PublicKey, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxOut,
        bip32::{ChildNumber, DerivationPath, Error as Bip32Error},
        hashes::{Hash, sha256},
        key::{
            Keypair, Secp256k1,
            rand::{self, RngCore},
        },
        relative::LockTime,
        secp256k1::{All as Secp256k1All, Message, Parity, XOnlyPublicKey, schnorr::Signature},
        sighash::{Prevouts, SighashCache, TaprootError},
        taproot::{ControlBlock, LeafVersion, Signature as TaprootSig},
    },
    descriptor::DescriptorError,
    keys::{DescriptorPublicKey, DescriptorSecretKey},
    miniscript::{
        DefiniteDescriptorKey, Descriptor, Error as MiniscriptError, Preimage32, Satisfier,
        descriptor::{ConversionError, DescriptorKeyParseError},
    },
};
use thiserror::Error;
use tracing::*;

use wallet_utils::log_err;

#[derive(Error, Debug)]
pub enum HtlcError {
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

    #[error("descriptor error: {0}")]
    NoKey(String),

    #[error("witness error: {0}")]
    Witness(String),

    #[error("sign error: {0}")]
    Sign(String),
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
    pub wallet: &'a Wallet,
    pub secp: &'a Secp256k1<Secp256k1All>,
    pub preimage_hash: sha256::Hash,
    pub csv_blocks: u32,
    pub claim_xonly_pubkey: XOnlyPublicKey,
    pub refund_xonly_pubkey: XOnlyPublicKey,
}

impl<'a> Htlc<'a> {
    pub fn new(
        wallet: &'a Wallet,
        preimage_hash: sha256::Hash,
        csv_blocks: u32,
        claim_xonly_pubkey: XOnlyPublicKey,
        refund_xonly_pubkey: XOnlyPublicKey,
    ) -> Result<Self, HtlcError> {
        Ok(Self {
            wallet,
            secp: wallet.secp_ctx(),
            preimage_hash,
            csv_blocks,
            claim_xonly_pubkey,
            refund_xonly_pubkey,
        })
    }

    pub fn generate_descriptor(&self) -> Result<Descriptor<DescriptorPublicKey>, HtlcError> {
        let intr_ext = DescriptorPublicKey::from_str(NUMS_XPUBKEY)
            .map_err(|e| log_err!(HtlcError::DescriptorKeyParse(e), "internal key"))?;
        let (htlc_descriptor, _key_map, _networks) = bdk_wallet::descriptor!(
            tr(
                intr_ext,
                {
                    and_v(v:sha256(self.preimage_hash), pk(self.claim_xonly_pubkey)),
                    and_v(v:older(self.csv_blocks), pk(self.refund_xonly_pubkey))
                }
            )
        )
        .map_err(|e| log_err!(HtlcError::Descriptor(e), "desc! macro"))?;
        Ok(htlc_descriptor)
    }

    pub fn witness_stack_for_claim(
        &self,
        claim_addrinfo: &AddressInfo,
        htlc_descriptor: &Descriptor<DescriptorPublicKey>,
        spend_tx: &Transaction,
        txout: TxOut,
        preimage: [u8; 32],
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let htlc_derived = htlc_descriptor
            .at_derivation_index(0)
            .map_err(|e| log_err!(HtlcError::Conversion(e), "witness_stack_for_claim"))?;

        let mut preimages = BTreeMap::new();
        preimages.insert(self.preimage_hash, preimage);

        self.witness_stack(
            &htlc_derived,
            spend_tx,
            txout,
            claim_addrinfo,
            self.claim_xonly_pubkey,
            preimages,
            None,
            "claim",
        )
    }

    pub fn witness_stack_for_refund(
        &self,
        refund_addrinfo: &AddressInfo,
        htlc_descriptor: &Descriptor<DescriptorPublicKey>,
        spend_tx: &Transaction,
        txout: TxOut,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let htlc_derived = htlc_descriptor
            .at_derivation_index(0)
            .map_err(|e| log_err!(HtlcError::Conversion(e), "witness_stack_for_refund"))?;

        self.witness_stack(
            &htlc_derived,
            spend_tx,
            txout,
            refund_addrinfo,
            self.refund_xonly_pubkey,
            BTreeMap::new(),
            Some(spend_tx.input[0].sequence.to_consensus_u32()),
            "refund",
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn witness_stack(
        &self,
        htlc_derived: &Descriptor<DefiniteDescriptorKey>,
        spend_tx: &Transaction,
        txout: TxOut,
        addr_info: &AddressInfo,
        xonly: XOnlyPublicKey,
        preimages: BTreeMap<sha256::Hash, Preimage32>,
        sequence: Option<u32>,
        leaf_name: &str,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let spend_data = build_taproot_leaf_spend_data(htlc_derived, xonly, leaf_name)?;
        let taproot_sig =
            self.sign_taproot_script_spend(addr_info, spend_tx, txout, spend_data.leaf_hash)?;

        let pk = PublicKey::from(xonly.public_key(Parity::Even));

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

        let htlc_definite = htlc_derived
            .derived_descriptor(self.secp)
            .map_err(|e| log_err!(HtlcError::Conversion(e), "witness_stack"))?;
        let (witness_stack, _script_sig) = htlc_definite
            .get_satisfaction(satisfier)
            .map_err(|e| log_err!(HtlcError::Miniscript(e), "get_satisfaction"))?;
        Ok(witness_stack)
    }

    fn sign_taproot_script_spend(
        &self,
        addr_info: &AddressInfo,
        spend_tx: &Transaction,
        txout: TxOut,
        leaf_hash: TapLeafHash,
    ) -> Result<TaprootSig, HtlcError> {
        let prevouts = [txout];
        let mut sighash_cache = SighashCache::new(spend_tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| log_err!(HtlcError::Taproot(e), "taproot_script_spend_signature_hash"))?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = self.sign_schnorr(addr_info, &msg)?;

        Ok(TaprootSig {
            signature,
            sighash_type: TapSighashType::Default,
        })
    }

    fn sign_schnorr(&self, addr_info: &AddressInfo, msg: &Message) -> Result<Signature, HtlcError> {
        let signers = self.wallet.get_signers(KeychainKind::External);
        let dsk = signers
            .signers()
            .iter()
            .find_map(|&s| s.descriptor_secret_key())
            .ok_or_else(|| HtlcError::Sign("no secret key in wallet".into()))?;

        let sec_key = match dsk {
            DescriptorSecretKey::XPrv(xkey) => {
                let child = ChildNumber::from_normal_idx(addr_info.index)
                    .map_err(|e| log_err!(HtlcError::Bip32(e), "from_normal_idx"))?;
                let mut path_vec: Vec<ChildNumber> =
                    xkey.derivation_path.into_iter().copied().collect();
                path_vec.push(child);
                let full_path = DerivationPath::from(path_vec);
                xkey.xkey
                    .derive_priv(self.secp, &full_path)
                    .map_err(|e| log_err!(HtlcError::Bip32(e), "derive_priv"))?
                    .private_key
            }
            _ => return Err(HtlcError::Sign("expected xprv signer".into())),
        };
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
        return Err(HtlcError::Witness("expected Taproot descriptor".into()));
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
        .ok_or_else(|| HtlcError::Witness(format!("{leaf_name} leaf not found")))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    Ok(TaprootSpendData {
        leaf_script,
        control_block,
        leaf_hash,
    })
}

pub fn convert_descriptor(
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
