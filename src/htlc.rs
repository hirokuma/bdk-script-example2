use std::{collections::BTreeMap, result::Result, str::FromStr};

use bdk_wallet::{
    AddressInfo, KeychainKind, Wallet,
    bitcoin::{
        PublicKey, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxOut,
        bip32::{self, ChildNumber, DerivationPath},
        hashes::{Hash, sha256},
        key::Keypair,
        relative::LockTime,
        secp256k1::{Message, XOnlyPublicKey, schnorr::Signature},
        sighash::{Prevouts, SighashCache},
        taproot::{ControlBlock, LeafVersion, Signature as TaprootSig},
    },
    descriptor,
    keys::DescriptorPublicKey,
    miniscript::{
        DefiniteDescriptorKey, Descriptor, Preimage32, Satisfier, descriptor::ConversionError,
    },
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HtlcError {
    #[error("conversion error: {0}")]
    ConvError(#[from] ConversionError),

    #[error("descriptor error: {0}")]
    DescriptorError(#[from] bdk_wallet::descriptor::DescriptorError),

    #[error("bip32 error: {0}")]
    Bip32Error(#[from] bip32::Error),

    #[error("taproot sighash error: {0}")]
    TaprootError(#[from] bdk_wallet::bitcoin::sighash::TaprootError),

    #[error("miniscript error: {0}")]
    MiniscriptError(#[from] bdk_wallet::miniscript::Error),

    #[error("descriptor error: {0}")]
    NoKey(String),

    #[error("witness error: {0}")]
    WitnessError(String),

    #[error("sign error: {0}")]
    SignError(String),

    #[error("other error: {0}")]
    Error(String),
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

pub struct Htlc {
    pub preimage: [u8; 32],
    pub older_blocks: u32,
    pub claim_addrinfo: AddressInfo,
    pub refund_addrinfo: AddressInfo,
}

impl Htlc {
    pub fn new(
        preimage: Vec<u8>,
        older_blocks: u32,
        claim_addrinfo: AddressInfo,
        refund_addrinfo: AddressInfo,
    ) -> Result<Self, HtlcError> {
        Ok(Self {
            preimage: preimage
                .try_into()
                .map_err(|_| HtlcError::Error("invalid preimage length".into()))?,
            older_blocks,
            claim_addrinfo,
            refund_addrinfo,
        })
    }

    pub fn generate_descriptor(
        &self,
        wallet: &Wallet,
    ) -> Result<Descriptor<DescriptorPublicKey>, HtlcError> {
        let payment_hash: sha256::Hash = sha256::Hash::hash(&self.preimage);
        let claim_xonly = convert_descriptor(wallet, &self.claim_addrinfo)?;
        let refund_xonly = convert_descriptor(wallet, &self.refund_addrinfo)?;
        let intr_ext = DescriptorPublicKey::from_str(NUMS_XPUBKEY)
            .inspect_err(|e| eprintln!("Internal key error: {}", e))
            .unwrap();
        let (htlc_descriptor, _key_map, _networks) = descriptor!(
            tr(
                intr_ext,
                {
                    and_v(v:sha256(payment_hash), pk(claim_xonly)),
                    and_v(v:older(self.older_blocks), pk(refund_xonly))
                }
            )
        )?;
        Ok(htlc_descriptor)
    }

    pub fn witness_stack_for_claim(
        &self,
        wallet: &Wallet,
        htlc_descriptor: &Descriptor<DescriptorPublicKey>,
        spend_tx: &Transaction,
        txout: TxOut,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let payment_hash: sha256::Hash = sha256::Hash::hash(&self.preimage);
        let claim_xonly = convert_descriptor(wallet, &self.claim_addrinfo)?;
        let htlc_derived = htlc_descriptor.at_derivation_index(0)?;

        let mut preimages = BTreeMap::new();
        preimages.insert(payment_hash, self.preimage);

        self.witness_stack(
            wallet,
            &htlc_derived,
            spend_tx,
            txout,
            &self.claim_addrinfo,
            claim_xonly,
            preimages,
            None,
            "claim",
        )
    }

    pub fn witness_stack_for_refund(
        &self,
        wallet: &Wallet,
        htlc_descriptor: &Descriptor<DescriptorPublicKey>,
        spend_tx: &Transaction,
        txout: TxOut,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let refund_xonly = convert_descriptor(wallet, &self.refund_addrinfo)?;
        let htlc_derived = htlc_descriptor.at_derivation_index(0)?;

        self.witness_stack(
            wallet,
            &htlc_derived,
            spend_tx,
            txout,
            &self.refund_addrinfo,
            refund_xonly,
            BTreeMap::new(),
            Some(spend_tx.input[0].sequence.to_consensus_u32()),
            "refund",
        )
    }

    fn witness_stack(
        &self,
        wallet: &Wallet,
        htlc_derived: &Descriptor<DefiniteDescriptorKey>,
        spend_tx: &Transaction,
        txout: TxOut,
        addr_info: &AddressInfo,
        xonly: XOnlyPublicKey,
        preimages: BTreeMap<sha256::Hash, Preimage32>,
        sequence: Option<u32>,
        leaf_name: &str,
    ) -> Result<Vec<Vec<u8>>, HtlcError> {
        let spend_data = taproot_spend_data(htlc_derived, xonly, leaf_name)?;
        let taproot_sig =
            sign_taproot_script_spend(wallet, addr_info, spend_tx, txout, spend_data.leaf_hash)?;

        let pk = PublicKey::from(xonly.public_key(bdk_wallet::bitcoin::secp256k1::Parity::Even));

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

        let secp = wallet.secp_ctx();
        let htlc_definite = htlc_derived.derived_descriptor(secp)?;
        let (witness_stack, _script_sig) = htlc_definite.get_satisfaction(satisfier)?;
        Ok(witness_stack)
    }
}

fn taproot_spend_data(
    htlc_derived: &Descriptor<DefiniteDescriptorKey>,
    xonly: XOnlyPublicKey,
    leaf_name: &str,
) -> Result<TaprootSpendData, HtlcError> {
    let Descriptor::Tr(tr) = htlc_derived else {
        return Err(HtlcError::WitnessError(
            "expected Taproot descriptor".into(),
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
        .ok_or_else(|| HtlcError::WitnessError(format!("{leaf_name} leaf not found")))?;

    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    Ok(TaprootSpendData {
        leaf_script,
        control_block,
        leaf_hash,
    })
}

fn sign_taproot_script_spend(
    wallet: &Wallet,
    addr_info: &AddressInfo,
    spend_tx: &Transaction,
    txout: TxOut,
    leaf_hash: TapLeafHash,
) -> Result<TaprootSig, HtlcError> {
    let prevouts = [txout];
    let mut sighash_cache = SighashCache::new(spend_tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::Default,
    )?;

    let msg = bdk_wallet::bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let signature = sign_shnorr(wallet, addr_info, &msg)?;

    Ok(TaprootSig {
        signature,
        sighash_type: TapSighashType::Default,
    })
}

fn convert_descriptor(
    wallet: &Wallet,
    addr_info: &bdk_wallet::AddressInfo,
) -> Result<XOnlyPublicKey, HtlcError> {
    let secp = wallet.secp_ctx();
    let xonly: XOnlyPublicKey = {
        let desc = wallet
            .public_descriptor(KeychainKind::External)
            .at_derivation_index(addr_info.index)?
            .derived_descriptor(secp)?;
        match desc {
            Descriptor::Tr(tr) => tr.internal_key().inner.x_only_public_key().0,
            _ => Err(HtlcError::NoKey("Expected Taproot descriptor".into()))?,
        }
    };
    Ok(xonly)
}

fn sign_shnorr(
    wallet: &Wallet,
    addr_info: &bdk_wallet::AddressInfo,
    msg: &Message,
) -> Result<Signature, HtlcError> {
    let secp = wallet.secp_ctx();
    let signers = wallet.get_signers(KeychainKind::External);
    let dsk = signers
        .signers()
        .iter()
        .find_map(|&s| s.descriptor_secret_key())
        .ok_or_else(|| HtlcError::SignError("no secret key in wallet".into()))?;

    let sec_key = match dsk {
        bdk_wallet::keys::DescriptorSecretKey::XPrv(xkey) => {
            let child = ChildNumber::from_normal_idx(addr_info.index)?;
            let mut path_vec: Vec<ChildNumber> =
                xkey.derivation_path.into_iter().copied().collect();
            path_vec.push(child);
            let full_path = DerivationPath::from(path_vec);
            xkey.xkey.derive_priv(secp, &full_path)?.private_key
        }
        _ => return Err(HtlcError::SignError("expected xprv signer".into())),
    };
    let keypair = Keypair::from_secret_key(secp, &sec_key);
    Ok(secp.sign_schnorr(msg, &keypair))
}
