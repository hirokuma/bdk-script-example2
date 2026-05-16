use std::{collections::BTreeMap, str::FromStr};

use bdk_electrum::{BdkElectrumClient, electrum_client, electrum_client::Client};
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{
        Address, Amount, Network, NetworkKind, OutPoint, PublicKey, ScriptBuf, Sequence,
        TapLeafHash, TapSighashType, Transaction, TxIn, Witness, absolute,
        bip32::{ChildNumber, DerivationPath, Xpriv},
        consensus::serialize,
        hashes::{Hash, sha256},
        key::{
            Keypair,
            rand::{self, RngCore},
        },
        secp256k1::{Message, XOnlyPublicKey, schnorr::Signature},
        sighash::{Prevouts, SighashCache},
        taproot::{ControlBlock, LeafVersion, Signature as TaprootSig},
        transaction,
    },
    chain::spk_client::{SyncRequest, SyncRequestBuilder},
    descriptor,
    keys::DescriptorPublicKey,
    miniscript::{Descriptor, Preimage32, Satisfier},
    template::{Bip86, DescriptorTemplate},
};

const ELECTRUM_SERVER: &str = "tcp://localhost:50001";
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;
const NETWORK: Network = Network::Regtest;
const WATCH_DURATION_SECS: u64 = 1;

// pick as internal key a "Nothing Up My Sleeve" (NUMS) point
// TODO H + rG
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
const NUMS_XPUBKEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// テストのため固定値
// const SEED: &str = "55a89a1ef590feea61ee171e84936fd3c1ee4aba94d4283cf74664b1191186ce";
const ADDR1_INDEX: u32 = 0;
const ADDR2_INDEX: u32 = 1;
// const PREIMAGE: &str = "465a9a18ea11c40ea501e7e1e4cfd6c9ae629999d3546ef4bb1e2e56590935ab";

fn main() -> anyhow::Result<()> {
    let seed = create_seed();
    // let seed = SEED.to_string();
    println!("Using seed: {}", seed);

    let mut wallet = create_wallet(&seed);
    full_scan(&mut wallet);

    // 最初のアドレス（preimage知っている場合の受取先）
    let addr1 = wallet.peek_address(KeychainKind::External, ADDR1_INDEX);
    println!("address 1: {}, index={}", addr1.address, addr1.index);

    // 2番目のアドレス（16ブロック後の受取先）
    let addr2 = wallet.peek_address(KeychainKind::External, ADDR2_INDEX);
    println!("address 2: {}, index={}", addr2.address, addr2.index);

    // preimageとpayment_hashの生成
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    // let preimage = hex::decode(PREIMAGE).unwrap();
    // let preimage: [u8; 32] = preimage.try_into().unwrap();
    println!("preimage: {}", hex::encode(preimage));
    let payment_hash: sha256::Hash = sha256::Hash::hash(&preimage);

    let addr1_xonly = convert_descriptor(&wallet, &addr1)?;
    let addr2_xonly = convert_descriptor(&wallet, &addr2)?;
    let intr_ext = DescriptorPublicKey::from_str(NUMS_XPUBKEY)
        .inspect_err(|e| eprintln!("Internal key error: {}", e))
        .unwrap();
    let (htlc_descriptor, _key_map, _networks) = descriptor!(
        tr(
            intr_ext,
            {
                and_v(v:sha256(payment_hash), pk(addr1_xonly)),
                and_v(v:older(16),            pk(addr2_xonly))
            }
        )
    )?;

    let htlc_derived = htlc_descriptor.at_derivation_index(0)?;
    let htlc_address = htlc_derived.address(Network::Regtest)?;
    println!("HTLC Address: {}", htlc_address);

    let tx = watch_address(&mut wallet, &htlc_address);
    let txid = tx.compute_txid();
    let mut index = 0;
    for txout in &tx.output {
        if txout.script_pubkey == htlc_address.script_pubkey() {
            break;
        }
        index += 1;
    }

    let txout = tx.output[index].clone();
    let prev_output = OutPoint {
        txid,
        vout: index as u32,
    };
    println!("Spendable outpoint: {}", prev_output);

    let fee = Amount::from_sat(1000);
    let out_value = Amount::from_sat(txout.value.to_sat() - fee.to_sat());
    let mut spend_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![transaction::TxOut {
            value: out_value,
            script_pubkey: addr1.address.script_pubkey(),
        }],
    };

    // ── Tapscript の claim leaf と control block を取り出す ───────────────
    //
    //  Descriptor::Tr(tr).spend_info() で TaprootSpendInfo を得る。
    //  script_map() はすべての (ScriptBuf, LeafVersion) → ControlBlock のマップ。
    //  claim leaf を特定するには、script bytes に claim_xonly の 32 バイトが含まれるかで判断。
    let (claim_leaf_script, claim_control_block): (ScriptBuf, ControlBlock) = match &htlc_derived {
        Descriptor::Tr(tr) => {
            let spend_info = tr.spend_info();
            let xonly_bytes = addr1_xonly.serialize(); // 32 bytes
            spend_info
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
                .ok_or_else(|| anyhow::anyhow!("claim leaf not found"))?
        }
        _ => anyhow::bail!("expected Taproot descriptor"),
    };

    let leaf_hash = TapLeafHash::from_script(&claim_leaf_script, LeafVersion::TapScript);

    // ── TapScript sighash を計算 ──────────────────────────────────────────
    //
    //  SighashCache::taproot_script_spend_signature_hash() に
    //  input index、prevouts、leaf hash、sighash type を渡す。
    let prevouts = [txout.clone()];
    let mut sighash_cache = SighashCache::new(&spend_tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::Default,
    )?;

    // ── claim_seckey で Schnorr 署名 ─────────────────────────────────────
    let msg = bdk_wallet::bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let sig = sign_shnorr(&wallet, &addr1, &msg)?;

    let taproot_sig = TaprootSig {
        signature: sig,
        sighash_type: TapSighashType::Default,
    };

    // ── Satisfier を実装して miniscript の get_satisfaction() で witness を得る ─
    //
    //  lookup_tap_leaf_script_sig: (PublicKey, TapLeafHash) → TaprootSig
    //  lookup_sha256             : sha256::Hash → preimage [u8; 32]
    //  lookup_tap_control_block_map: ControlBlock → (ScriptBuf, LeafVersion)
    //
    //  get_satisfaction() は witness stack (Vec<Vec<u8>>) と script_sig を返す。
    //  Tapscript の場合は script_sig は空で、witness stack に:
    //    [<sig>, <preimage>, <leaf_script>, <control_block>]
    //  が積まれる。

    struct ClaimSatisfier {
        sigs: BTreeMap<(PublicKey, TapLeafHash), TaprootSig>,
        preimages: BTreeMap<sha256::Hash, Preimage32>,
        control_blocks: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,
    }

    impl Satisfier<PublicKey> for ClaimSatisfier {
        fn lookup_tap_leaf_script_sig(
            &self,
            pk: &PublicKey,
            lh: &TapLeafHash,
        ) -> Option<TaprootSig> {
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
    }

    // Satisfier<PublicKey> のキーは bitcoin::PublicKey（compressed 33-byte）
    // claim_xonly → bitcoin::PublicKey へ変換（Taproot は even parity と仮定）
    let claim_pk =
        PublicKey::from(addr1_xonly.public_key(bdk_wallet::bitcoin::secp256k1::Parity::Even));

    let mut sigs = BTreeMap::new();
    sigs.insert((claim_pk, leaf_hash), taproot_sig);

    let mut preimages = BTreeMap::new();
    preimages.insert(payment_hash, preimage);

    let mut control_blocks = BTreeMap::new();
    control_blocks.insert(
        claim_control_block.clone(),
        (claim_leaf_script.clone(), LeafVersion::TapScript),
    );

    let satisfier = ClaimSatisfier {
        sigs,
        preimages,
        control_blocks,
    };

    // ── htlc_descriptor の DefiniteDescriptor（Descriptor<PublicKey>）を得る ─
    //
    //  definite_htlc は Descriptor<bitcoin::PublicKey> なので
    //  Satisfier<bitcoin::PublicKey> を実装する必要がある。
    //
    //  at_derivation_index(0) → DefiniteDescriptorKey を確定
    //  derived_descriptor(secp) → Descriptor<bitcoin::PublicKey>
    //  これに対して get_satisfaction(satisfier) を呼ぶ。
    let secp = wallet.secp_ctx();
    let htlc_definite = htlc_derived.derived_descriptor(secp)?;

    // get_satisfaction() → (witness_stack: Vec<Vec<u8>>, _script_sig: ScriptBuf)
    let (witness_stack, _script_sig) = htlc_definite.get_satisfaction(satisfier)?;

    // witness を spend_tx に設定
    spend_tx.input[0].witness = Witness::from_slice(&witness_stack);

    // ── 結果表示 ─────────────────────────────────────────────────────────
    let witness = &spend_tx.input[0].witness;
    println!("\n  witness stack ({} items):", witness.len());
    let labels = ["Schnorr sig", "preimage", "leaf script", "control block"];
    for (i, item) in witness.iter().enumerate() {
        let label = labels.get(i).unwrap_or(&"?");
        println!(
            "    [{}] {} ({} bytes): {}",
            i,
            label,
            item.len(),
            hex::encode(item)
        );
    }

    // ── 署名を再検証 ─────────────────────────────────────────────────────
    secp.verify_schnorr(
        &sig,
        &bdk_wallet::bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()),
        &addr1_xonly,
    )
    .map_err(|e| anyhow::anyhow!("sig verify failed: {e}"))?;

    println!("\n✓ Schnorr 署名の検証 OK");
    println!(
        "✓ witness: [sig({} B), preimage({} B), leaf_script({} B), control_block({} B)]",
        witness.nth(0).map(|x| x.len()).unwrap_or(0),
        witness.nth(1).map(|x| x.len()).unwrap_or(0),
        witness.nth(2).map(|x| x.len()).unwrap_or(0),
        witness.nth(3).map(|x| x.len()).unwrap_or(0),
    );
    println!("spend_tx: {}", hex::encode(serialize(&spend_tx)));

    let _ = watch_address(&mut wallet, &addr1);
    println!("TX detected.");

    Ok(())
}

fn create_seed() -> String {
    let mut seed: [u8; 32] = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    hex::encode(seed)
}

// https://bitcoindevkit.github.io/book-of-bdk/cookbook/keys-descriptors/descriptors/#using-descriptor-templates
fn create_wallet(seed_hex: &str) -> Wallet {
    let mut seed: [u8; 32] = [0u8; 32];
    hex::decode_to_slice(seed_hex, &mut seed).expect("Invalid seed hex");

    let kind = NetworkKind::from(NETWORK);
    let xprv: Xpriv = Xpriv::new_master(NETWORK, &seed).unwrap();
    let (descriptor, key_map, _) = Bip86(xprv, KeychainKind::External)
        .build(kind)
        .expect("Failed to build external descriptor");

    let (change_descriptor, change_key_map, _) = Bip86(xprv, KeychainKind::Internal)
        .build(kind)
        .expect("Failed to build internal descriptor");

    let external_descriptor_priv = descriptor.to_string_with_secret(&key_map);
    let internal_descriptor_priv = change_descriptor.to_string_with_secret(&change_key_map);
    Wallet::create(external_descriptor_priv, internal_descriptor_priv)
        .network(NETWORK)
        .create_wallet_no_persist()
        .expect("Failed to create wallet")
}

fn full_scan(wallet: &mut Wallet) {
    let client: BdkElectrumClient<Client> = BdkElectrumClient::new(
        electrum_client::Client::new(ELECTRUM_SERVER).expect("Failed to create Electrum client"),
    );

    let full_scan_request = wallet.start_full_scan();
    let update = client
        .full_scan(full_scan_request, STOP_GAP, BATCH_SIZE, true)
        .expect("Failed to perform full scan");
    wallet.apply_update(update).expect("Failed to apply update");
}

fn watch_address(wallet: &mut Wallet, addr: &Address) -> Transaction {
    let client: BdkElectrumClient<Client> = BdkElectrumClient::new(
        electrum_client::Client::new(ELECTRUM_SERVER).expect("Failed to create Electrum client"),
    );

    let tx: Transaction;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(WATCH_DURATION_SECS));

        let sync_request = sync_request(wallet, addr);
        let sync_response = client
            .sync(sync_request, BATCH_SIZE, false)
            .expect("Failed to sync");
        if !sync_response.tx_update.txs.is_empty() {
            tx = (*sync_response.tx_update.txs[0]).clone();
            break;
        }
    }
    tx
}

fn sync_request(
    wallet: &Wallet,
    addr: &Address,
) -> SyncRequestBuilder<(bdk_wallet::KeychainKind, u32)> {
    let mut spks_to_sync = std::collections::BTreeSet::new();

    // Externalアドレスのみチェックする
    if let Some(derived_index) = wallet.derivation_index(KeychainKind::External) {
        for index in 0..=derived_index {
            let address_info = wallet.peek_address(KeychainKind::External, index);
            spks_to_sync.insert((
                (KeychainKind::External, index),
                address_info.address.script_pubkey(),
            ));
        }
    }
    spks_to_sync.insert(((KeychainKind::External, 0), addr.script_pubkey()));
    for tx in wallet.transactions() {
        if tx.chain_position.is_unconfirmed() {
            for out in &tx.tx_node.tx.output {
                if let Some(index) = wallet.spk_index().index_of_spk(out.script_pubkey.clone()) {
                    spks_to_sync.insert((*index, out.script_pubkey.clone()));
                }
            }
        }
    }
    let chain_tip = wallet.local_chain().tip();
    SyncRequest::builder()
        .chain_tip(chain_tip)
        .spks_with_indexes(spks_to_sync)
}

fn convert_descriptor(
    wallet: &Wallet,
    addr_info: &bdk_wallet::AddressInfo,
) -> anyhow::Result<XOnlyPublicKey> {
    let secp = wallet.secp_ctx();
    let xonly: XOnlyPublicKey = {
        let desc = wallet
            .public_descriptor(KeychainKind::External)
            .at_derivation_index(addr_info.index)?
            .derived_descriptor(secp)?;
        match desc {
            Descriptor::Tr(tr) => tr.internal_key().inner.x_only_public_key().0,
            _ => anyhow::bail!("expected Taproot descriptor"),
        }
    };
    Ok(xonly)
}

fn sign_shnorr(
    wallet: &Wallet,
    addr_claim_info: &bdk_wallet::AddressInfo,
    msg: &Message,
) -> anyhow::Result<Signature> {
    let secp = wallet.secp_ctx();
    let signers = wallet.get_signers(KeychainKind::External);
    let dsk = signers
        .signers()
        .iter()
        .find_map(|&s| s.descriptor_secret_key())
        .ok_or_else(|| anyhow::anyhow!("no secret key in wallet"))?;

    let sec_key = match dsk {
        bdk_wallet::keys::DescriptorSecretKey::XPrv(xkey) => {
            // xkey.xkey        : ExtendedPrivKey（descriptor のルート鍵 tprv...）
            // xkey.derivation_path: /86'/1'/0'/0 部分
            // derive_priv でそこまで降りてから、wildcard の index を追加で derive する
            let child = ChildNumber::from_normal_idx(addr_claim_info.index)?;
            let mut path_vec: Vec<ChildNumber> =
                xkey.derivation_path.into_iter().copied().collect();
            path_vec.push(child);
            let full_path = DerivationPath::from(path_vec);
            xkey.xkey.derive_priv(secp, &full_path)?.private_key
        }
        _ => anyhow::bail!("expected xprv signer"),
    };
    let keypair = Keypair::from_secret_key(secp, &sec_key);
    Ok(secp.sign_schnorr(&msg, &keypair))
}
