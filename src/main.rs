mod htlc;

use bdk_electrum::{BdkElectrumClient, electrum_client, electrum_client::Client};
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{
        Address, Amount, Network, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        Witness, absolute,
        bip32::Xpriv,
        consensus::serialize,
        key::rand::{self, RngCore},
        secp256k1::XOnlyPublicKey,
        transaction,
    },
    chain::spk_client::{SyncRequest, SyncRequestBuilder},
    miniscript::Descriptor,
    template::{Bip86, DescriptorTemplate},
};

use htlc::Htlc;

const ELECTRUM_SERVER: &str = "tcp://localhost:50001";
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;
const NETWORK: Network = Network::Regtest;
const WATCH_DURATION_SECS: u64 = 1;

const ADDR1_INDEX: u32 = 0;
const ADDR2_INDEX: u32 = 1;

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

    let htlc = Htlc::new(preimage.to_vec(), 16, addr1.clone(), addr2.clone())?;
    let htlc_descriptor = htlc.generate_descriptor(&wallet)?;
    let htlc_derived = htlc_descriptor.at_derivation_index(0)?;
    let htlc_address = htlc_derived.address(NETWORK)?;
    println!("HTLC Address: {}", htlc_address);

    let tx = watch_address(&mut wallet, &htlc_address);
    let txid = tx.compute_txid();
    let (index, txout) = match tx
        .output
        .iter()
        .enumerate()
        .find(|&(_, item)| item.script_pubkey == htlc_address.script_pubkey())
    {
        Some(res) => res,
        None => anyhow::bail!("HTLC output not found in the transaction"),
    };
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

    let witness =
        htlc.witness_stack_for_claim(&wallet, &htlc_descriptor, &spend_tx, txout.clone())?;
    spend_tx.input[0].witness = Witness::from_slice(&witness);
    println!("spend_tx: {}", hex::encode(serialize(&spend_tx)));

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

    // // ── 署名を再検証 ─────────────────────────────────────────────────────
    // secp.verify_schnorr(
    //     &sig,
    //     &bdk_wallet::bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()),
    //     &addr1_xonly,
    // )
    // .map_err(|e| anyhow::anyhow!("sig verify failed: {e}"))?;

    // println!("\n✓ Schnorr 署名の検証 OK");
    // println!(
    //     "✓ witness: [sig({} B), preimage({} B), leaf_script({} B), control_block({} B)]",
    //     witness.nth(0).map(|x| x.len()).unwrap_or(0),
    //     witness.nth(1).map(|x| x.len()).unwrap_or(0),
    //     witness.nth(2).map(|x| x.len()).unwrap_or(0),
    //     witness.nth(3).map(|x| x.len()).unwrap_or(0),
    // );

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
