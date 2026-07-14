mod htlc;

use std::io::{self, Write};

use bdk_electrum::{BdkElectrumClient, electrum_client, electrum_client::Client};
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{
        Address, Network, NetworkKind, OutPoint, Transaction,
        bip32::Xpriv,
        consensus::serialize,
        key::rand::{self, RngCore},
    },
    chain::spk_client::{SyncRequest, SyncRequestBuilder},
    template::{Bip86, DescriptorTemplate},
};
use tracing_subscriber::{EnvFilter, prelude::*};

use htlc::Htlc;

const ELECTRUM_SERVER: &str = "tcp://localhost:50001";
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;
const NETWORK: Network = Network::Regtest;
const WATCH_DURATION_SECS: u64 = 1;

const HTLC_CSV: u32 = 16;
const ADDR1_INDEX: u32 = 0;
const ADDR2_INDEX: u32 = 10;

enum SpendPath {
    Claim,
    Refund,
}

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder().parse_lossy("debug");
    tracing_subscriber::Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_filter(filter),
        )
        .init();

    // preimageを後で取得する受取先
    // 正常に処理されて受け取ることを期待するアドレス(claim)
    let seed1 = create_seed();
    let mut wallet1 = create_wallet(&seed1);
    full_scan(&mut wallet1);
    let addr1 = wallet1.peek_address(KeychainKind::External, ADDR1_INDEX);
    let addr1_xonly_pubkey = htlc::convert_xonly_pubkey(&wallet1, &addr1)?;
    println!(
        "address(claim): {}, index={}, xpubkey={}",
        addr1.address, addr1.index, addr1_xonly_pubkey
    );
    // 確認のため作り直しておく
    let addr1_xonly_pubkey_str = addr1_xonly_pubkey.to_string();
    let addr1_xonly_pubkey = htlc::xonly_pubkey(&addr1_xonly_pubkey_str)?;

    // 16ブロック後の受取先
    // 正常に処理されずにタイムアウトして戻されるアドレス(refund)
    let seed2 = create_seed();
    let mut wallet2 = create_wallet(&seed2);
    full_scan(&mut wallet2);
    let addr2 = wallet2.peek_address(KeychainKind::External, ADDR2_INDEX);
    let addr2_xonly_pubkey = htlc::convert_xonly_pubkey(&wallet2, &addr2)?;
    println!(
        "address(refund): {}, index={}, xpubkey={}",
        addr2.address, addr2.index, addr2_xonly_pubkey
    );
    // 確認のため作り直しておく
    let addr2_xonly_pubkey_str = addr2_xonly_pubkey.to_string();
    let addr2_xonly_pubkey = htlc::xonly_pubkey(&addr2_xonly_pubkey_str)?;

    let preimage = htlc::generate_preimage();
    println!("preimage: {}", hex::encode(preimage.0));
    println!("preimage_hash: {}", hex::encode(preimage.1));

    let htlc_claim = Htlc::new(
        &wallet1,
        preimage.1,
        HTLC_CSV,
        addr1.index,
        addr1_xonly_pubkey,
        addr2.index,
        addr2_xonly_pubkey,
    )?;
    let htlc_refund = Htlc::new(
        &wallet2,
        preimage.1,
        HTLC_CSV,
        addr1.index,
        addr1_xonly_pubkey,
        addr2.index,
        addr2_xonly_pubkey,
    )?;

    let htlc_address = htlc_claim.address(NETWORK)?;
    println!("HTLC Address: {}", htlc_address);

    // refundでも同じ情報になる
    let htlc_address2 = htlc_refund.address(NETWORK)?;
    assert_eq!(htlc_address, htlc_address2);

    let tx = watch_address(&wallet1, &htlc_address);
    let txid = tx.compute_txid();
    let (index, prev_txout) = match tx
        .output
        .iter()
        .enumerate()
        .find(|&(_, item)| item.script_pubkey == htlc_address.script_pubkey())
    {
        Some(res) => res,
        None => anyhow::bail!("HTLC output not found in the transaction"),
    };
    let prev_outpoint = OutPoint {
        txid,
        vout: index as u32,
    };
    println!("Spendable outpoint: {}", prev_outpoint);

    let spend_path = select_spend_path(htlc_refund.csv_blocks)?;
    let destination = match spend_path {
        SpendPath::Claim => &addr1.address,
        SpendPath::Refund => &addr2.address,
    };
    let spend_tx_vin = 0; // vin#0 固定
    let spend_tx = match spend_path {
        SpendPath::Claim => {
            htlc_claim.create_claim_tx(prev_outpoint, prev_txout, spend_tx_vin, preimage.0, 1.0)?
        }
        SpendPath::Refund => {
            htlc_refund.create_refund_tx(prev_outpoint, prev_txout, spend_tx_vin, 1.0)?
        }
    };
    println!("spend_tx: {}", hex::encode(serialize(&spend_tx)));

    let labels = match spend_path {
        SpendPath::Claim => ["Schnorr sig", "preimage", "leaf script", "control block"].as_slice(),
        SpendPath::Refund => ["Schnorr sig", "leaf script", "control block"].as_slice(),
    };

    // ── 結果表示 ─────────────────────────────────────────────────────────
    let witness = &spend_tx.input[spend_tx_vin].witness;
    println!("\n  witness stack ({} items):", witness.len());
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

    let _ = watch_address(&wallet1, destination);
    println!("TX detected.");

    Ok(())
}

fn select_spend_path(csv_blocks: u32) -> anyhow::Result<SpendPath> {
    println!("How do you want to solve the HTLC script?");
    println!("  1: solve with preimage");
    println!("  2: solve after {} blocks", csv_blocks);
    print!("Select 1 or 2: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match input.trim() {
        "1" => Ok(SpendPath::Claim),
        "2" => Ok(SpendPath::Refund),
        other => anyhow::bail!("invalid selection: {other}. expected 1 or 2"),
    }
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

fn watch_address(wallet: &Wallet, addr: &Address) -> Transaction {
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
