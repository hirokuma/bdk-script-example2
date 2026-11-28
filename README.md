# bdk-script-example2

BDKでHTLCを作ってpreimageが必要なルート。
このブランチではP2TRで直接OPコードを使って記述している。

## 準備

RegTestでElectrum Serverを立てる。

* `tcp://localhost:50001`
  * ハードコーディングしているので適当に変更しても良い
* Bitcoin Coreでウォレットを作って、適当にマイニングして自由に扱えるBTCを取得しておく
* BlockstreamのDockerコンテナを使うのが楽だと思うが何でも良い
  * [参考](https://blog.hirokuma.work/bitcoin/01_basics/regtest.html#blockstream-esplora-docker-container)

## 実行

`cargo run` などで立ち上げるとウォレットを作りHTLCアドレスを出力する。  
その後、HTLCアドレスへの入金待ちになる。

出力されたアドレスにBitcoin Coreから `sendtoaddress` で適当に入金する。1BTCでよいだろう。  
そうすると待ち状態が解除される。

解除されると、preimageを必要とするルートを通して自分のウォレットに送金するトランザクションを作成する。  
トランザクションのHEX文字列が出力されて待ち状態になる。

Bitcoin Coreから `sendrawtransaction` でそのトランザクションを展開する。  
そうすると待ち状態が解除される。  

## 補足

P2TRのleafはminiscript / descriptorを使わず、生のスクリプト（tapscript）で2本構成している。
内部鍵はNUMSをそのまま使う。
今回の例ではclaim側を通る。

claim leaf(73byte)

```
OP_SIZE 0x20 OP_EQUALVERIFY
OP_SHA256 <preimage_hash> OP_EQUALVERIFY
<addr1_xonly> OP_CHECKSIG
```

refund leaf(37byte、`HTLC_CSV = 16`のとき)

```
0x10 OP_CHECKSEQUENCEVERIFY OP_DROP
<addr2_xonly> OP_CHECKSIG
```

`OP_CSV`は検証後にスタックの値を残すため、`OP_DROP`で除去する。
witnessはclaimルートが`[sig, preimage, script, control_block]`、refundルートが`[sig, script, control_block]`。
