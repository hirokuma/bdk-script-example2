# bdk-script-example2

BDKでHTLCを作ってpreimageが必要なルート。  
このブランチではP2TRでminiscript/descriptorを使って記述している。

* [https://blog.hirokuma.work/2026/05/20260510-bdk](https://blog.hirokuma.work/2026/05/20260510-bdk)

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

P2TRなのでleafごとにスクリプトを持つ。
今回は上側を通る。

```
tr(
    intr_ext,
    {
        and_v(v:sha256(payment_hash), pk(addr1_xonly)),
        and_v(v:older(16),            pk(addr2_xonly))
    }
)
```
