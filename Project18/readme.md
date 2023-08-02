## *Project19: send a tx on Bitcoin testnet, and parse the tx data down to every bit

项目完成人：王庆华

testnet：[比特币测试网浏览器 — Blockchair](https://blockchair.com/zh/bitcoin/testnet)

get bitcoin：[Bitcoin testnet3 faucet (coinfaucet.eu)](https://coinfaucet.eu/en/btc-testnet/)

![](https://img1.imgtp.com/2023/07/07/6CLaX4Qp.png)

![](https://img1.imgtp.com/2023/07/07/DaVQKLjF.png)

address：miner8VH6WPrsQ1Fxqb7MPgJEoFYX2RCkS

![](https://img1.imgtp.com/2023/07/07/Mf6orCda.png)

TX:9d49a74c1b174a0ffca7b62106295bdd34f5c193c715e479ac31d57cb44ba524

hash:000000007c409bca04513369f186d91ffd374b295c676d2a38624f4391338eb3

details：

```apl
{
    "block_height": -1,
    "block_index": -1,
    "hash": "9d49a74c1b174a0ffca7b62106295bdd34f5c193c715e479ac31d57cb44ba524",
    "hex": "02000000000101196f91cfcf20a09a26a57255cba3ddead413f312ae688c4061548e35201695c10100000000fdffffff02e8ff1cb4000000001976a9142bbf24ce37e5e2e99a18d812bf1b8aea30be0d1188ac5b7e0f00000000001976a91423e077ffac6f109795a82021dc1698bd9ce4011988ac02473044022043955d7eecbd63bfc9166d2136f877d0c0594285e62a61dc3512f1b73be5238c02205b4056c0013fc82ef706b5e882de2aeb174c1fd52a2086d06b65e3d8cf0f29630121027daf3d140b37c677964b1cfc9079de44183b1f6080f39491a8230e7552a31f7f2d3e2500",
    "addresses": [
        "miner8VH6WPrsQ1Fxqb7MPgJEoFYX2RCkS",
        "mjWGLCqF4e8DkFqmy7Y3EgoUtw7T5LyBkn",
        "tb1qy9293p4rqf3kq98jwg724k2y9amxstz7dfn0fl"
    ],
    "total": 3022814787,
    "fees": 14700,
    "size": 228,
    "vsize": 147,
    "preference": "high",
    "relayed_by": "89.105.221.245:18333",
    "received": "2023-07-07T04:55:42.14Z",
    "ver": 2,
    "lock_time": 2440749,
    "double_spend": false,
    "vin_sz": 1,
    "vout_sz": 2,
    "opt_in_rbf": true,
    "confirmations": 0,
    "inputs": [
        {
            "prev_hash": "c1951620358e5461408c68ae12f313d4eadda3cb5572a5269aa020cfcf916f19",
            "output_index": 1,
            "output_value": 3022829487,
            "sequence": 4294967293,
            "addresses": [
                "tb1qy9293p4rqf3kq98jwg724k2y9amxstz7dfn0fl"
            ],
            "script_type": "pay-to-witness-pubkey-hash",
            "age": 2440749,
            "witness": [
                "3044022043955d7eecbd63bfc9166d2136f877d0c0594285e62a61dc3512f1b73be5238c02205b4056c0013fc82ef706b5e882de2aeb174c1fd52a2086d06b65e3d8cf0f296301",
                "027daf3d140b37c677964b1cfc9079de44183b1f6080f39491a8230e7552a31f7f"
            ]
        }
    ],
    "outputs": [
        {
            "value": 3021799400,
            "script": "76a9142bbf24ce37e5e2e99a18d812bf1b8aea30be0d1188ac",
            "addresses": [
                "mjWGLCqF4e8DkFqmy7Y3EgoUtw7T5LyBkn"
            ],
            "script_type": "pay-to-pubkey-hash"
        },
        {
            "value": 1015387,
            "script": "76a91423e077ffac6f109795a82021dc1698bd9ce4011988ac",
            "addresses": [
                "miner8VH6WPrsQ1Fxqb7MPgJEoFYX2RCkS"
            ],
            "script_type": "pay-to-pubkey-hash"
        }
    ]
}
```

![](https://img1.imgtp.com/2023/07/07/YsgKh2o6.png)

脚本输出：

![](https://img1.imgtp.com/2023/07/07/znTaBKlK.png)
