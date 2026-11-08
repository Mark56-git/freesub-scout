# freesub-scout

自动搜集并凝聚去重 GitHub 上的**公开**节点源。

## 本仓库做什么
- **搜集**（`scout.py`）：搜近 30 天仍活跃的 GitHub 节点/订阅类公开仓 → 找仓库内节点文件 → raw 验证确实含节点 → 去重追加进 `pools.txt`。幂等；单轮 6 分钟时间预算、最多加 50 个源。
- **凝聚去重**（`subconv.py`）：零依赖归一化器——下载全部源，全协议解析（URI / base64 / Clash YAML / sing-box JSON / v2ray JSON），按「协议+服务器+端口+凭据+SNI+flow」指纹去重。
- **逐源溯源**（`pool/_sources.json`）：逐源清单（URL ↔ 贡献节点数 / 判重与丢弃原因）+ 逐节点来源索引（每个产物节点来自哪个源），便于按源归因与淘汰长期无贡献源。
- **池上限**（`POOL_CAP`）：池节点超过 10000 时按「源贡献量从大到小」裁剪（大源先让位），保持源多样性；CI 日志打 `[pool-cap]` 行。
- **定时**（`.github/workflows/collect.yml`）：**每 4h** 自动一轮「搜集 → 凝聚去重 → 池维护 → 有变化才提交」；整轮 < 1h（55min 硬顶，超时即失败下轮重跑，不留脏状态）；也可 workflow_dispatch 手动触发（改完 pools.txt 立即生效）。

## 产物（CI 自动更新）
| 文件 | 说明 |
|---|---|
| `pool/merged-v2ray.txt` | 全池 v2ray URI 行（去重后） |
| `pool/merged-v2ray-blob.txt` | 全池 base64 订阅 |
| `pool/merged-clash.yaml` | 全池 Clash/Mihomo 配置 |
| `pool/_sources.json` | 逐源溯源：逐源清单（URL ↔ 入池节点数、判重/丢弃计数）+ 逐节点来源索引 |

## 说明
- 仅聚合 GitHub 公开节点源（含自动发现的公开仓）与 `pools.txt` 内所列公开订阅，不含任何私人订阅/凭据。
- 节点可用性随时间衰减；本仓库只做**收集与格式归一/去重**，不保证可用性，也不做连通性/延迟检测。
- `pools.txt` 由 scout 自动维护，亦接受手动追加（`#` 注释）。
