# freesub-scout

自动搜集并凝聚去重 GitHub 上的**公开**节点源。

## 本仓库做什么
- **搜集**（`scout.py`）：搜近 30 天仍活跃的 GitHub 节点/订阅类公开仓 → 找仓库内节点文件 → raw 验证确实含节点 → 去重追加进 `pools.txt`。幂等；单轮 6 分钟时间预算、最多加 50 个源。
- **凝聚去重**（`subconv.py`）：零依赖归一化器——下载全部源，全协议解析，凭据指纹去重。
- **定时**（`.github/workflows/collect.yml`）：公开仓每 12h 自动一轮「搜集 → 凝聚去重 → 有变化才提交」；整轮 < 1h（55min 硬顶，超时即失败下轮重跑，不留脏状态）。私有期间定时停用，手动 Run 即可。

## 产物（CI 自动更新）
| 文件 | 说明 |
|---|---|
| `pool/merged-v2ray.txt` | 全池 v2ray URI 行（去重后） |
| `pool/merged-v2ray-blob.txt` | 全池 base64 订阅 |
| `pool/merged-clash.yaml` | 全池 Clash/Mihomo 配置 |
| `pool/pool-{0..5}-*` | 6 个打散小池 |
| `pool/pools.json` | 产物清单 |
| `pool/_sources.json` | 逐源溯源：URL ↔ 解析节点数/丢弃数 |

## 来源声明
仅聚合 GitHub 公开节点源（含自动发现的公开仓）与 `pools.txt` 内所列公开订阅，不含任何私人订阅/凭据；节点可用性随时间衰减。`pools.txt` 由 scout 自动维护，亦接受手动追加（`#` 注释）。
