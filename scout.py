#!/usr/bin/env python3
"""scout.py — GitHub 公开节点源自动搜集 (CI 用, 幂等)。

流程: 搜「近 30 天还活跃」的节点/订阅类公开仓 → 找仓库里的节点文件 (txt/yaml/json)
→ raw 拉取验证「真的含节点」(URI 行 / base64 blob / clash proxies) → 新源去重追加进
pools.txt。无鉴权 (search API 10 req/min, 靠 sleep 控制); 任何异常只告警不中断,
让后续 collect 步骤照常跑。
"""
import os, re, time, json, base64, datetime
import urllib.request, urllib.parse

UA = {"User-Agent": "freesub-scout (public repo collector)"}
POOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pools.txt")

def gh(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

def raw_text(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(400_000).decode("utf-8", "replace")

URI_RE = re.compile(r"^(vless|vmess|trojan|ss|ssr|hysteria|hy2|tuic|anytls|http)://", re.I | re.M)

# 时间预算: 搜集阶段最多 6 分钟 + 每次运行最多加 50 新源 (剩下的下轮自然再搜到),
# 保证「搜集+去重」整轮 << 1h (collect 工作流 55min 硬顶)。
SCOUT_TIME_BUDGET = 360
SCOUT_MAX_NEW = 50

def score(text):
    """(像不像节点文件, 估算节点数)。认三种形态: URI 行 / base64 blob / clash proxies。"""
    n = len(URI_RE.findall(text))
    if n >= 5:
        return True, n
    m = re.search(r"[A-Za-z0-9+/=]{500,}", text)
    if m:
        try:
            n2 = len(URI_RE.findall(base64.b64decode(m.group(0)[:120_000]).decode("utf-8", "replace")))
            if n2 >= 5:
                return True, n2
        except Exception:
            pass
    if re.search(r"^proxies:\s*$", text, re.M) and re.search(r"-\s*name:", text, re.M):
        return True, len(re.findall(r"-\s*name:", text, re.M))
    return False, 0

QUERIES = [
    "v2ray subscribe", "vless reality", "vless free", "clash subscription",
    "clash-meta sub", "hysteria2 free", "hysteria nodes", "xray share",
    "trojan subscription", "shadowsocks free", "sing-box nodes", "quantumult sub",
    "free vpn subscribe", "public proxy list", "vpn sub github", "wireguard free",
    "clash 订阅", "免费节点", "免费机场 订阅", "机场 分享 订阅",
    "vless 订阅", "翻墙 节点", "代理 订阅 免费", "hysteria 机场",
]


def pick_queries(k=5):
    """按 4h 块轮转取 k 个不同 query → 多轮覆盖不同切片, 持续发现新源 (不再只盯同一批 top)。"""
    blk = int(time.time() // 14400)
    idx = blk % len(QUERIES)
    return [QUERIES[(idx + i) % len(QUERIES)] for i in range(k)]


REPOS_SCAN_CAP = 25          # core API (无鉴权 60/h) 安全线: 每轮只深扫 ≤25 仓
SEARCH_PAGES = 2             # 分页, per_page=50 → 越过 top-15 找冷门仓


FILE_RE = re.compile(r"(?i)(v2ray|vless|clash|subscribe|sub-?[0-9]|nodes?|proxy|free[-_]?sub|output|result|merged|share|subscription)[-_./]")


def candidates(repo):
    owner, name = repo["full_name"].split("/", 1)
    branch = repo.get("default_branch") or "main"
    try:
        d = gh(f"https://api.github.com/repos/{owner}/{name}/git/trees/{branch}")
    except Exception:
        return []
    out = []
    trees = [d]
    for t in d.get("tree", []):
        if t["type"] == "tree" and t["path"].lower() in ("output", "result", "results", "sub", "subs"):
            try:
                trees.append(gh(f"https://api.github.com/repos/{owner}/{name}/git/trees/{t['sha']}"))
            except Exception:
                pass
    for dd in trees:
        for t in dd.get("tree", []):
            if t["type"] != "blob":
                continue
            p = t["path"]
            if p.lower().endswith((".txt", ".yaml", ".yml", ".sub", ".json")) and FILE_RE.search(p):
                out.append((f"{owner}/{name}", branch, p))
    return out[:20]


def scan_repo(repo, have, new, stats):
    """一仓 → 候选节点文件 → raw 验真 → 入 new。受 REPOS_SCAN_CAP 控 core API 量。"""
    if stats["repos"] >= REPOS_SCAN_CAP:
        return
    for owner_repo, branch, p in candidates(repo):
        if stats["repos"] >= REPOS_SCAN_CAP:
            break
        url = f"https://raw.githubusercontent.com/{owner_repo}/{branch}/{urllib.parse.quote(p)}"
        if url in have:
            continue
        try:
            ok, n = score(raw_text(url))
        except Exception:
            continue
        if ok:
            new.append((url, n, repo["full_name"]))
            print(f"[+] {repo['full_name']} :: {p}  ~{n} 节点")
        time.sleep(1.0)


def main():
    have = set()
    if os.path.exists(POOLS):
        have = {l.strip() for l in open(POOLS, encoding="utf-8").read().splitlines()
                if l.strip() and not l.startswith("#")}
    new, seen, stats = [], set(), {"repos": 0, "api_fail": 0}
    t_start = time.time()
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=30)).strftime("%Y-%m-%d")

    # ① 轮转 query + 分页 (per_page=50, 越 top-15)
    for q in pick_queries(5):
        if time.time() - t_start > SCOUT_TIME_BUDGET or len(new) >= SCOUT_MAX_NEW or stats["repos"] >= REPOS_SCAN_CAP:
            break
        for page in range(1, SEARCH_PAGES + 1):
            if time.time() - t_start > SCOUT_TIME_BUDGET or len(new) >= SCOUT_MAX_NEW or stats["repos"] >= REPOS_SCAN_CAP:
                break
            try:
                d = gh("https://api.github.com/search/repositories?" +
                       urllib.parse.urlencode({"q": q, "sort": "updated", "per_page": 50, "page": page}))
            except Exception as e:
                stats["api_fail"] += 1
                print(f"[!] 搜索失败 {q!r} p{page}: {e} (疑限流, 退避)")
                time.sleep(30)
                break
            for repo in d.get("items", []):
                if stats["repos"] >= REPOS_SCAN_CAP or time.time() - t_start > SCOUT_TIME_BUDGET or len(new) >= SCOUT_MAX_NEW:
                    break
                fn = repo["full_name"]
                if fn in seen:
                    continue
                seen.add(fn)
                if (repo.get("pushed_at") or "")[:10] < cutoff or repo.get("size", 0) > 50_000:
                    continue
                stats["repos"] += 1
                scan_repo(repo, have, new, stats)
                time.sleep(1.0)
            time.sleep(8)      # search API 10/min

    # ② 新仓切片: created:>7 天 (常规 sort=updated 永远盯老牌仓, 新冒头的仓靠这个抓)
    since = (datetime.datetime.utcnow() - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
    if len(new) < SCOUT_MAX_NEW and time.time() - t_start < SCOUT_TIME_BUDGET:
        for q in pick_queries(2):
            if stats["repos"] >= REPOS_SCAN_CAP + 10:
                break
            try:
                d = gh("https://api.github.com/search/repositories?" +
                       urllib.parse.urlencode({"q": f"{q} created:>{since}", "sort": "created", "per_page": 30}))
            except Exception as e:
                stats["api_fail"] += 1
                print(f"[!] 新仓搜索失败 {q!r}: {e}")
                time.sleep(30)
                continue
            for repo in d.get("items", []):
                if stats["repos"] >= REPOS_SCAN_CAP + 10 or len(new) >= SCOUT_MAX_NEW or time.time() - t_start > SCOUT_TIME_BUDGET:
                    break
                fn = repo["full_name"]
                if fn in seen:
                    continue
                seen.add(fn)
                stats["repos"] += 1
                scan_repo(repo, have, new, stats)
                time.sleep(1.0)

    if new:
        stamp = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        with open(POOLS, "a", encoding="utf-8") as f:
            f.write(f"\n# gh-scout {stamp} 自动搜集 +{len(new)} 源 (活跃+新仓轮转 + raw 验真)\n")
            for u, n, fn in new:
                f.write(f"{u}\n")
        print(f"[+] pools.txt +{len(new)} 源 (现 {len(have) + len(new)} 源, 扫 {stats['repos']} 仓, API失败 {stats['api_fail']})")
    else:
        print(f"[*] 未发现新源 (现有 {len(have)} 源, 扫 {stats['repos']} 仓, API失败 {stats['api_fail']})")


if __name__ == "__main__":
    main()
