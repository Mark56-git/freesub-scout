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

QUERIES = ["v2ray subscribe free", "vless reality", "clash 订阅", "hysteria2 节点", "免费节点 订阅"]
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
            if not p.lower().endswith((".txt", ".yaml", ".yml", ".sub", ".json")):
                continue
            if FILE_RE.search(p):
                out.append((f"{owner}/{name}", branch, p))
    return out[:30]


def main():
    have = set()
    if os.path.exists(POOLS):
        have = {l.strip() for l in open(POOLS, encoding="utf-8").read().splitlines()
                if l.strip() and not l.startswith("#")}
    new, seen = [], set()
    t_start = time.time()
    cutoff = "2026-09-01"
    for q in QUERIES:
        if time.time() - t_start > SCOUT_TIME_BUDGET or len(new) >= SCOUT_MAX_NEW:
            break
        try:
            d = gh("https://api.github.com/search/repositories?" +
                   urllib.parse.urlencode({"q": q, "sort": "updated", "per_page": 15}))
        except Exception as e:
            print(f"[!] scout 搜索失败 {q!r}: {e} (跳过该 query)")
            continue
        for repo in d.get("items", []):
            if time.time() - t_start > SCOUT_TIME_BUDGET or len(new) >= SCOUT_MAX_NEW:
                break
            fn = repo["full_name"]
            if fn in seen or (repo.get("pushed_at") or "")[:10] < cutoff or repo.get("size", 0) > 50_000:
                seen.add(fn)
                continue
            seen.add(fn)
            for owner_repo, branch, p in candidates(repo):
                if time.time() - t_start > SCOUT_TIME_BUDGET or len(new) >= SCOUT_MAX_NEW:
                    break
                url = f"https://raw.githubusercontent.com/{owner_repo}/{branch}/{urllib.parse.quote(p)}"
                if url in have:
                    continue
                try:
                    ok, n = score(raw_text(url))
                except Exception:
                    continue
                if ok:
                    new.append((url, n, fn))
                    print(f"[+] {fn} :: {p}  ~{n} 节点")
                time.sleep(1.0)
        time.sleep(3.0)

    if new:
        stamp = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        with open(POOLS, "a", encoding="utf-8") as f:
            f.write(f"\n# gh-scout {stamp} 自动搜集 +{len(new)} 源 (近 30 天活跃 + raw 验真)\n")
            for u, n, fn in new:
                f.write(f"{u}\n")
        print(f"[+] pools.txt +{len(new)} 源 (现 {len(have) + len(new)} 源)")
    else:
        print("[*] 未发现新源 (现有 %d 源)" % len(have))


if __name__ == "__main__":
    main()
