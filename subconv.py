#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
subconv.py — 零依赖订阅格式转换/合并器（纯 Python 标准库，subconverter 的本地轻量替代）

功能：
  1. 读入本地文件（自动识别格式）：
     - base64 blob（整段 base64，解码后是 URI 列表）
     - URI 行（vless:// vmess:// trojan:// ss:// ssr:// hysteria2:// u2:// tuic://
       socks5:// socks5h:// http:// https://）
     - sing-box JSON（自动识别 "outbounds"）
     - Clash/Mihomo YAML（需 pip install pyyaml，没有就跳过该文件并提示）
  2. 解析 → 统一中间结构 → 去重（协议参数指纹）
  3. 输出：
     - merged-clash.yaml  （Mihomo/Clash Meta 完整配置：proxies + AUTO url-test 组 + 基础规则）
     - merged-v2ray.txt   （base64 通用订阅，v2rayN / 小火箭 / Hiddify 直接导入）

用法：
  python subconv.py <文件...或目录...> [-o 输出目录]
  python subconv.py --urls "https://a|https://b" [-o out] [--proxy http://127.0.0.1:7890]

说明：
  - 纯离线转换，不需要网络（--urls 才下载；本机走 Clash 时加 --proxy http://127.0.0.1:7890）
  - 支持协议：vless(reality/tls/ws/grpc) vmess trojan ss ssr hysteria2 tuic socks5 http/https
  - 免费节点仅供测试学习，勿用于敏感账号
"""
import argparse, base64, json, os, re, sys, time
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote, quote

WARN = {}          # 跳过的节点原因计数 {reason: n}
WARN_EX = {}       # {reason: [样本行×≤3]}：跳过统计里带样本，便于调试（"未知协议:ss"这类才能看到原行）
NODES = []         # 统一节点：(key, 归一dict, raw{raw/name/source}, kind)
# 溯源 + 逐源统计：当前在解析的源 (label=dl_N.sub/文件名, url=原始订阅 URL)
SRC = {'label': '', 'url': ''}
SMAP = {}          # {dl_N.sub basename: {'url':..., 'line':N}} fetch_urls 填、process_file 溯源用
SRC_STAT = {}          # {label: {'url':..., 'nodes':n, 'warns':{reason:n}}} 逐源解析/丢弃

def _log_src_added():
    st = SRC_STAT.setdefault(SRC['label'], {'url': SRC.get('url', ''), 'nodes': 0, 'warns': {}})
    st['nodes'] += 1
    if SRC.get('url'):
        st['url'] = SRC['url']

# ---------- 通用工具 ----------
def b64s(s):
    return base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8', 'replace')

def warn(reason, detail=''):
    WARN[reason] = WARN.get(reason, 0) + 1
    if detail:
        ex = WARN_EX.setdefault(reason, [])
        if len(ex) < 3:
            ex.append(detail[:80])
    lab = SRC.get('label')
    if lab:   # 解析期把丢弃/警告归因到源，便于定位"哪个源脏/重复/丢格式"
        st = SRC_STAT.setdefault(lab, {'url': SRC.get('url', ''), 'nodes': 0, 'warns': {}})
        st['warns'][reason] = st['warns'].get(reason, 0) + 1

_YAML_BOOT = None   # (ok, msg) 只修一次

def ensure_vendor_yaml():
    """vendor\\yaml（纯 Python pyyaml）自检+自修：
    副本坏掉/不可读时（import 出来的 yaml 是 namespace 包、没有 safe_load），
    自动从 PyPI/清华/阿里镜像下载 pyyaml 源码包，把纯 Python 包解到 vendor\\yaml（C 扩展不需要）。
    需要网络（用户机器环境跑）；无网/失败时静默返回，YAML 源按旧行为跳过。
    返回 (ok: bool, msg: str)。"""
    global _YAML_BOOT
    if _YAML_BOOT:
        return _YAML_BOOT
    import importlib, tarfile, io, shutil
    vdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor')
    ydir = os.path.join(vdir, 'yaml')

    def _ok():
        for m in [m for m in list(sys.modules) if m == 'yaml' or m.startswith('yaml.')]:
            del sys.modules[m]
        importlib.invalidate_caches()
        if vdir not in sys.path:
            sys.path.insert(0, vdir)
        try:
            import yaml as _y
            return hasattr(_y, 'safe_load')
        except Exception:
            return False

    if os.path.isdir(vdir) and _ok():
        _YAML_BOOT = (True, 'vendor\\yaml 完好')
        return _YAML_BOOT

    # 清掉坏副本（目录 ACL 坏时 rmtree 会部分失败，ignore 掉继续）
    for sub in ('yaml', '_yaml'):
        shutil.rmtree(os.path.join(vdir, sub), ignore_errors=True)
    if os.path.isdir(vdir):
        for f in os.listdir(vdir):
            if f.startswith('pyyaml') and f.endswith('.dist-info'):
                shutil.rmtree(os.path.join(vdir, f), ignore_errors=True)

    def _get(url, timeout=40):
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 R2-subconv-yaml-boot'})
        try:
            return urllib.request.urlopen(req, timeout=timeout).read()
        except Exception:
            ph = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:7890',
                                              'https': 'http://127.0.0.1:7890'})
            return urllib.request.build_opener(ph).open(req, timeout=timeout).read()

    tar_url = None
    for meta in ('https://pypi.org/pypi/pyyaml/json',
                 'https://pypi.tuna.tsinghua.edu.cn/pypi/pyyaml/json'):
        try:
            j = json.loads(_get(meta))
            for u in j.get('urls', []):
                if u.get('packagetype') == 'sdist':
                    tar_url = u['url']
                    break
            if tar_url:
                break
        except Exception:
            continue
    if not tar_url:
        try:
            html = _get('https://mirrors.aliyun.com/pypi/simple/pyyaml/').decode('utf-8', 'replace')
            m = re.findall(r'href="([^"]+/pyyaml[^"]*\.tar\.gz[^"]*)"', html)
            tar_url = m[0] if m else None
        except Exception:
            pass
    if not tar_url:
        _YAML_BOOT = (False, '下载 pyyaml 失败（无网络/镜像全挂），YAML 源暂跳过')
        return _YAML_BOOT
    try:
        data = _get(tar_url, timeout=120)
        tf = tarfile.open(fileobj=io.BytesIO(data))
        # 找 sdist 里的 yaml 包根（lib/yaml/ 或 yaml/），整包解到 vendor\yaml
        roots = set()
        for m in tf.getmembers():
            nm = m.name.replace('\\', '/')
            if re.search(r'(^|/)(lib/)?yaml/__init__\.py$', nm):
                roots.add(nm[: nm.index('yaml/') + 5])
        if not roots:
            raise RuntimeError('sdist 里没找到 yaml 包')
        os.makedirs(ydir, exist_ok=True)
        for m in tf.getmembers():
            nm = m.name.replace('\\', '/')
            if not m.isfile():
                continue
            for root in roots:
                if nm.startswith(root + '/'):
                    dest = os.path.join(ydir, nm[len(root) + 1:])
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with tf.extractfile(m) as fh, open(dest, 'wb') as out:
                        out.write(fh.read())
                    break
        ok = _ok()
        _YAML_BOOT = (ok, 'vendor\\yaml 已自修（纯 Python pyyaml）' if ok else '自修后仍不可导入')
        return _YAML_BOOT
    except Exception as e:
        _YAML_BOOT = (False, f'自修失败: {type(e).__name__}: {str(e)[:80]}')
        return _YAML_BOOT

def hostport_split(netloc):
    """netloc 可能是 host:port / [ipv6]:port / host"""
    netloc = netloc or ''
    if netloc.startswith('['):
        m = re.match(r'\[(.*?)\](:\d+)?$', netloc)
        return (m.group(1), int(m.group(2)[1:])) if m else (netloc, 0)
    if ':' in netloc:
        h, p = netloc.rsplit(':', 1)
        return (h, int(p)) if p.isdigit() else (netloc, 0)
    return (netloc, 0)

def uhp(p):
    """urlparse 结果 → (host, port)，安全处理 userinfo / IPv6 / 非法端口"""
    try:
        return (p.hostname or '', p.port or 0)
    except ValueError:
        return hostport_split(p.netloc)

def _flagnorm(d):
    """把解析器产出的语义字段名规范化成 FlClash 内核实测可导入的写法
    （对齐 735754647 参考：servername / client-fingerprint / reality-opts / skip-cert-verify / sni / xhttp-opts）。"""
    t = d.get('type')
    # SNI：vless/vmess/anytls→servername；trojan/hysteria2→sni
    sni = d.pop('server-name', None)
    if sni is None:
        sni = d.pop('sni', None)
    if sni:
        d['sni' if t in ('trojan', 'hysteria2', 'hysteria') else 'servername'] = sni
    # 指纹
    fp = d.pop('fingerprint', None)
    if fp:
        d['client-fingerprint'] = fp
    # 跳过证书
    if d.pop('insecure', None) or d.get('skip-cert-verify'):
        d['skip-cert-verify'] = True
    # reality 公钥/短id → reality-opts。mihomo 真验边界（tools\_sid_test 实测）：
    # 偶数位 hex 全接受（2/16/32 位均可，空亦可），奇数位拒收整份配置 → 只省略奇数位/非hex
    pk, sid = d.pop('public-key', None), d.pop('short-id', None)
    if sid:
        s = str(sid)
        if not re.fullmatch(r'[0-9a-fA-F]*', s) or len(s) % 2 or len(s) > 32:
            warn('reality短id非法hex(省略)', s[:20])
            sid = None
    if pk or sid:
        ro = {}
        if pk: ro['public-key'] = pk
        if sid: ro['short-id'] = sid
        d['reality-opts'] = ro
    # hysteria2 salamander → obfs + obfs-password
    if t in ('hysteria2', 'hysteria') and d.get('obfs') == 'salamander':
        ob = d.pop('obfs-salamander', {})
        if ob.get('payload'):
            d['obfs-password'] = ob['payload']
    return d

def _finalize(d):
    """vmess 默认 + ss base64/去 2022 + TLS 跳证书 + udp + 字段规范化。
    返回 False 表示该节点应丢弃（mihomo 不兼容）。"""
    t = d.get('type')
    if t == 'vmess':
        d.setdefault('cipher', 'auto'); d.setdefault('alterId', 0)
    if t == 'ss':
        # mihomo 对 ss 强制要求 cipher 字段（缺了整份配置拒收 "unset fields: cipher"）；
        # 部分源（如 V2rayNG3 导出的 clash YAML）ss 节点不带 cipher → 补默认值
        d.setdefault('cipher', 'aes-256-cfb')
        cipher = str(d.get('cipher', ''))
        if cipher.startswith('2022-'):
            return False
        # 源数据损坏防护：cipher 混入二进制（如 TLS 握手字节 r\x16…）时 mihomo 报
        # "unknown method" 并拒收整份配置 → 直接剔除该节点
        if cipher and not re.fullmatch(r'[A-Za-z0-9\-]+', cipher):
            warn('ss cipher 损坏(剔除)', f"{d.get('server')}:{d.get('port')} {cipher[:20]!r}")
            return False
        # password 已在各解析源归一（URI/singbox/v2rayjson 明文→base64；clash YAML 本身 base64）
    if d.get('tls') or t in ('trojan', 'hysteria2', 'tuic'):
        d['insecure'] = True
    d['udp'] = True
    _flagnorm(d)
    return True

def add(clash_dict, raw_uri, kind):
    if not clash_dict.get('server') or not clash_dict.get('port'):
        warn('缺server/port', str(raw_uri.get('raw', ''))[:60]); return
    clash_dict.setdefault('name', raw_uri.get('name') or f"{kind}:{clash_dict['server']}:{clash_dict['port']}")
    # 去重指纹（用规范化前的稳定字段）
    key = (clash_dict.get('type'), clash_dict['server'], clash_dict['port'],
           str(clash_dict.get('uuid', clash_dict.get('password', ''))),
           str(clash_dict.get('server-name', clash_dict.get('sni', ''))), str(clash_dict.get('flow', '')))
    if any(k2 == key for k2, _, _, _ in NODES):
        warn('重复'); return
    if not _finalize(clash_dict):
        warn('ss2022加密(mihomo不兼容)', f"{clash_dict.get('server')}:{clash_dict.get('port')}"); return
    _ingest(key, clash_dict, raw_uri, kind)

def _strip_lone_surrogates(obj):
    """解析期根除孤立 surrogate (U+D800–DFFF) → U+FFFD（递归 dict/list/str）。
    写盘侧另有 utf-8/replace 兜底；这里在入库时就清，保证 NODES 里任何字符串
    都不带坏 encode，脏源（GBK 乱码/坏 base64 解码）不再崩管线。"""
    if isinstance(obj, str):
        return ''.join('\uFFFD' if 0xD800 <= ord(c) <= 0xDFFF else c for c in obj)
    if isinstance(obj, dict):
        return {k: _strip_lone_surrogates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_lone_surrogates(v) for v in obj]
    return obj

def _ingest(key, d, raw, kind):
    """节点入库唯一入口：溯源(source) + 脏数据规范化 + 记逐源统计。
    去重行为由各调用方保持原状（URI/v2ray-json 去重，clash-yaml/sing-box 不去重），
    本函数不改去重语义，只补 source + strip + 统计。"""
    if isinstance(d, dict):
        d = _strip_lone_surrogates(d)
    if isinstance(raw, dict):
        raw = dict(raw)
        raw['source'] = SRC.get('label')
        raw = _strip_lone_surrogates(raw)
    NODES.append((key, d, raw, kind))
    _log_src_added()

# ---------- 各协议解析 ----------
def parse_vless(u):
    p = urlparse(u); uuid, host, port = p.username or '', *uhp(p)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}; frag = unquote(p.fragment)
    sec = q.get('security', '')
    net = q.get('type', 'tcp')
    d = {'type': 'vless', 'server': host, 'port': int(port) if port else 443, 'uuid': uuid, 'network': 'tcp'}
    if not uuid: warn('vless无uuid', u[:50]); return
    flow = q.get('flow', '')
    if flow: d['flow'] = flow
    if sec in ('reality', 'tls') or 'pbk' in q:
        d['tls'] = True
        if q.get('sni'): d['server-name'] = q['sni']
        if sec == 'reality' or 'pbk' in q:
            if q.get('pbk'): d['public-key'] = q['pbk']
            if q.get('sid'): d['short-id'] = q['sid']
        if q.get('allowInsecure') in ('1', 'true') or q.get('insecure') in ('1', 'true'): d['insecure'] = True
    if q.get('fp'): d['fingerprint'] = q['fp']
    if net == 'ws':
        d['network'] = 'ws'
        wo = {}
        if q.get('path'): wo['path'] = q['path']
        if q.get('host'): wo['headers'] = {'Host': q['host']}
        if wo: d['ws-opts'] = wo
        if q.get('alpn'): d['alpn'] = q['alpn'].split(',')
        if q.get('encryption') == 'xudp': d['client-opts'] = {'packet-encoding': 'xudp'}
    elif net in ('xhttp', 'httpupgrade'):
        d['network'] = 'xhttp'
        xo = {}
        if q.get('path'): xo['path'] = q['path']
        if q.get('host'): xo['host'] = q['host']
        xo['mode'] = q.get('mode') or 'stream-one'
        if q.get('alpn'): d['alpn'] = q['alpn'].split(',')
        d['xhttp-opts'] = xo
    elif net == 'grpc':
        d['network'] = 'grpc'
        d['grpc-opts'] = {'grpc-service-name': q.get('serviceName') or q.get('path') or ''}
        if q.get('mode') == 'gun':   # gun 协议（gRPC 的抗 DPI 变体，v2rayN 写法 type=grpc&mode=gun）
            d['grpc-opts']['mode'] = 'gun'
        if q.get('authority'):
            d['grpc-opts']['authority'] = q['authority']
    if q.get('headerType'): d['header-type'] = q['headerType']
    add(d, {'name': frag, 'raw': u}, 'vless')

def parse_vmess(u):
    rest = u[len('vmess://'):]
    parts = rest.split('#', 1)
    frag = unquote(parts[1]) if len(parts) > 1 else ''
    # b64/JSON 损坏防护：坏行（非法 b64 / 解出非 JSON）以前抛 JSONDecodeError/binascii.Error 没接住
    try:
        j = json.loads(b64s(parts[0]))
    except Exception:
        warn('vmess b64/JSON 损坏(剔除)', u[:50]); return
    if not isinstance(j, dict):
        warn('vmess b64/JSON 损坏(剔除)', u[:50]); return
    host = j.get('add', '')
    try:
        port = int(str(j.get('port', 0) or 0))
    except (ValueError, TypeError):
        port = 0
    t = j.get('net', j.get('type', 'tcp'))
    d = {'type': 'vmess', 'server': host, 'port': port, 'uuid': j.get('id'), 'network': 'tcp'}
    if not d['uuid']: warn('vmess无uuid', u[:50]); return
    aid = j.get('aid', j.get('alterId', 0))
    if str(aid) not in ('', '0'): d['alterId'] = int(aid)
    sc = j.get('scy', j.get('sc', ''))
    if sc and sc not in ('none', 'null'): d['cipher'] = sc
    if t == 'ws':
        d['network'] = 'ws'
        wo = {}
        if j.get('path'): wo['path'] = j['path']
        if j.get('host'): wo['headers'] = {'Host': j['host']}
        if wo: d['ws-opts'] = wo
        if j.get('tls') in (True, 'tls', 'true') or port == 443: d['tls'] = True
        if j.get('host'): d['server-name'] = j['host']
    elif t in ('xhttp', 'httpupgrade'):
        d['network'] = 'xhttp'
        xo = {}
        if j.get('path'): xo['path'] = j['path']
        if j.get('host'): xo['host'] = j['host']
        xo['mode'] = 'stream-one'
        d['xhttp-opts'] = xo
        if j.get('tls') in (True, 'tls', 'true'): d['tls'] = True
    elif t == 'grpc':
        d['network'] = 'grpc'
        d['grpc-opts'] = {'grpc-service-name': j.get('path', '')}
        if j.get('mode') == 'gun':
            d['grpc-opts']['mode'] = 'gun'
        if port == 443: d['tls'] = True
        if j.get('host'): d['server-name'] = j['host']
    if j.get('path') and t not in ('ws', 'grpc'): pass
    add(d, {'name': frag or j.get('ps'), 'raw': u}, 'vmess')

def parse_trojan(u):
    p = urlparse(u); pwd, host, port = p.username or '', *uhp(p)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}; frag = unquote(p.fragment)
    # 非标参数兼容：proxypool 等用 ws=1&wsPath=... 代替 type=ws&path=...
    if q.get('ws') in ('1', 'true'):
        q.setdefault('type', 'ws'); q.setdefault('path', q.get('wsPath') or q.get('wspath') or '')
    t = q.get('type', 'tcp'); sec = q.get('security', 'tls')
    d = {'type': 'trojan', 'server': host, 'port': int(port) if port else 443, 'password': pwd, 'tls': True}
    if not pwd: warn('trojan无密码', u[:50]); return
    if q.get('sni') or q.get('peer'): d['server-name'] = q.get('sni') or q.get('peer')
    if q.get('fp') or q.get('fingerprint'): d['fingerprint'] = q.get('fp') or q.get('fingerprint')
    if q.get('insecure') in ('1', 'true') or q.get('allowInsecure') in ('1', 'true'): d['insecure'] = True
    if t in ('ws', 'xhttp'):
        d['network'] = 'ws'
        wo = {}
        if q.get('path'): wo['path'] = q['path']
        if q.get('host'): wo['headers'] = {'Host': q['host']}
        if wo: d['ws-opts'] = wo
    elif t == 'grpc':
        d['network'] = 'grpc'
        d['grpc-opts'] = {'grpc-service-name': q.get('serviceName', '')}
    add(d, {'name': frag, 'raw': u}, 'trojan')

def parse_ss(u):
    rest = u[len('ss://'):]
    parts = rest.split('#', 1)
    frag = unquote(parts[1]) if len(parts) > 1 else ''
    body = parts[0]
    method, pwd = '', ''
    if '@' in body:
        payload, hostport = body.rsplit('@', 1)
        host, port = hostport_split(hostport)
        user = payload
        # SIP002 新式：payload = b64(method:pass)；老式：payload 整体 = b64(method:pass@host:port)
        try:
            dec = b64s(payload)
            if '@' in dec:
                method, pwd, host, port = _ss_legacy_split(dec, host, port)
            else:
                method, pwd = dec.split(':', 1)
        except Exception:
            method, pwd = user.split(':', 1) if ':' in user else ('', user)
    else:
        # 纯 b64 老式
        dec = b64s(body)
        method, pwd, host, port = _ss_legacy_split(dec, '', 0)
    q = {k: v[0] for k, v in parse_qs(('?' + u.split('?', 1)[1]) if '?' in u else '').items()}
    if not port: port = 8388  # ss 默认端口
    # mihomo 的 YAML password 必须 base64；URI 里解出的 pwd 是明文 → 解析期就编码
    # （不能靠"长得像 base64 就不编码"的启发式：shadowsocks 这类纯字母明文会被误判）
    pwd_b64 = base64.b64encode(pwd.encode('utf-8', 'replace')).decode('ascii') if pwd else ''
    d = {'type': 'ss', 'server': host, 'port': int(port) if str(port).isdigit() else (int(q.get('port', 0)) or 8388), 'password': pwd_b64}
    cipher = method or q.get('method') or q.get('cipher')
    if cipher: d['cipher'] = cipher
    if not pwd: warn('ss无密码', u[:50]); return
    if q.get('enc'): d['cipher'] = q['enc']
    # SIP002 TLS（?tls=1）
    if q.get('tls') in ('1', 'true'):
        d['tls'] = True
        if q.get('sni'): d['server-name'] = q['sni']
    add(d, {'name': frag, 'raw': u}, 'ss')

def _ss_legacy_split(dec, host, port):
    # dec = "method:pass@host:port"（可能含 ? 等）
    m = re.match(r'^([^:]*):([^@]*)@(.*?)(?::(\d+))?$', dec)
    if m:
        host = m.group(3)
        port = m.group(4) or port
    parts = dec.split(':', 1)
    method = parts[0] if len(parts) > 1 else ''
    rest = parts[1] if len(parts) > 1 else ''
    pwd = rest.split('@', 1)[0]
    return method, pwd, host, port

def parse_ssr(u):
    import base64 as _b
    rest = u[len('ssr://'):]
    parts = rest.split('#', 1)
    frag = unquote(parts[1]) if len(parts) > 1 else ''
    body = parts[0]
    # 严格 base64（validate=True）：坏链接（payload 混入 ?/& 等字符，如 wenxig 池的损坏 ssr）直接跳过
    try:
        main = _b.b64decode(body + '=' * (-len(body) % 4), validate=True).decode('utf-8', 'replace')
    except Exception:
        warn('ssr base64 损坏(剔除)', u[:50]); return
    main = re.sub(r'^ssr\d?://', '', main)          # 有的编码内层还带 ssr:// 前缀
    opts_b64 = ''
    if '@' in main:
        main, opts_b64 = main.split('@', 1)
    opts = {}
    if opts_b64:
        try:
            opts = json.loads(_b.b64decode(opts_b64 + '=' * (-len(opts_b64) % 4), validate=True))
        except Exception:
            opts = {}
    fields = main.split(':')
    if len(fields) < 4:
        warn('ssr格式异常(剔除)', u[:50]); return
    host = fields[0]
    try:
        port = int(fields[1] or 0)
    except ValueError:
        port = 0
    protocol = fields[2] if len(fields) > 2 else ''
    method = fields[3]
    obfs = (fields[4] if len(fields) > 4 else 'plain') or 'plain'
    pwd = (fields[5] if len(fields) > 5 else '') or opts.get('passwd', '') or frag
    if not host or not port or not pwd:
        warn('ssr缺字段(剔除)', u[:50]); return
    # mihomo 内核实测（tools 内核 -t）：type: ssr 必拒（缺 obfs/protocol）→ 一律出 ss+plugin 形态；
    # 密码与 parse_ss 对齐：YAML 里必须 base64
    pwd_b64 = _b.b64encode(pwd.encode('utf-8', 'replace')).decode('ascii')
    d = {'type': 'ss', 'server': host, 'port': port, 'password': pwd_b64,
         'cipher': method or 'aes-256-cfb', 'udp': True}
    if protocol in ('', 'original'):
        d['plugin'] = 'simple-obfs'
        po = {}
        if obfs in ('plain', 'none', ''):
            po['mode'] = 'plain'
        elif obfs == 'http':
            po['mode'] = 'http'
        elif obfs == 'http2':
            po['mode'] = 'http2'
        else:   # tls1.0 / tls1.2_ticket_auth / tls1.2_ticket_auth_ic...
            po['mode'] = 'http'
            po['obfs'] = obfs
        po['obfs-host'] = host
        d['plugin-opts'] = po
    else:
        # auth_*（v2ray 风味 SSR，免费池里少见）→ v2ray-plugin 形态（内核实测接受）
        d['plugin'] = 'v2ray-plugin'
        d['plugin-opts'] = {'protocol': 'websocket', 'mode': 'websocket',
                            'obfs': obfs if obfs in ('http', 'tls1.2_ticket_auth') else 'http',
                            'obfs-host': host, 'tls': False}
    add(d, {'name': frag or f'SSR {host}', 'raw': u}, 'ssr')

def parse_hy2(u):
    p = urlparse(u)
    auth = p.username or ''
    host, port = uhp(p)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}; frag = unquote(p.fragment)
    pwd = q.get('passwd') or q.get('auth') or auth
    if q.get('auth'):
        try: pwd = b64s(q['auth'])
        except Exception: pass
    d = {'type': 'hysteria2', 'server': host, 'port': int(port) or 443, 'password': pwd, 'tls': True}
    if q.get('sni'): d['server-name'] = q['sni']
    if q.get('insecure') in ('1', 'true') or q.get('allowInsecure') in ('1', 'true'): d['insecure'] = True
    if q.get('iblk'): d['obfs'] = 'salamander'; d['obfs-salamander'] = {'payload': q.get('iblk', '0,4')}
    if not pwd: warn('hy2无密码', u[:50]); return
    add(d, {'name': frag, 'raw': u}, 'hysteria2')

def parse_tuic(u):
    p = urlparse(u)
    host, port = uhp(p)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}; frag = unquote(p.fragment)
    d = {'type': 'tuic', 'server': host, 'port': int(port) or 443}
    if q.get('uuid'): d['uuid'] = q['uuid']
    if q.get('private'): d['private'] = q['private']
    if q.get('sni'): d['server-name'] = q['sni']
    if q.get('insecure') in ('1', 'true'): d['allow-insecure'] = True
    if q.get('ip'): d['ip'] = q['ip']
    if q.get('alpn'): d['alpn'] = q['alpn']
    if not q.get('uuid'): warn('tuic无uuid', u[:50]); return
    add(d, {'name': frag, 'raw': u}, 'tuic')

def parse_plain(u):
    """socks:// socks5:// socks5h:// http:// https:// 裸代理"""
    p = urlparse(u); t = p.scheme
    host, port = uhp(p)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}; frag = unquote(p.fragment)
    # mihomo 的 http outbound 支持 TLS（type: http + tls: true）；https 不是独立协议类型
    ctype = 'socks5' if t in ('socks', 'socks5', 'socks5h') else ('http' if t in ('http', 'https') else t)
    d = {'type': ctype,
         'server': host, 'port': int(port) or (1080 if t.startswith('socks') else 80)}
    if t == 'socks5h': d['remote-dns'] = True
    if p.username: d['username'] = p.username
    if p.password: d['password'] = p.password
    if t == 'https':
        d['tls'] = True
        if q.get('sni'): d['server-name'] = q['sni']
        if q.get('allowInsecure') in ('1', 'true'): d['insecure'] = True
    add(d, {'name': frag or f'{t}://{host}:{port}', 'raw': u}, t)

def parse_anytls(u):
    p = urlparse(u); pwd, host, port = p.username or '', *uhp(p)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}; frag = unquote(p.fragment)
    sec = q.get('security', 'tls')
    d = {'type': 'anytls', 'server': host, 'port': int(port) if port else 443,
         'password': pwd or q.get('password', '')}
    if not d['password']:
        warn('anytls无凭证', u[:50]); return
    if sec != 'none':
        d['tls'] = True
        if q.get('sni'): d['server-name'] = q['sni']
    if q.get('fp'): d['fingerprint'] = q['fp']
    t = q.get('type', 'tcp')
    if t != 'tcp': d['network'] = t
    add(d, {'name': frag or f'anytls:{host}:{port}', 'raw': u}, 'anytls')

PARSERS = {'vless': parse_vless, 'vmess': parse_vmess, 'trojan': parse_trojan,
           'ss': parse_ss, 'ssr': parse_ssr, 'hysteria2': parse_hy2, 'hysteria': parse_hy2,
           'hy2': parse_hy2, 'u2': parse_hy2,
           'tuic': parse_tuic, 'anytls': parse_anytls,
           'socks5': parse_plain, 'socks': parse_plain,
           'socks5h': parse_plain,
           'http': parse_plain, 'https': parse_plain}

# ---------- 备用小池（打散分配，稳定指纹哈希：加新源不挪旧节点） ----------
def partition_pools(nodes, n=6):
    """把去重后的节点集按 指纹哈希 打散到 n 个互斥小池（每池协议/地区自然混合）。
    稳定性：分配只依赖节点指纹（type/server/port/凭证/sni/flow）→ 以后加新订阅源时，
    旧节点池号不变，只有新节点填入 → 池子可作长期"备用轮换"。"""
    import hashlib
    pools = [[] for _ in range(max(2, int(n)))]
    for key, d, raw, kind in nodes:
        fp = '|'.join(str(x) for x in key)
        idx = int(hashlib.md5(fp.encode('utf-8','replace')).hexdigest()[:8], 16) % len(pools)
        pools[idx].append((key, d, raw, kind))
    return pools

def emit_pools(nodes, out_dir, n=6):
    """每个池出 完整 mihomo 配置 + v2ray URI 行 + base64 blob；写 out_dir/pools.json 清单。
    返回 {n, total, pools:[{i,count,by_kind,files}]}。"""
    import json as _json
    from collections import Counter
    os.makedirs(out_dir, exist_ok=True)
    pools = partition_pools(nodes, n)
    man = {'n': len(pools), 'ts': time.time(), 'total': len(nodes), 'pools': []}
    for i, pn in enumerate(pools, 1):
        files = []
        if pn:
            by = dict(Counter(k for _, _, _, k in pn))
            c = os.path.join(out_dir, f'pool-{i}-clash.yaml')
            v = os.path.join(out_dir, f'pool-{i}-v2ray.txt')
            vb = os.path.join(out_dir, f'pool-{i}-v2ray-blob.txt')
            emit_clash_yaml(c, pn)
            emit_v2ray_lines(v, pn)
            emit_v2ray_blob(vb, pn)
            files = [os.path.basename(c), os.path.basename(v), os.path.basename(vb)]
            man['pools'].append({'i': i, 'count': len(pn), 'by_kind': by, 'files': files})
        else:
            man['pools'].append({'i': i, 'count': 0, 'by_kind': {}, 'files': []})
    open(os.path.join(out_dir, 'pools.json'), 'w', encoding='utf-8', errors='replace').write(
        _json.dumps(man, ensure_ascii=False, indent=1))
    return man

# ---------- 订阅 URL 识别（in/ 里混的"订阅链接" vs "节点 URI"） ----------
# 节点 URI 的特征：scheme:// 在 PARSERS 里（vless/vmess/ss/…/http/https 后面跟 host:port）。
# 订阅 URL 的特征：http(s) + 域名（非 IP）+ 长路径（.yaml/.txt/.json/.sub/… 或 /sub//subscribe//nodes/… 段）。
_SUB_URL_RE = re.compile(
    r'^(https?://[a-z0-9][^/\s]+(?:/[^#\s?]+)*?'
    r'(?:/sub(?:scribe)?|/source|/output|/nodes?|/free|/clash|/v2ray|/sing|/upload\w*|/list|/release\w*|/dist)'
    r'(?:/[^#\s?]+)*?[^#\s?]*\.(yaml|yml|txt|json|sub|meta|jpg)(?:[?#].*)?)$', re.I)

def is_sub_url(line):
    """一行是不是"订阅链接"（要下载解析），而不是 https 明文代理节点。
    IP 主机的 https://1.2.3.4:443 = 节点；域名 + 订阅特征路径/扩展名 = 订阅链接。"""
    line = line.strip()
    m = re.match(r'^https?://', line, re.I)
    if not m:
        return False
    hostport = line.split('/', 3)[2] if line.count('/') >= 3 else ''
    host = hostport.split(':', 1)[0].strip().lower()
    if not host or host in ('localhost',):
        return False
    # 纯 IP 主机 → 节点（https 明文代理）
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host):
        return False
    if _SUB_URL_RE.match(line):
        return True
    # 兜底：路径里带订阅特征词（/sub /subscribe /free /clash /v2ray /nodes /upload /output /source）
    path = line.split('/', 3)[3] if line.count('/') >= 3 else ''
    if re.search(r'(^|/)(sub|subscribe|subscription|clash|v2ray|singbox|sing-box|nodes?|free|uploads?|outputs?|sources?|links|list)(/|$|\.)', path, re.I) \
       and not re.search(r'[:/]\d{2,5}(?:[/?#]|$)', line):   # 排除带明显端口的节点写法
        return True
    return False

def extract_sub_urls(text):
    """从文本里抽出所有订阅 URL（去重、保序、跳过节点行）"""
    out, seen = [], set()
    for line in (text or '').splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if '://' in s and s.split('://', 1)[0].lower() in ('vless', 'vmess', 'ss', 'ssr', 'trojan',
                                                            'hysteria2', 'hy2', 'u2', 'tuic', 'anytls'):
            continue   # 节点 URI 不是订阅链接
        if is_sub_url(s):
            core = s.split('#', 1)[0]
            if core not in seen:
                seen.add(core)
                out.append(core)
    return out


# ---------- 输入识别（CLI 文件与 webgui 粘贴共用） ----------
def process_text(raw, label='<粘贴>'):
    """按内容自动识别输入格式并解析：JSON(v2ray/sing-box) / Clash YAML / base64 blob / URI 行列表"""
    raw = (raw or '').strip()
    if not raw:
        return
    # JSON 配置（v2ray 风格 protocol / sing-box 风格 type）
    if raw.lstrip().startswith('{') and '"outbounds"' in raw:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            warn('JSON格式错误(按URI/base64继续)', label)
        else:
            obs = data.get('outbounds', [])
            if obs and isinstance(obs[0], dict) and 'protocol' in obs[0]:
                process_v2rayjson(data, label); return
            process_singbox(data, label); return
    # Clash YAML
    if raw.lstrip().startswith('---') or re.search(r'^proxies\s*:', raw, re.M):
        import importlib as _il
        _vendor = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor')
        if os.path.isdir(_vendor) and _vendor not in sys.path:
            sys.path.insert(0, _vendor)   # 工作区内装的 pyyaml（沙箱不能写系统 site-packages）
        try:
            import yaml as _yaml
        except Exception:
            _yaml = None
        if _yaml is None or not hasattr(_yaml, 'safe_load'):
            ok, msg = ensure_vendor_yaml()   # 自修：自动下载纯 Python pyyaml（需网络）
            if ok:
                for _m in [m for m in list(sys.modules) if m == 'yaml' or m.startswith('yaml.')]:
                    del sys.modules[_m]
                _il.invalidate_caches()
                import yaml as _yaml
            if not hasattr(_yaml, 'safe_load'):
                warn('无pyyaml(跳过YAML输入)', label)
                print(f'  [跳过] {label}: pyyaml 不可用（{msg}）→ 该 YAML 源跳过，base64/URI 源不受影响')
                return
        try:
            data = _yaml.safe_load(raw)
            if isinstance(data, dict) and data.get('proxies'):
                for pr in data['proxies']:
                    if isinstance(pr, dict) and pr.get('type'):
                        pr.setdefault('name', 'unnamed')
                        _ingest((pr.get('type'), pr.get('server'), pr.get('port')), pr, {}, 'clash-yaml')
                print(f'  [YAML] {label}: 合并 {len(data["proxies"])} 个节点')
            return
        except Exception as e:
            warn(f'YAML解析失败:{type(e).__name__}', label)
            print(f'  [跳过] {label}: YAML 解析异常 {str(e)[:80]}')
            return
    # base64 blob
    body = re.sub(r'\s+', '', raw)
    if re.fullmatch(r'[A-Za-z0-9+/=]{40,}', body):
        try:
            decoded = b64s(body)
            if '://' in decoded:
                _iter_uri_lines(decoded, label, 'base64')
                return
        except Exception:
            pass
    _iter_uri_lines(raw, label, 'URI')

def process_file(path):
    SRC['label'] = os.path.basename(path)
    SRC['url'] = SMAP.get(os.path.basename(path), '')   # dl_N.sub ↔ 原始 URL（fetch_urls 记进 SMAP）
    raw = open(path, encoding='utf-8', errors='replace').read()
    process_text(raw, os.path.basename(path))
    SRC['label'] = ''                 # 复位：emit 期的 warn 不归属到上一个源

def _iter_uri_lines(text, path, label='URI'):
    n0 = len(NODES)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', '- ')): continue
        if '://' in line:
            sch = line.split('://', 1)[0].lower()
            fn = PARSERS.get(sch)
            if fn:
                try: fn(line)
                except Exception as e: warn(f'解析异常:{type(e).__name__}', line[:50])
            else:
                warn(f'未知协议:{sch}', line[:50])
            continue
        # 逐行 base64（每行一个 b64 编码的 URI，如 wenxig/dongtai-sub 的 sub.txt）
        if re.fullmatch(r'[A-Za-z0-9+/=]{16,}', line):
            try:
                dec = b64s(line)
            except Exception:
                continue
            if '://' in dec:
                for dl in dec.splitlines():
                    dl = dl.strip()
                    if not dl:
                        continue
                    sch = dl.split('://', 1)[0].lower()
                    fn = PARSERS.get(sch)
                    if fn:
                        try: fn(dl)
                        except Exception as e: warn(f'解析异常(b64行):{type(e).__name__}', dl[:40])
                    else:
                        warn(f'未知协议(b64行):{sch}', dl[:40])
    print(f'  [{label}] {os.path.basename(path)}: 解析 {len(NODES)-n0} 行')

def process_singbox(data, path):
    n0 = len(NODES)
    for ob in data.get('outbounds', []):
        t = ob.get('type')
        if t in ('direct', 'dns', 'loopback', 'blackhole', 'selector', 'urltest', 'balancer'): continue
        host, port = ob.get('server', ''), ob.get('port', 0)
        try: port = int(port or 0)
        except (TypeError, ValueError): port = 0
        # sing-box type → mihomo type 映射：shadowsocks=ss、hysteria=hysteria2（漏映射 mihomo 拒收）
        mt = {'shadowsocks': 'ss', 'hysteria': 'hysteria2'}.get(t, t)
        d = {'type': mt, 'server': host, 'port': port, 'name': ob.get('tag', '')}
        if t == 'vless':
            d['uuid'] = ob.get('uuid')
            tls = ob.get('tls', {}) or {}
            if tls: d['tls'] = True
            if tls.get('server_name'): d['server-name'] = tls['server_name']
            if tls.get('insecure'): d['insecure'] = True
            if tls.get('fingerprint'): d['fingerprint'] = tls['fingerprint']
            if tls.get('public_key'): d['public-key'] = tls['public_key']
            if tls.get('short_id'): d['short-id'] = tls['short_id']
            if ob.get('flow'): d['flow'] = ob['flow']
            if ob.get('ws'):
                d['network'] = 'ws'
                wo = {}
                if ob['ws'].get('path'): wo['path'] = ob['ws']['path']
                if ob['ws'].get('headers', {}).get('Host'): wo['headers'] = {'Host': ob['ws']['headers']['Host']}
                if wo: d['ws-opts'] = wo
            if ob.get('grpc'):
                d['network'] = 'grpc'
                d['grpc-opts'] = {'grpc-service-name': ob['grpc'].get('service_name', '')}
        elif t == 'vmess':
            d['uuid'] = ob.get('uuid')
            if ob.get('alter'): d['alterId'] = ob['alter']
            if ob.get('cipher') and ob['cipher'] != 'auto': d['cipher'] = ob['cipher']
            tls = ob.get('tls', {}) or {}
            if tls.get('enabled'): d['tls'] = True
            if tls.get('server_name'): d['server-name'] = tls['server_name']
            if ob.get('ws'):
                d['network'] = 'ws'
                wo = {}
                if ob['ws'].get('path'): wo['path'] = ob['ws']['path']
                if ob['ws'].get('headers', {}).get('Host'): wo['headers'] = {'Host': ob['ws']['headers']['Host']}
                if wo: d['ws-opts'] = wo
            if ob.get('grpc'):
                d['network'] = 'grpc'
                d['grpc-opts'] = {'grpc-service-name': ob['grpc'].get('service_name', '')}
        elif t in ('trojan', 'shadowsocks', 'hysteria', 'tuic'):
            if t == 'tuic':
                d['uuid'] = ob.get('uuid'); d['private'] = ob.get('private')
            else:
                if t == 'shadowsocks':
                    # sing-box 的 ss password 是明文 → mihomo 要 base64
                    d['password'] = base64.b64encode(str(ob.get('password', '')).encode('utf-8', 'replace')).decode('ascii')
                else:
                    d['password'] = ob.get('password', '')
            if t in ('trojan', 'hysteria', 'tuic'):
                d['tls'] = True
                tls = ob.get('tls', {}) or {}
                if tls.get('server_name'): d['server-name'] = tls['server_name']
                if tls.get('insecure'): d['insecure'] = True
            if t == 'shadowsocks': d['cipher'] = ob.get('method', 'chacha20-ietf-poly1305')
        elif t in ('socks', 'http'):
            d['type'] = t
            if ob.get('username'): d['username'] = ob['username']
            if ob.get('password'): d['password'] = ob['password']
            if t == 'http' and (ob.get('tls') or {}).get('enabled'): d['tls'] = True
        if not host or not port or (t in ('vless', 'vmess', 'tuic') and not d.get('uuid')):
            warn('singbox节点缺字段', d.get('name')); continue
        if not _finalize(d):
            continue
        _ingest((d['type'], host, port, str(d.get('uuid', d.get('password', '')))), d, {}, f'singbox:{t}')
    print(f'  [singbox] {os.path.basename(path)}: 合并 {len(NODES)-n0} 个节点')

def process_v2rayjson(data, path):
    """v2ray-core 风格 JSON 配置：outbounds[{protocol, settings{address,port,id,password,security,flow,...},
    streamSettings{network, security, tlsSettings/realitySettings, wsSettings, grpcSettings}}]。
    与 sing-box 的 type 风格区分：outbounds[0] 里有 'protocol' 键即 v2ray 风格。"""
    n0 = len(NODES)
    for ob in data.get('outbounds', []):
        proto = str(ob.get('protocol', '')).lower()
        if proto in ('freedom', 'blackhole', 'dns', 'direct', 'routing'):
            continue
        st = ob.get('settings', {}) or {}
        if isinstance(st, str):   # 部分导出器 settings 是 JSON 字符串
            try: st = json.loads(st)
            except Exception:
                warn('v2ray-json settings 非对象(剔除)', ob.get('tag', '')); continue
        ss = ob.get('streamSettings', {}) or {}
        if isinstance(ss, str):
            try: ss = json.loads(ss)
            except Exception: ss = {}
        net = str(ss.get('network', 'tcp')).lower()
        if net == 'gun':
            net = 'grpc'   # gun 协议在 Xray JSON 里写作独立 network，归一到 grpc+mode
        gun = bool(ss.get('gunSettings'))
        sec = str(ss.get('security', st.get('security', 'none'))).lower()
        host = st.get('address', '') or st.get('server', '')
        try:
            port = int(st.get('port', 0) or 0)
        except (TypeError, ValueError):
            port = 0
        tag = ob.get('tag', '') or ''
        d = {'type': proto, 'server': host, 'port': port, 'name': tag or f'{proto}:{host}:{port}'}
        if net in ('ws', 'httpupgrade', 'grpc'):
            d['network'] = 'ws' if net in ('ws', 'httpupgrade') else net
        realinfo = ss.get('realitySettings') or {}
        tlsinfo = ss.get('tlsSettings') or {}
        if sec in ('tls', 'reality') or tlsinfo or realinfo:
            d['tls'] = True
            sni = realinfo.get('serverName') or tlsinfo.get('serverName') or ''
            if sni: d['server-name'] = sni
            fp = realinfo.get('fingerprint') or tlsinfo.get('fingerprint') or ''
            if fp: d['fingerprint'] = fp
            if realinfo.get('publicKey'): d['public-key'] = realinfo['publicKey']
            if realinfo.get('shortId'): d['short-id'] = realinfo['shortId']
        if net in ('ws', 'httpupgrade'):
            wsp = ss.get('wsSettings') or {}
            wo = {}
            if wsp.get('path'): wo['path'] = wsp['path']
            h = (wsp.get('headers') or {}).get('Host')
            if h: wo['headers'] = {'Host': h}
            if wo: d['ws-opts'] = wo
        if net == 'grpc':
            d['grpc-opts'] = {'grpc-service-name': (ss.get('grpcSettings') or {}).get('serviceName', '')}
            if gun:
                d['grpc-opts']['mode'] = 'gun'
        if proto == 'vless':
            d['uuid'] = st.get('id', '')
            if st.get('flow'): d['flow'] = st['flow']
        elif proto == 'vmess':
            d['uuid'] = st.get('id', '')
        elif proto == 'shadowsocks':
            d['type'] = 'ss'
            d['cipher'] = st.get('method', 'chacha20-poly1305')
            # v2ray 风格 JSON 的 ss password 是明文 → mihomo 要 base64
            d['password'] = base64.b64encode(str(st.get('password', '')).encode('utf-8', 'replace')).decode('ascii')
        elif proto in ('trojan', 'hysteria2', 'anytls'):
            d['password'] = st.get('password', st.get('id', ''))
        elif proto == 'hysteria':
            d['type'] = 'hysteria2'
            d['password'] = st.get('password', '')
        elif proto == 'tuic':
            d['uuid'] = st.get('uuid', st.get('id', ''))
            d['private'] = st.get('private', '')
        elif proto in ('socks', 'http'):
            d['type'] = 'socks5' if proto == 'socks' else 'http'
            if st.get('username'): d['username'] = st['username']
            if st.get('password'): d['password'] = st['password']
        if not host or not port:
            warn('v2ray-json缺server/port', tag); continue
        if proto in ('vless', 'vmess', 'tuic') and not d.get('uuid'):
            warn('v2ray-json缺uuid', tag); continue
        if d['type'] in ('ss', 'trojan', 'hysteria2', 'anytls') and not d.get('password'):
            warn('v2ray-json缺凭证', tag); continue
        key = (d['type'], host, port, str(d.get('uuid', d.get('password', ''))),
               str(d.get('server-name', d.get('sni', ''))), str(d.get('flow', '')))
        if any(k2 == key for k2, _, _, _ in NODES):
            warn('重复')
            continue
        if not _finalize(d):
            warn('v2ray-json ss2022(不兼容)', tag)
            continue
        _ingest((key, d, {}, f'v2rayjson:{proto}'))
    print(f'  [v2ray-json] {os.path.basename(path)}: 合并 {len(NODES)-n0} 个节点')

# ---------- YAML 输出 ----------
_SAFE = re.compile(r'^[A-Za-z0-9._\-]+$')

def _s(v):
    if v is True: return 'true'
    if v is False: return 'false'
    if v is None: return 'null'
    if isinstance(v, (int, float)): return str(v)
    s = str(v)
    # 像数字/科学计数/八进制的字符串必须加引号：YAML 解析器会把裸 "01"/"1e5"/"0x1F"
    # 读成数字 → mihomo 按 int 校验失败（如 short-id: 01 → "invalid REALITY short ID"）
    if re.match(r'^(0|[+-]?\d|\.)', s):
        return json.dumps(s, ensure_ascii=False)
    if s and _SAFE.match(s) and s.lower() not in ('true', 'false', 'null', 'none', 'on', 'off', 'yes', 'no'):
        return s
    # 含 C0(0x00-0x1F)、DEL(0x7F) 或 C1(0x80-0x9F) 时必须 \uXXXX 转义：
    # YAML 双引号串禁止裸控制字符，mihomo 的 libyaml 对 C0/C1 都报 "control characters are not allowed"。
    # GBK→UTF-8 乱码（xiaoji235 大池）会产出 C1 字符，旧版只查 <0x20+0x7F 漏了 0x80-0x9F。
    # json.dumps(ensure_ascii=True) 会把 0x7F 及以上全转 \uXXXX（C1 覆盖），只补 0x7F 保险。
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in s):
        return json.dumps(s, ensure_ascii=True).replace('\x7f', '\\u007f')
    return json.dumps(s, ensure_ascii=False)

def _dict_lines(d, indent):
    """dict → YAML 行（嵌套 dict/list 递归）"""
    lines = []
    for k, v in d.items():
        sp = '  ' * indent
        if isinstance(v, dict):
            if v:
                lines.append(f'{sp}{k}:')
                lines += _dict_lines(v, indent + 1)
            else:
                lines.append(f'{sp}{k}: {{}}')
        elif isinstance(v, list):
            lines.append(f'{sp}{k}:')
            lines += _list_lines(v, indent + 1)
        else:
            lines.append(f'{sp}{k}: {_s(v)}')
    return lines

def _list_lines(lst, indent):
    """list → YAML 行（元素为 dict 时用 '- ' 起始）"""
    lines = []
    for item in lst:
        if isinstance(item, dict):
            lines += _dict_item_lines(item, indent)
        else:
            lines.append(f'{"  " * indent}- {_s(item)}')
    return lines

def _dict_item_lines(item, indent):
    """list 中一个 dict 元素：首键带 '- '，嵌套子键比父键深两级"""
    lines = []
    for i, (k, v) in enumerate(item.items()):
        prefix = '  ' * indent + '- ' if i == 0 else '  ' * (indent + 1)
        if isinstance(v, dict):
            if v:
                lines.append(f'{prefix}{k}:')
                lines += _dict_lines(v, indent + 2)
            else:
                lines.append(f'{prefix}{k}: {{}}')
        elif isinstance(v, list):
            lines.append(f'{prefix}{k}:')
            lines += _list_lines(v, indent + 2)
        else:
            lines.append(f'{prefix}{k}: {_s(v)}')
    return lines

def emit_clash_yaml(path, nodes, variant='flclash'):
    """variant: 'flclash'=FlClash 内核字段方言（默认，导入用）；
    'mihomo'=原版 mihomo 标准字段（servername→server-name、sni→server-name、
    client-fingerprint→fingerprint）——测试实例（⑦/⑧http补测）跑原版 mihomo 必须用这个，
    否则 SNI 字段名不被识别 → TLS/reality/http-tls 节点静默丢 SNI → 系统性全死。"""
    proxies = [dict(d) for _, d, _, _ in nodes]   # 拷贝：变体改字段名不污染全局 NODES
    if variant == 'mihomo':
        for d in proxies:
            if 'servername' in d:
                d['server-name'] = d.pop('servername')
            if 'sni' in d:
                d['server-name'] = d.pop('sni')
            if 'client-fingerprint' in d:
                d['fingerprint'] = d.pop('client-fingerprint')
    for i, d in enumerate(proxies):
        # mihomo 要求名字非空且唯一；空名强制回退
        d['name'] = d.get('name') or f'node{i}'
    # 组内引用要求名字唯一
    seen, uniq = set(), []
    for d in proxies:
        n = d['name']
        if n in seen:
            j = 2
            while f'{n} ({j})' in seen: j += 1
            n = d['name'] = f'{n} ({j})'
        seen.add(n); uniq.append(n)
    top = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning', 'ipv6': False,
        # 注意：不加 dns 块 / external-controller —— 对齐 735754647 等 FlClash 实配。
        # 带自定义 dns/external-controller 时 FlClash 导入常显示 0 节点；省略则 FlClash 用自己的默认 DNS，
        # 行为等价 v2rayN（系统 DNS 能解析外国域名），外国节点才连得上。
        'proxies': proxies,
        'proxy-groups': [{'name': 'AUTO', 'type': 'url-test',
                          'url': 'https://www.google.com/generate_204',
                          'interval': 300, 'tolerance': 100, 'proxies': uniq},
                         {'name': 'PROXY', 'type': 'select',
                          'proxies': ['AUTO', 'DIRECT'] + uniq}],
        'rules': ['GEOIP,LAN,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,PROXY']}
    header = '\n'.join([
        '# ============================================================',
        f'# R2 subconv 生成 · {len(proxies)} 个免费节点 · {time.strftime("%Y-%m-%d %H:%M")}',
        '# 导入对象：FlClash / Clash Verge Rev / Mihomo Party（mihomo 内核）',
        '# 组：AUTO(自动测速换线) · PROXY(手动选择，含全部节点)',
        '# 导入后：① 配置页点选激活 ② 自动用 AUTO / 手动挑节点用 PROXY',
        '# 不适用：原版 Clash（vless/reality 字段不支持，请用 merged-v2ray.txt）',
        '# 免费节点不稳定、运营商可见流量，勿登录重要账号',
        '# ============================================================',
    ])
    open(path, 'w', encoding='utf-8', errors='replace').write(header + '\n' + '\n'.join(_dict_lines(top, 0)) + '\n')

# ---------- round-trip 逆编码：归一 proxy dict → 标准节点 URI（单一事实源）----------
# 原 Cloudfree main_v2.py 有个"临时桥" clash_proxy_to_uri 做这件事；这里正式收归 subconv，
# 让 Clash/sing-box/v2ray-json 解析出的节点也能进 merged-v2ray.txt / blob（三格式全量不遗漏）。
# 字段约定 = subconv flclash 方言：SNI 是小写 servername（trojan/hysteria2 用 sni）；
# shadowsocks 的 password 在 Clash YAML 里是 base64（重编码前用 _b64maybe 解码）。

def _q(v):
    return quote(str(v), safe='')

def _host_or_v6(host):
    host = str(host)
    return ('[' + host + ']') if (':' in host) else host

def _b64maybe(s):
    """mihomo 约定 shadowsocks 的 password 是 base64；尝试解码，解不出/含 NUL 就当明文原样。"""
    s = str(s or '')
    try:
        d = base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8')
        return d if d and ('\x00' not in d) else s
    except Exception:
        return s

def clash_proxy_to_uri(p):
    """归一 proxy dict（mihomo/clash 字段）→ 标准节点 URI。
    覆盖 vless/vmess/trojan/ss/shadowsocks/hysteria2/tuic/anytls；无法逆向返回 None。
    socks/http 等少见协议不逆编码（下游 sing-box prober 也不解析它们），下游按"跳过"计数。"""
    if not isinstance(p, dict):
        return None
    t = str(p.get('type', '')).lower()
    host = str(p.get('server', '')).strip()
    port = p.get('port', 0)
    if not host or not port:
        return None
    h = _host_or_v6(host)
    name = _q(p.get('name', ''))
    wo = p.get('ws-opts') or {}
    wo_path = wo.get('path') or ''
    wo_host = (wo.get('headers') or {}).get('Host') or ''
    # subconv 发 servername(小写)，部分源发 serverName/sni —— 三个都认
    sni = p.get('serverName') or p.get('servername') or p.get('sni') or host
    suffix = ('#' + name) if name else ''

    if t == 'vless':
        q = ['encryption=none', 'type=' + _q(str(p.get('network', 'tcp')).lower())]
        reality = p.get('reality-opts')
        if p.get('tls') and reality:
            q += ['security=reality', 'sni=' + _q(sni),
                  'fp=' + _q(p.get('client-fingerprint') or 'chrome'),
                  'pbk=' + _q(reality.get('public-key', '')), 'sid=' + _q(reality.get('short-id', ''))]
        elif p.get('tls'):
            q += ['security=tls', 'sni=' + _q(sni),
                  'allowInsecure=' + ('1' if p.get('skip-cert-verify') else '0')]
        if p.get('flow'):
            q.append('flow=' + _q(p.get('flow')))
        if wo_path:
            q.append('path=' + _q(wo_path))
        if wo_host:
            q.append('host=' + _q(wo_host))
        return 'vless://%s@%s:%s?' % (_q(p.get('uuid', '')), h, port) + '&'.join(q) + suffix

    if t == 'vmess':
        d = {'v': '2', 'ps': p.get('name', ''), 'add': host, 'port': str(port),
             'id': str(p.get('uuid', '')), 'aid': str(p.get('alterId') or p.get('alter_id') or 0),
             'scy': p.get('cipher', 'auto'), 'net': str(p.get('network', 'tcp')).lower(),
             'type': 'none', 'host': wo_host,
             'path': wo_path or ((p.get('grpc-opts') or {}).get('serviceName', '') or ''),
             'sni': sni}
        if p.get('tls'):
            d['tls'] = 'tls'
        return 'vmess://' + base64.b64encode(json.dumps(d).encode('utf-8', 'replace')).decode()

    if t == 'trojan':
        q = ['security=tls', 'sni=' + _q(sni), 'allowInsecure=' + ('1' if p.get('skip-cert-verify') else '0')]
        if p.get('alpn'):
            alpn = p['alpn']
            q.append('alpn=' + _q(','.join(alpn if isinstance(alpn, list) else [alpn])))
        if p.get('fp') or p.get('client-fingerprint'):
            q.append('fp=' + _q(p.get('fp') or p.get('client-fingerprint')))
        net = str(p.get('network', 'tcp')).lower()
        if net != 'tcp':
            q.append('type=' + _q(net))
        if wo_path:
            q.append('path=' + _q(wo_path))
        if wo_host:
            q.append('host=' + _q(wo_host))
        return 'trojan://%s@%s:%s?' % (_q(p.get('password', '')), h, port) + '&'.join(q) + suffix

    if t in ('ss', 'shadowsocks'):
        method = str(p.get('cipher', 'chacha20-ietf-poly1305')).lower()
        userinfo = base64.b64encode(('%s:%s' % (method, _b64maybe(p.get('password', '')))).encode('utf-8', 'replace')).decode()
        return 'ss://%s@%s:%s' % (userinfo, h, port) + suffix

    if t in ('hysteria2', 'hy2', 'hysteria'):
        q = []
        if sni and sni != host:
            q.append('sni=' + _q(sni))
        if p.get('obfs'):
            q.append('obfs=' + _q(p.get('obfs')))
        if p.get('obfs-password'):
            q.append('obfs-password=' + _q(p.get('obfs-password')))
        if p.get('skip-cert-verify'):
            q.append('insecure=1')
        qs = ('?' + '&'.join(q)) if q else ''
        return 'hy2://%s@%s:%s%s' % (_q(p.get('password', '')), h, port, qs) + suffix

    if t == 'tuic':
        q = []
        if sni and sni != host:
            q.append('sni=' + _q(sni))
        if p.get('alpn'):
            alpn = p['alpn']
            q.append('alpn=' + _q(','.join(alpn if isinstance(alpn, list) else [alpn])))
        if p.get('allow-insecure') or p.get('insecure'):
            q.append('insecure=1')
        qs = ('?' + '&'.join(q)) if q else ''
        return 'tuic://%s:%s@%s:%s%s%s' % (_q(p.get('uuid', '')), _q(p.get('private', '')), h, port, qs, suffix)

    if t == 'anytls':
        q = []
        if p.get('tls'):
            q.append('security=tls')
            if sni:
                q.append('sni=' + _q(sni))
        else:
            q.append('security=none')
        fp = p.get('fingerprint') or p.get('client-fingerprint')
        if fp:
            q.append('fp=' + _q(fp))
        net = str(p.get('network', 'tcp')).lower()
        if net != 'tcp':
            q.append('type=' + _q(net))
        qs = ('?' + '&'.join(q)) if q else ''
        return 'anytls://%s@%s:%s%s%s' % (_q(p.get('password', '')), h, port, qs, suffix)

    return None   # socks/http/ssr-as-ss 等：不逆编码（下游 prober 也不解析），下游按"跳过"计数

def node_uri(key, d, raw, kind):
    """取节点的"标准 URI"：有原始 raw（URI 源）用原样；否则用归一 dict 逆编码（round-trip）。"""
    r = raw.get('raw') if isinstance(raw, dict) else None
    if r:
        return r
    return clash_proxy_to_uri(d)

def emit_v2ray_b64(path, nodes):
    """逐行 base64（少用/已弃用）。round-trip：每个节点都出 URI（clash/sing-box 节点逆编码）。"""
    import base64 as b
    lines = []
    for key, d, raw, kind in nodes:
        u = node_uri(key, d, raw, kind)
        if u:
            lines.append(b.b64encode(u.encode('utf-8', 'replace')).decode())
        else:
            warn('无法逆编码URI(跳过)', d.get('name'))
    open(path, 'w', encoding='utf-8', errors='replace').write('\n'.join(lines) + '\n')

def emit_v2ray_lines(path, nodes):
    """纯 URI 行格式（一行一个 vless://vmess://ss://…，无 base64）。
    round-trip：每个节点都出 URI（clash/sing-box/v2ray-json 解析出的节点用 node_uri 逆编码补齐），
    保证三格式产物全量不遗漏。v2rayN/FlClash「本地文件/粘贴导入」认这种；订阅链接场景用 emit_v2ray_blob。"""
    uris = [u for u in (node_uri(key, d, raw, kind) for key, d, raw, kind in nodes) if u]
    open(path, 'w', encoding='utf-8', errors='replace').write('\n'.join(uris) + '\n')

def emit_v2ray_blob(path, nodes):
    """标准 base64 订阅：所有 URI 用 \\n 连接后整段 base64（一行）。
    subs-check/大部分订阅工具的 Base64 格式都是这种；逐行 base64 是非标准，解出来是拼接垃圾。"""
    import base64 as b
    uris = [u for u in (node_uri(key, d, raw, kind) for key, d, raw, kind in nodes) if u]
    open(path, 'w', encoding='utf-8', errors='replace').write(b.b64encode(('\n'.join(uris)).encode('utf-8', 'replace')).decode() + '\n')

# ---------- 下载 ----------
def fetch_urls(urls, outdir, proxy=None, stop_event=None):
    """下载订阅源。成功才覆盖旧文件（dl_N.sub）；失败保留旧文件 → 合并集永远不会缩水。
    stop_event：置位后跳过剩余源（已下载的保留），返回 {'files':..., 'stopped':True}。"""
    import urllib.request as ur
    proxy_opener = ur.build_opener(ur.ProxyHandler({'http': proxy, 'https': proxy})) if proxy else None
    direct_opener = ur.build_opener(ur.ProxyHandler({}))  # 强制直连
    files = []
    smap = {}
    stopped = False
    for i, u in enumerate(urls):
        if stop_event is not None and stop_event.is_set():
            print(f'  [stop] 已停止：跳过剩余 {len(urls) - i} 个源（已下载/旧文件照常并入）')
            stopped = True
            break
        fn = os.path.join(outdir, f'dl_{i}.sub')
        tmp = fn + '.new'
        smap[os.path.basename(fn)] = {'url': u, 'line': i + 1}
        print(f'  下载 [{i}] {u}')
        ok = False
        for label, op in ((f'via proxy {proxy}', proxy_opener), ('直连', direct_opener)):
            if op is None:
                continue
            try:
                req = ur.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
                data = op.open(req, timeout=30).read().decode('utf-8', 'replace')
                open(tmp, 'w', encoding='utf-8', errors='replace').write(data)
                os.replace(tmp, fn)          # 成功才替换；旧文件在此之前不动
                print(f'    ✓ {label} 成功 ({len(data)} B)')
                ok = True
                break
            except Exception as e:
                print(f'    ✗ {label} 失败: {e}')
        if not ok:
            try:
                if os.path.exists(tmp): os.remove(tmp)
            except OSError:
                pass
            if os.path.exists(fn):
                print(f'    ⚠ 下载失败，保留上次的旧文件 {os.path.basename(fn)}')
                files.append(fn)
            else:
                print(f'    跳过（两种通道都失败，且无旧文件）')
            continue
        files.append(fn)
    SMAP.update(smap)
    return files   # 溯源靠全局 SMAP（process_file 查它）；清单在 main 解析完写

def sanitize_for_mihomo(mihomo_exe, candidates, max_rounds=80):
    """mihomo 严格校验：一个坏 proxy 就拒整份配置。本函数循环跑 `mihomo -t`，
    解析报错的 proxy（type+server+port），逐个丢弃，直到通过或无法解析。
    candidates: [(key, dict, raw, kind), ...]（NODES 条目）
    返回 (kept, removed, passed, last_err)"""
    import subprocess, copy
    geodir = os.path.dirname(os.path.abspath(mihomo_exe))
    kept = list(candidates)
    removed = []
    passed = False
    last_err = ''
    for rnd in range(max_rounds):
        tmp = os.path.join(geodir, '_sanitize_tmp.yaml')
        # 用副本 emit，避免改名污染共享 dict
        emit_clash_yaml(tmp, [(k, copy.deepcopy(d), r, ki) for k, d, r, ki in kept])
        try:
            p = subprocess.run([mihomo_exe, '-d', geodir, '-f', tmp, '-t'],
                               capture_output=True, text=True, timeout=180, cwd=geodir)
        except Exception as e:
            last_err = f'mihomo 执行异常: {e}'
            break
        finally:
            try: os.remove(tmp)
            except OSError: pass
        if p.returncode == 0:
            passed = True
            break
        out_txt = (p.stdout or '') + (p.stderr or '')
        # proxy 级错误形如：proxy 417: ss 130.61.37.86:59924 cipher: ... error
        m = re.search(r'proxy\s+\d+:\s*([a-z0-9\-]+)\s+([^\s:]+):(\d+)', out_txt)
        if m:
            t, srv, pno = m.group(1), m.group(2), m.group(3)
            bad = [n for n in kept if n[1].get('type') == t
                   and str(n[1].get('server')) == srv and str(n[1].get('port')) == pno]
            if not bad:
                last_err = f'定位失败（无法匹配 {t} {srv}:{pno}）'
                break
            for n in bad:
                kept.remove(n)
            removed.extend(bad)
            continue
        # 兜底：解析不了 type/server（如 "proxy 8610: '' has unset fields: cipher"）
        # → 按报错里的 proxy 序号（0-based）直接剔除该位置节点；防同轮报错多个序号，逐个剔
        idx_m = re.findall(r'proxy\s+(\d+):', out_txt)
        if not idx_m:
            last_err = out_txt.strip().splitlines()[-1][:200] if out_txt.strip() else '未知错误'
            break
        bad = []
        for idx in idx_m:
            i = int(idx)
            if 0 <= i < len(kept):
                bad.append(kept[i])
        if not bad:
            last_err = f'序号越界 {idx_m}（kept={len(kept)}）'
            break
        for n in bad:
            kept.remove(n)
        removed.extend(bad)
    return kept, removed, passed, last_err

def _find_lone_surrogates(nodes):
    """定位含孤立 surrogate (U+D800–DFFF) 的字段样本 — 排查脏源用。
    返回 [(kind, field, 样本值, ...)]。纯只读, 不改数据。"""
    bad = []
    for key, d, raw, kind in nodes:
        for f in ('name', 'server', 'password', 'uuid'):
            v = d.get(f)
            if isinstance(v, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in v):
                bad.append((kind, f, v[:48]))
        r = raw.get('raw') if isinstance(raw, dict) else None
        if isinstance(r, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in r):
            bad.append((kind, 'raw-uri', r[:48]))
    return bad


def _write_source_manifest(outdir, smap):
    """写 out/_sources.json：dl_N.sub ↔ node_pools.txt 行号/原始 URL + 该源解析出的节点数（可溯源）。"""
    if not smap:
        return
    import json as _json
    rows = []
    for label, meta in sorted(smap.items(), key=lambda kv: (kv[1].get('line') or 0)):
        st = SRC_STAT.get(label, {})
        rows.append({'line': meta.get('line'), 'file': label, 'url': meta.get('url', ''),
                     'nodes': st.get('nodes', 0), 'dropped': st.get('warns', {})})
    try:
        open(os.path.join(outdir, '_sources.json'), 'w', encoding='utf-8', errors='replace').write(
            _json.dumps(rows, ensure_ascii=False, indent=1))
    except Exception:
        pass

def _print_coverage():
    """打印逐源解析/丢弃统计（"哪个源脏/重复/丢格式" 直接可定位）+ 无法逆编码计数。"""
    if not SRC_STAT:
        return
    print('\n== 逐源统计（可溯源：dl_N.sub ↔ node_pools.txt 第 N 行 / 原始 URL）==')
    for label, st in sorted(SRC_STAT.items(), key=lambda kv: -kv[1].get('nodes', 0)):
        dropped = st.get('warns', {})
        ds = ', '.join('%s×%d' % (k, v) for k, v in sorted(dropped.items(), key=lambda x: -x[1]) if k != '重复')
        dup = dropped.get('重复', 0)
        extra = ('  重复×%d' % dup) if dup else ''
        tail = ('  丢弃: ' + ds) if ds else ''
        print('  [%s] nodes=%d%s%s' % (label, st.get('nodes', 0), extra, tail))
    n_ne = WARN.get('无法逆编码URI(跳过)', 0)
    if n_ne:
        print('  [round-trip] %d 个节点无法逆编码成 URI（socks/http/ssr 等，仍进 clash.yaml）' % n_ne)


def main():
    ap = argparse.ArgumentParser(description='零依赖订阅转换/合并器')
    ap.add_argument('inputs', nargs='*', help='订阅文件或目录')
    ap.add_argument('--urls', help='|分隔的订阅 URL 列表（先下载再转换）')
    ap.add_argument('--urlfile', help='订阅 URL 文件（每行一个，# 开头为注释），合并进 --urls')
    ap.add_argument('--proxy', help='下载用代理，如 http://127.0.0.1:7890')
    ap.add_argument('-o', '--out', default='subconv-out', help='输出目录')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    inputs = list(args.inputs)
    if args.urlfile:
        extra = [l.strip() for l in open(args.urlfile, encoding='utf-8').read().splitlines()
                 if l.strip() and not l.startswith('#')]
        if extra:
            args.urls = '|'.join(([args.urls] if args.urls else []) + extra)
    if args.urls:
        dl = fetch_urls([x.strip() for x in args.urls.split('|') if x.strip()], args.out, args.proxy)
        inputs += dl

    if not inputs:
        ap.print_help(); return
    _ok, _msg = ensure_vendor_yaml()
    print(f'  [pyyaml] {_msg}')
    for it in inputs:
        if os.path.isdir(it):
            for f in sorted(os.listdir(it)):
                if f.endswith(('.txt', '.yaml', '.yml', '.json', '.sub')):
                    process_file(os.path.join(it, f))
        else:
            process_file(it)

    if not NODES:
        print('!! 没有解析到任何节点'); return

    # 节点名兜底
    for key, d, raw, kind in NODES:
        if not d.get('name'):
            d['name'] = f'{d["server"]}:{d["port"]}'

    # 脏源诊断: 列出带孤立 surrogate 的字段 (输出已用 replace 兜底为 U+FFFD, 不崩; 这里帮定位来源)
    _bad = _find_lone_surrogates(NODES)
    if _bad:
        print('\n' + '=' * 56)
        print('!! 检出 %d 个字段含孤立 surrogate (源数据脏, 输出已替换为 U+FFFD;' % len(_bad))
        print('   建议排查下列类型来源, 必要时从 node_pools.txt 摘除该源):')
        for kind, f, s in _bad[:10]:
            print('   [%s] %s = %r' % (kind, f, s))
        print('=' * 56)
    out_c = os.path.join(args.out, 'merged-clash.yaml')
    out_v = os.path.join(args.out, 'merged-v2ray.txt')
    emit_clash_yaml(out_c, NODES)
    emit_v2ray_lines(out_v, NODES)   # 纯 URI 行（v2rayN/FlClash 本地导入）
    emit_v2ray_blob(os.path.join(args.out, 'merged-v2ray-blob.txt'), NODES)   # 整段 base64（订阅链接格式）
    from collections import Counter
    by = Counter(k for _, _, _, k in NODES)
    print(f'\n== 完成: {len(NODES)} 个节点（去重后）')
    print(f'   协议分布: ' + ', '.join(f'{k}×{v}' for k, v in by.most_common()))
    if WARN:
        print('   跳过/警告:')
        for r, n in sorted(WARN.items(), key=lambda x: -x[1]):
            print(f'     {r}: {n}')
    _write_source_manifest(args.out, SMAP)   # 溯源清单：dl_N.sub ↔ node_pools.txt 行号/URL + 各源节点数
    _print_coverage()
    print(f'   输出: {out_c}\n         {out_v}')

if __name__ == '__main__':
    main()



