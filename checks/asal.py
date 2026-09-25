#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""asal: đánh giá tư thế an ninh của agent theo guideline ASAL. Thiết kế: checks/DESIGN.md.

Ba lệnh:

  collect  Đọc cấu hình MCP và settings của client trên máy (SC-01, SC-02, SC-03, NET-04,
           ACT-03; với Claude Code thêm ISO-02 và ISO-03 cho tool file built-in).
           Chạy như người dùng bình thường, ngoài sandbox.
  probe    Thử những gì tiến trình của agent làm được (ISO-01, ISO-03, ISO-04, NET-01,
           NET-02, CRED-01). Phải chạy BÊN TRONG môi trường của agent.
  report   Gom nhiều file JSON do collect và probe ghi ra, đối chiếu với policy và xác
           nhận tay, xuất báo cáo Markdown hoặc CSV theo cấp ASAL.

Ví dụ:
  python3 checks/asal.py collect
  python3 checks/asal.py probe --context devcontainer --use-case coding-agent -o probe.json
  python3 checks/asal.py report reports/ --policy policy.json --attest attest.json -o report.md

collect và probe không in nội dung secret nào và không tự gửi dữ liệu đi đâu. Phép thử
đọc file chỉ đọc một byte rồi bỏ đi; phép thử socket chỉ mở kết nối rồi đóng. Phép thử
mạng kết nối tới các địa chỉ công cộng ghi trong --help.

Kết quả chỉ nói về những đường đi đã thử (guideline, Mục 0.5). Đạt không chứng minh hệ
thống an toàn; chưa đạt thì chắc chắn có đường hở.

Chỉ dùng thư viện chuẩn của Python 3.9 trở lên.
"""
import argparse, base64, csv, datetime, glob, hashlib, hmac, io, json, os, platform, re
import shutil, socket, subprocess, sys, tempfile, urllib.parse, uuid

VERSION = "0.1.1"
REPORT_SCHEMA = "asal-report/1"
POLICY_SCHEMA = "asal-policy/1"
ATTEST_SCHEMA = "asal-attestation/1"
MATRIX_SCHEMA = "asal-matrix/1"

PASS, FAIL, REVIEW, UNTESTED, NA = "pass", "fail", "review", "untested", "na"
LABEL = {PASS: "Đạt", FAIL: "Chưa đạt", REVIEW: "Cần xem", UNTESTED: "Chưa kiểm được", NA: "Không áp dụng"}
SEVERITY = {FAIL: 0, REVIEW: 1, UNTESTED: 2, PASS: 3, NA: 4}

IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
HOME = os.path.expanduser("~")

CAVEAT = ("Kết quả chỉ nói về những đường đi đã thử (guideline, Mục 0.5). "
          "Đạt không chứng minh hệ thống an toàn; chưa đạt thì chắc chắn có đường hở.")


class Run:
    """Results of one collect or probe run."""

    def __init__(self):
        self.results = []
        self.inventory = []

    def add(self, probe, control, status, message, evidence=None, kind="test"):
        self.results.append({"probe": probe, "control": control, "kind": kind, "status": status,
                             "message": message, "evidence": [tilde(e) for e in (evidence or [])]})


def tilde(value):
    """Replace the home directory with ~ in a string, so reports do not carry the user name."""
    s = str(value)
    if HOME and HOME != "/" and HOME in s:
        s = s.replace(HOME, "~")
    return s


# ----------------------------------------------------------------------------------------
# Low-level helpers

def can_read(path):
    """True if the process can read the path. Reads at most one byte; never prints content."""
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            with open(path, "rb") as f:
                f.read(1)
        return True
    except OSError:
        return False


def exists(path):
    try:
        return os.path.lexists(path)
    except OSError:
        return False


def path_state(path):
    """'absent', 'blocked' or 'readable'. A path hidden by a sandbox (EPERM or EACCES on lstat)
    counts as blocked, not absent."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "blocked"
    return "readable" if can_read(path) else "blocked"


def unix_socket_connectable(path):
    if IS_WIN or not path or not exists(path):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def tcp_connect(host, port, family=socket.AF_UNSPEC, timeout=3):
    """Direct TCP connect, ignoring any proxy settings. Returns (connected, reason)."""
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, "không phân giải được tên (%s)" % e.strerror
    last = "không có địa chỉ"
    for fam, typ, proto, _, addr in infos:
        s = socket.socket(fam, typ, proto)
        s.settimeout(timeout)
        try:
            s.connect(addr)
            return True, "kết nối được tới %s" % (addr[0],)
        except OSError as e:
            last = e.strerror or str(e)
        finally:
            s.close()
    return False, last


def udp_dns_reply(server, timeout=3):
    """Send one DNS query for example.org over UDP; True if a reply comes back."""
    query = (b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03org\x00\x00\x01\x00\x01")
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
    except OSError as e:
        return False, e.strerror or type(e).__name__
    s.settimeout(timeout)
    try:
        s.sendto(query, (server, 53))
        data, _ = s.recvfrom(512)
        return data[:2] == b"\x13\x37", "có trả lời"
    except OSError as e:
        return False, e.strerror or type(e).__name__
    finally:
        s.close()


def run_quiet(cmd, timeout=5):
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def container_kind():
    if exists("/.dockerenv"):
        return "docker"
    if exists("/run/.containerenv"):
        return "podman"
    try:
        with open("/proc/1/cgroup") as f:
            if re.search(r"docker|containerd|kubepods|libpod", f.read()):
                return "container"
    except OSError:
        pass
    return None


def home_mount():
    """Linux: (mount point, fs type) of the mount that holds HOME, from /proc/self/mountinfo."""
    try:
        with open("/proc/self/mountinfo") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    best = None
    for line in lines:
        left, _, right = line.partition(" - ")
        fields, rfields = left.split(), right.split()
        if len(fields) < 5 or not rfields:
            continue
        point = fields[4].replace("\\040", " ")
        if HOME == point or HOME.startswith(point.rstrip("/") + "/"):
            if best is None or len(point) > len(best[0]):
                best = (point, rfields[0])
    return best


# ----------------------------------------------------------------------------------------
# collect: MCP configuration and client settings

def mcp_config_files(workspace):
    """(client, path, scope, loader) for every known MCP configuration location (SC-01)."""
    appdata = os.environ.get("APPDATA", "")
    user = [
        ("Claude Code", os.path.join(HOME, ".claude.json"), "user", "claude_json"),
        ("Claude Desktop", os.path.join(HOME, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "user", "mcpServers"),
        ("Claude Desktop", os.path.join(HOME, ".config", "Claude", "claude_desktop_config.json"), "user", "mcpServers"),
        ("Claude Desktop", os.path.join(appdata, "Claude", "claude_desktop_config.json") if appdata else "", "user", "mcpServers"),
        ("Cursor", os.path.join(HOME, ".cursor", "mcp.json"), "user", "mcpServers"),
        ("Codex CLI", os.path.join(HOME, ".codex", "config.toml"), "user", "codex_toml"),
        # https://antigravity.google/docs/mcp/ (shared by Antigravity 2.0, IDE and CLI)
        ("Antigravity", os.path.join(HOME, ".gemini", "config", "mcp_config.json"), "user", "mcpServers"),
        # https://opencode.ai/docs/config/, https://opencode.ai/v2/docs/config
        ("opencode", os.path.join(HOME, ".config", "opencode", "opencode.json"), "user", "opencode"),
        ("opencode", os.path.join(HOME, ".config", "opencode", "opencode.jsonc"), "user", "opencode"),
    ]
    project = [
        ("Claude Code", os.path.join(workspace, ".mcp.json"), "project", "mcpServers"),
        ("Cursor", os.path.join(workspace, ".cursor", "mcp.json"), "project", "mcpServers"),
        ("VS Code", os.path.join(workspace, ".vscode", "mcp.json"), "project", "servers"),
        ("Antigravity", os.path.join(workspace, ".agents", "mcp_config.json"), "project", "mcpServers"),
        ("opencode", os.path.join(workspace, "opencode.json"), "project", "opencode"),
        ("opencode", os.path.join(workspace, "opencode.jsonc"), "project", "opencode"),
        ("opencode", os.path.join(workspace, ".opencode", "opencode.json"), "project", "opencode"),
        ("opencode", os.path.join(workspace, ".opencode", "opencode.jsonc"), "project", "opencode"),
    ]
    # A file hidden by a sandbox is kept, so that reading it fails loudly instead of the
    # location counting as empty.
    return [entry for entry in user + project if entry[1] and path_state(entry[1]) != "absent"]


def parse_codex_toml(text):
    """Minimal reader for [mcp_servers.NAME] tables in Codex config.toml (command, args, url, cwd, enabled)."""
    servers, current = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r'\[mcp_servers\.("[^"]+"|[^.\]]+)(\.[^\]]+)?\]$', line)
        if m:
            # [mcp_servers.NAME] opens a server; [mcp_servers.NAME.env] is a sub-table of it.
            current = None if m.group(2) else servers.setdefault(m.group(1).strip('"'), {})
            continue
        if line.startswith("["):
            current = None
            continue
        if current is None:
            continue
        m = re.match(r"(command|url|cwd)\s*=\s*\"(.*)\"", line)
        if m:
            current[m.group(1)] = m.group(2)
        m = re.match(r"enabled\s*=\s*(true|false)\b", line)
        if m:
            current["enabled"] = m.group(1) == "true"
        m = re.match(r"args\s*=\s*\[(.*)\]", line)
        if m:
            current["args"] = re.findall(r"\"((?:[^\"\\]|\\.)*)\"", m.group(1))
    return servers


def parse_codex_plugins(text):
    """{"name@marketplace": enabled} from the [plugins."name@marketplace"] tables of Codex config.toml."""
    plugins, current = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r'\[plugins\.("[^"]+"|[^.\]]+)\]$', line)
        if m:
            current = m.group(1).strip('"')
            plugins.setdefault(current, False)
            continue
        if line.startswith("["):
            current = None
            continue
        m = re.match(r"enabled\s*=\s*(true|false)\b", line)
        if current and m:
            plugins[current] = m.group(1) == "true"
    return plugins


def _manifest_part(root, value, key):
    """A plugin manifest field that is either inline or a path, relative to the plugin root, to a
    JSON file holding {key: ...} (Codex .mcp.json, .app.json)."""
    if isinstance(value, str):
        with open(os.path.join(root, value), encoding="utf-8") as f:
            data = json.load(f)
        value = data.get(key, data) if isinstance(data, dict) else {}
    return value if isinstance(value, dict) else {}


def codex_plugins():
    """Plugins enabled in Codex config.toml, with the MCP servers, apps and hooks each declares.

    Codex keeps installed plugins under ~/.codex/plugins/cache/<marketplace>/<name>/<version>/,
    with the manifest in .codex-plugin/plugin.json. This layout was read from a Codex install
    (2026-09); Codex does not document it, so a plugin that cannot be read is reported, never
    skipped.
    """
    config = os.path.join(HOME, ".codex", "config.toml")
    try:
        with open(config, encoding="utf-8") as f:
            enabled = [p for p, on in parse_codex_plugins(f.read()).items() if on]
    except OSError:
        return []
    found = []
    for plugin in enabled:
        name, _, market = plugin.partition("@")
        item = {"client": "Codex CLI", "plugin": plugin, "root": "", "version": "", "servers": {},
                "apps": {}, "hooks": False, "error": ""}
        roots = glob.glob(os.path.join(HOME, ".codex", "plugins", "cache", glob.escape(market), glob.escape(name), "*", ".codex-plugin", "plugin.json"))
        if not roots:
            item["error"] = "không thấy manifest trong ~/.codex/plugins/cache/%s/%s/" % (market, name)
            found.append(item)
            continue
        manifest = max(roots, key=os.path.getmtime)
        root = os.path.dirname(os.path.dirname(manifest))
        item["root"], item["version"] = root, os.path.basename(root)
        try:
            with open(manifest, encoding="utf-8") as f:
                data = json.load(f)
            item["servers"] = _manifest_part(root, data.get("mcpServers"), "mcpServers")
            item["apps"] = _manifest_part(root, data.get("apps"), "apps")
            item["hooks"] = bool(data.get("hooks"))
        except (OSError, ValueError, AttributeError) as e:
            item["error"] = "không đọc được manifest %s: %s" % (tilde(manifest), e)
        found.append(item)
    return found


def _install_paths(index, plugin):
    """installPath values recorded for plugin in Claude Code's installed_plugins.json, whatever
    the nesting: the docs name the fields (scope, installPath, version), not the layout."""
    paths = []
    def walk(node, under):
        if isinstance(node, dict):
            if under and isinstance(node.get("installPath"), str):
                paths.append(node["installPath"])
            for k, v in node.items():
                walk(v, under or k == plugin)
        elif isinstance(node, list):
            for v in node:
                walk(v, under)
    walk(index, False)
    return paths


def claude_plugins(workspace):
    """Plugins enabled in Claude Code settings, with the MCP servers and hooks each declares.

    https://code.claude.com/docs/en/plugins/loading.md: plugins live under
    ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/ (or CLAUDE_CODE_PLUGIN_CACHE_DIR),
    recorded in installed_plugins.json. enabledPlugins is read from managed, local, project and
    user settings, the first scope that names a plugin deciding. MCP servers come from .mcp.json
    at the plugin root and the manifest's mcpServers; hooks from hooks/hooks.json and the
    manifest's hooks (https://code.claude.com/docs/en/plugins/components.md).
    """
    sources = claude_code_settings(workspace)
    decided = {}
    for scope in ("managed", "local", "project", "user"):
        for s, path, data in sources:
            if s != scope:
                continue
            for plugin, on in _section(data, "enabledPlugins").items():
                decided.setdefault(plugin, (on is True, s))
    enabled = sorted((p, s) for p, (on, s) in decided.items() if on)
    if not enabled:
        return []
    base = os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR") or os.path.join(HOME, ".claude", "plugins")
    try:
        with open(os.path.join(base, "installed_plugins.json"), encoding="utf-8") as f:
            index = json.load(f)
    except (OSError, ValueError):
        index = {}
    found = []
    for plugin, scope in enabled:
        name, _, market = plugin.partition("@")
        item = {"client": "Claude Code", "plugin": plugin, "scope": scope, "root": "", "version": "",
                "servers": {}, "apps": {}, "hooks": False, "error": ""}
        roots = [r for r in _install_paths(index, plugin) if os.path.isdir(r)]
        roots = roots or [d for d in glob.glob(os.path.join(base, "cache", glob.escape(market), glob.escape(name), "*")) if os.path.isdir(d)]
        if not roots:
            item["error"] = "không thấy thư mục cài đặt trong %s" % tilde(base)
            found.append(item)
            continue
        root = max(roots, key=os.path.getmtime)
        item["root"], item["version"] = root, os.path.basename(root)
        try:
            manifest = {}
            mpath = os.path.join(root, ".claude-plugin", "plugin.json")
            if os.path.isfile(mpath):
                with open(mpath, encoding="utf-8") as f:
                    manifest = json.load(f)
            servers = {}
            if os.path.isfile(os.path.join(root, ".mcp.json")):
                servers.update(_manifest_part(root, ".mcp.json", "mcpServers"))
            declared = manifest.get("mcpServers")
            for part in (declared if isinstance(declared, list) else [declared] if declared else []):
                if isinstance(part, str) and not part.endswith(".json"):
                    raise ValueError("mcpServers trỏ tới MCP bundle %s, asal chưa đọc được" % part)
                servers.update(_manifest_part(root, part, "mcpServers"))
            item["servers"] = servers
            item["hooks"] = bool(manifest.get("hooks")) or os.path.isfile(os.path.join(root, "hooks", "hooks.json"))
        except (OSError, ValueError, AttributeError) as e:
            item["error"] = "không đọc được plugin trong %s: %s" % (tilde(root), e)
        found.append(item)
    return found


def plugin_sources(workspace):
    """Enabled plugins of every client asal knows, each with "kind" (codex, claude)."""
    found = [dict(p, kind="codex") for p in codex_plugins()]
    found += [dict(p, kind="claude") for p in claude_plugins(workspace)]
    return found


def strip_jsonc(text):
    """JSON with comments and trailing commas (opencode .jsonc) to plain JSON."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _opencode_servers(data):
    """opencode "mcp": v1 {name: server}, v2 {"servers": {name: server}}. A local server's command
    is one array; v1 turns a server off with enabled: false, v2 with disabled: true."""
    mcp = data.get("mcp") if isinstance(data.get("mcp"), dict) else {}
    inner = mcp.get("servers")
    if isinstance(inner, dict) and not {"type", "command", "url"} & set(inner):
        mcp = inner
    servers = {}
    for name, srv in mcp.items():
        if not isinstance(srv, dict):
            continue
        srv = dict(srv)
        cmd = srv.get("command")
        if isinstance(cmd, list):
            srv["command"], srv["args"] = (str(cmd[0]), [str(a) for a in cmd[1:]]) if cmd else ("", [])
        servers[name] = srv
    return servers


def _normalize(servers):
    """Field names that differ between clients, mapped to the ones pin_status and collect read:
    Antigravity serverUrl and Gemini httpUrl to url; disabled: true to enabled: false."""
    for srv in servers.values():
        if isinstance(srv, dict):
            if not srv.get("url") and (srv.get("serverUrl") or srv.get("httpUrl")):
                srv["url"] = srv.get("serverUrl") or srv.get("httpUrl")
            if srv.get("disabled") is True:
                srv["enabled"] = False
    return servers


def load_servers(path, loader):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.strip():
        return {}  # Antigravity creates an empty mcp_config.json before any server is added.
    if loader == "codex_toml":
        return parse_codex_toml(text)
    if loader == "opencode":
        return _normalize(_opencode_servers(json.loads(strip_jsonc(text))))
    data = json.loads(text)
    return _normalize(_load_json_servers(data, loader))


def _load_json_servers(data, loader):
    if loader == "claude_json":
        servers = dict(data.get("mcpServers") or {})
        # Servers added per project with "local" scope live under projects.<path>.mcpServers.
        for proj, cfg in (data.get("projects") or {}).items():
            for name, srv in ((cfg or {}).get("mcpServers") or {}).items():
                servers["%s (local, %s)" % (name, tilde(proj))] = srv
        return servers
    return dict(data.get(loader) or {})


VERSION_RE = re.compile(r"^(@[^/]+/)?[^@]+@(\d[^@]*)$")


def _npx_package(args):
    pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx", "exec")]
    return pkgs[0] if pkgs else ""


def _uvx_spec(command, args):
    rest = args[2:] if command == "uv" else args
    if "--from" in rest:
        i = rest.index("--from") + 1
        return rest[i] if i < len(rest) else ""
    return next((a for a in rest if not a.startswith("-")), "")


def _container_image(args):
    after = args[args.index("run") + 1:]
    return next((a for a in after if not a.startswith("-") and "=" not in a), "")


def _launcher(server):
    command = os.path.basename(str(server.get("command", "")))
    args = [str(a) for a in server.get("args", []) or []]
    if command in ("npx", "npx.cmd", "bunx", "pnpx") or (command in ("pnpm", "npm") and args[:1] in (["dlx"], ["exec"])):
        return "npm", command, args
    if command in ("uvx", "uvx.exe") or (command == "uv" and args[:2] == ["tool", "run"]):
        return "pypi", command, args
    if command in ("docker", "podman") and "run" in args:
        return "oci", command, args
    return "local", command, args


def _relative_command(command):
    """True for a command given as a relative path (./x, bin/x): which binary runs then depends
    on the directory the client starts it from, which a configuration file does not show."""
    return bool(command) and ("/" in command or "\\" in command) and not os.path.isabs(command) \
        and not command.startswith(("~", "$", "%"))


def pin_status(server, base=None):
    """How a server is started, (status, reason). guideline SC-03. (None, None) for remote servers.

    base is the directory the configuration came from (a plugin root), used only to say whether
    a relative command has a matching file there.
    """
    if server.get("url"):
        return None, None
    kind, command, args = _launcher(server)
    if kind == "npm":
        pkg = _npx_package(args)
        if not pkg:
            return FAIL, "%s không rõ package" % command
        if pkg.endswith("@latest"):
            return FAIL, "%s %s dùng @latest" % (command, pkg)
        if not VERSION_RE.match(pkg):
            return FAIL, "%s %s không kèm phiên bản" % (command, pkg)
        return PASS, "%s %s ghim phiên bản (chưa ghim dependency, xem SC-03)" % (command, pkg)
    if kind == "pypi":
        spec = _uvx_spec(command, args)
        if re.search(r"(==|@)\d", spec):
            return PASS, "uvx %s ghim phiên bản" % spec
        return FAIL, "uvx %s không kèm phiên bản" % (spec or "?")
    if kind == "oci":
        image = _container_image(args)
        if "@sha256:" in image:
            return PASS, "%s ghim theo digest" % image
        if ":" not in image.split("/")[-1] or image.endswith(":latest"):
            return FAIL, "image %s không ghim tag hay digest" % (image or "?")
        return REVIEW, "image %s ghim tag, chưa ghim digest" % image
    command = str(server.get("command") or "")
    if _relative_command(command):
        cwd = os.path.expanduser(str(server.get("cwd") or ""))
        if os.path.isabs(cwd):
            return PASS, "chạy trực tiếp %s" % tilde(os.path.normpath(os.path.join(cwd, command)))
        note = ""
        if base and os.path.isfile(os.path.join(base, command)):
            note = "; có file cùng tên trong %s" % tilde(base)
        return REVIEW, ("đường dẫn tương đối %s: binary nào chạy tùy thư mục client dùng làm cwd, "
                        "nếu đó là workspace thì repo quyết định binary%s" % (command, note))
    return PASS, "chạy trực tiếp %s" % (command or "?")


def server_identity(server):
    """A stable identity string for a configured server, used by the policy's approved list.

    Format: oci:<image>, pkg:npm:<name@version>, pkg:pypi:<spec>, url:<scheme://host[:port]/path>,
    local:<command>. This is a practical identity for inventory, not the full aab-00 Section 5.2
    normalization; approve servers with the string that `asal collect` prints.
    """
    url = server.get("url")
    if url:
        p = urllib.parse.urlsplit(str(url))
        port = "" if p.port in (None, 443 if p.scheme == "https" else 80) else ":%d" % p.port
        return "url:%s://%s%s%s" % (p.scheme.lower(), (p.hostname or "").lower(), port, p.path or "/")
    kind, command, args = _launcher(server)
    if kind == "npm":
        return "pkg:npm:%s" % _npx_package(args)
    if kind == "pypi":
        return "pkg:pypi:%s" % _uvx_spec(command, args)
    if kind == "oci":
        return "oci:%s" % _container_image(args)
    return "local:%s" % tilde(server.get("command") or "?")


def collect_mcp(run, workspace):
    files = mcp_config_files(workspace)
    project, pins, remotes, unread, disabled = [], [], [], [], []
    for client, path, scope, loader in files:
        try:
            servers = load_servers(path, loader)
        except (OSError, ValueError) as e:
            run.add("sc01.config.unreadable", "SC-01", REVIEW, "không đọc được %s" % tilde(path), [str(e)], kind="config")
            unread.append(tilde(path))
            continue
        for name, srv in servers.items():
            srv = srv if isinstance(srv, dict) else {}
            where = "%s: %s" % (tilde(path), name)
            if srv.get("enabled") is False:
                disabled.append(where)
                continue
            st, why = pin_status(srv)
            run.inventory.append({"client": client, "config": tilde(path), "scope": scope, "name": name,
                                  "identity": server_identity(srv), "remote": bool(srv.get("url")),
                                  "launch": st, "launch_note": why})
            if scope == "project":
                project.append(where)
            if st:
                pins.append((st, "%s → %s" % (where, why)))
            if srv.get("url"):
                remotes.append((where, str(srv["url"]), str(srv.get("type") or srv.get("transport") or "")))

    plugins = plugin_sources(workspace)
    unreadable, hooks = [], []
    for p in plugins:
        label = "%s plugin %s" % (p["client"], p["plugin"])
        if p["error"]:
            unreadable.append("%s: %s" % (label, p["error"]))
            continue
        config = "%s (plugin %s)" % (tilde(p["root"]), p["plugin"])
        for name, srv in p["servers"].items():
            srv = srv if isinstance(srv, dict) else {}
            if srv.get("enabled") is False:
                disabled.append("%s: %s" % (label, name))
                continue
            st, why = pin_status(srv, p["root"])
            run.inventory.append({"client": p["client"], "config": config, "scope": "plugin", "name": name,
                                  "identity": "plugin:%s:%s/%s/%s" % (p["kind"], p["plugin"], p["version"], name),
                                  "remote": bool(srv.get("url")), "launch": st, "launch_note": why})
            if st:
                pins.append((st, "%s: %s → %s" % (label, name, why)))
            if srv.get("url"):
                remotes.append(("%s: %s" % (label, name), str(srv["url"]), str(srv.get("type") or srv.get("transport") or "")))
        for name, app in p["apps"].items():
            app_id = app.get("id") if isinstance(app, dict) else ""
            run.inventory.append({"client": p["client"], "config": config, "scope": "plugin", "name": name,
                                  "identity": "app:%s:%s" % (p["kind"], app_id or name), "remote": True,
                                  "launch": None, "launch_note": "connector do nhà cung cấp client vận hành"})
        if p["hooks"]:
            hooks.append("%s (%s)" % (label, tilde(p["root"])))

    project += ["%s (enabledPlugins trong settings cấp %s)" % (p["plugin"], p["scope"])
                for p in plugins if p.get("scope") == "project"]
    n_plugins = sum(1 for p in plugins if not p["error"])
    if run.inventory:
        run.add("sc01.inventory", "SC-01", PASS, "thu được danh mục: %d MCP server và connector, từ %d file cấu hình và %d plugin" % (len(run.inventory), len(files), n_plugins),
                [i["config"] + ": " + i["name"] for i in run.inventory] + ["tắt, không tính: " + d for d in disabled], kind="config")
    elif unread:
        run.add("sc01.inventory", "SC-01", UNTESTED, "không liệt kê được: %d file cấu hình không đọc được" % len(unread), unread, kind="config")
    else:
        run.add("sc01.inventory", "SC-01", NA, "không thấy file cấu hình MCP ở các vị trí mặc định", kind="config")
    if unreadable:
        run.add("sc01.plugins", "SC-01", REVIEW, "có plugin đang bật mà không đọc được manifest: danh mục có thể thiếu server của plugin đó", unreadable, kind="config")
    if hooks:
        run.add("sc01.plugin.hooks", "SC-01", REVIEW, "plugin có hook: hook chạy ngoài sandbox của client (đã thử với Claude Code), cần duyệt như code chạy thẳng trên máy", hooks, kind="config")

    if project:
        run.add("sc02.project.config", "SC-02", REVIEW, "có cấu hình MCP cấp project: coi là không tin cậy, thay đổi phải được duyệt", project, kind="config")
    else:
        run.add("sc02.project.config", "SC-02", NA, "không có cấu hình MCP cấp project trong workspace", kind="config")

    if pins:
        worst = min((s for s, _ in pins), key=SEVERITY.get)
        run.add("sc03.launch", "SC-03", worst, "cách khởi động MCP server", ["[%s] %s" % (LABEL[s], d) for s, d in pins], kind="config")
    elif unread:
        run.add("sc03.launch", "SC-03", UNTESTED, "không thấy MCP server local trong các file đọc được", unread, kind="config")
    else:
        run.add("sc03.launch", "SC-03", NA, "không có MCP server local", kind="config")

    if remotes:
        bad = []
        for where, url, transport in remotes:
            p = urllib.parse.urlsplit(url)
            loopback = (p.hostname or "") in ("localhost", "127.0.0.1", "::1")
            if p.scheme == "http" and not loopback:
                bad.append((FAIL, "%s: %s không dùng HTTPS" % (where, url)))
            elif transport == "sse":
                bad.append((REVIEW, "%s: transport HTTP+SSE đã deprecated" % where))
        st = min((s for s, _ in bad), key=SEVERITY.get) if bad else PASS
        run.add("net04.remote.https", "NET-04", st, "%d remote MCP server; phần xác thực OAuth cần kiểm tay" % len(remotes),
                ["[%s] %s" % (LABEL[s], d) for s, d in bad] or ["%s: %s" % (w, u) for w, u, _ in remotes], kind="config")
    elif unread:
        run.add("net04.remote.https", "NET-04", UNTESTED, "không thấy remote MCP server trong các file đọc được", unread, kind="config")
    else:
        run.add("net04.remote.https", "NET-04", NA, "không có remote MCP server", kind="config")


def claude_code_settings(workspace):
    """Claude Code settings sources that exist: [(scope, path, data)].

    https://code.claude.com/docs/en/managed-settings.md, https://code.claude.com/docs/en/settings.md
    """
    if IS_MAC:
        managed = "/Library/Application Support/ClaudeCode/managed-settings.json"
    elif IS_WIN:
        managed = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "ClaudeCode", "managed-settings.json")
    else:
        managed = "/etc/claude-code/managed-settings.json"
    found = []
    for scope, path in [("managed", managed),
                        ("user", os.path.join(HOME, ".claude", "settings.json")),
                        ("project", os.path.join(workspace, ".claude", "settings.json")),
                        ("local", os.path.join(workspace, ".claude", "settings.local.json"))]:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                found.append((scope, path, data))
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            found.append((scope, path, {"__unreadable__": str(e)}))
    return found


# Tokens that agent clients keep for themselves. A command the agent runs can read another
# agent's token (or its own) and use it from elsewhere; the client process needs the file, the
# sandboxed tools do not.
AGENT_TOKENS = [".codex/auth.json", ".claude/.credentials.json", ".gemini/oauth_creds.json",
                ".gemini/jetski-standalone-oauth-token", ".gemini/antigravity/mcp_oauth_tokens.json",
                ".local/share/opencode/auth.json", ".local/share/opencode/mcp-auth.json",
                ".config/opencode/service.json"]

CREDENTIAL_READ = [".ssh", ".aws", ".config/gcloud", ".azure", ".kube", ".docker", ".gnupg",
                   ".netrc", ".git-credentials", ".config/gh"] + AGENT_TOKENS


def _section(data, key):
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def collect_claude_code(run, workspace):
    """ACT-03, ISO-02 and ISO-03 from Claude Code settings.

    The Claude Code sandbox covers Bash, PowerShell and Monitor commands and their child
    processes only; Read, Edit, Write and WebFetch follow permission rules
    (https://code.claude.com/docs/en/sandboxing.md). A probe run through the shell cannot see
    the built-in file tools, so their protection is checked here, from settings.
    """
    sources = claude_code_settings(workspace)
    if not sources and path_state(os.path.join(HOME, ".claude")) == "absent":
        run.add("act03.claude.bypass", "ACT-03", UNTESTED, "không thấy Claude Code trên máy; client khác cần kiểm tay hoặc xác nhận tay", kind="config")
        return
    unreadable = ["%s: %s" % (tilde(p), d["__unreadable__"]) for s, p, d in sources if "__unreadable__" in d]
    if unreadable:
        # A setting we cannot see may be the one that enables or disables something; judging
        # from the rest would give a wrong answer either way.
        msg = "không đọc được settings của Claude Code; nếu collect đang chạy trong sandbox, chạy lại như người dùng bình thường, ngoài sandbox"
        for probe, control in (("act03.claude.bypass", "ACT-03"), ("iso02.claude.sandbox", "ISO-02"), ("iso03.claude.file_tools", "ISO-03")):
            run.add(probe, control, UNTESTED, msg, unreadable, kind="config")
        return

    # ACT-03. bypassPermissions takes effect only from managed or user settings (or the CLI);
    # in project or local settings it is ignored (https://code.claude.com/docs/en/permission-modes.md).
    effective, ignored, disabled = [], [], []
    for scope, path, data in sources:
        perms = _section(data, "permissions")
        if perms.get("defaultMode") == "bypassPermissions":
            (effective if scope in ("managed", "user") else ignored).append("%s: %s" % (scope, path))
        if perms.get("disableBypassPermissionsMode") == "disable":
            disabled.append("%s: %s" % (scope, path))
    if effective:
        run.add("act03.claude.bypass", "ACT-03", FAIL, "Claude Code đặt defaultMode = bypassPermissions (bỏ mọi phê duyệt); chỉ chấp nhận khi cả client chạy trong container (ISO-04)", effective, kind="config")
    elif ignored:
        run.add("act03.claude.bypass", "ACT-03", REVIEW, "bypassPermissions trong settings cấp project không có hiệu lực theo tài liệu của Claude Code, nhưng cho thấy ý định bỏ phê duyệt; nên xóa", ignored, kind="config")
    elif disabled:
        run.add("act03.claude.bypass", "ACT-03", PASS, "Claude Code tắt chế độ bỏ phê duyệt (disableBypassPermissionsMode)", disabled, kind="config")
    else:
        run.add("act03.claude.bypass", "ACT-03", PASS, "Claude Code không đặt bypassPermissions trong settings; cờ --dangerously-skip-permissions vẫn dùng được, nên đặt disableBypassPermissionsMode", kind="config")

    # ISO-02. Managed wins; otherwise the most specific scope that sets sandbox.enabled.
    enabled = None
    for scope in ("managed", "local", "project", "user"):
        for s, path, data in sources:
            sb = _section(data, "sandbox")
            if s == scope and "enabled" in sb:
                enabled = (bool(sb["enabled"]), "%s: %s" % (s, path))
                break
        if enabled:
            break
    if enabled and enabled[0]:
        run.add("iso02.claude.sandbox", "ISO-02", PASS, "Claude Code bật sandbox trong settings; chạy probe qua tool Bash để kiểm nó có chặn thật không", [enabled[1]], kind="config")
    elif enabled:
        run.add("iso02.claude.sandbox", "ISO-02", FAIL, "Claude Code tắt sandbox trong settings (sandbox.enabled = false)", [enabled[1]], kind="config")
    else:
        run.add("iso02.claude.sandbox", "ISO-02", FAIL, "Claude Code không bật sandbox trong settings nào (sandbox.enabled); bật qua /sandbox hoặc managed settings, trừ khi cả client đã chạy trong container hay VM (ISO-04)", kind="config")

    # ISO-03 for the built-in file tools.
    block = [ "%s: %s" % (s, p) for s, p, d in sources if _section(d, "permissions").get("blockReadsOutsideWorkingDirectories") is True]
    if block:
        run.add("iso03.claude.file_tools", "ISO-03", PASS, "Claude Code chặn tool file built-in và lệnh trong sandbox đọc ngoài thư mục làm việc (blockReadsOutsideWorkingDirectories)", block, kind="config")
        return
    deny = []
    for s, path, data in sources:
        deny += [str(r).replace(" ", "") for r in (_section(data, "permissions").get("deny") or [])]
    home_all = any(re.match(r"^Read\((~|//)(/\*\*)?/?\*\*\)$", r) for r in deny)
    missing = []
    for rel in CREDENTIAL_READ:
        if not exists(os.path.join(HOME, *rel.split("/"))):
            continue
        covered = home_all or any(r.startswith("Read(~/%s" % rel) or r.startswith("Read(//%s/%s" % (HOME.strip("/"), rel)) for r in deny)
        if not covered:
            missing.append("~/" + rel)
    if missing:
        run.add("iso03.claude.file_tools", "ISO-03", FAIL,
                "tool file built-in của Claude Code không nằm trong sandbox và chưa bị chặn đọc %d vị trí credential. Đặt permissions.blockReadsOutsideWorkingDirectories, hoặc deny rule Read(...)" % len(missing),
                missing, kind="config")
    else:
        run.add("iso03.claude.file_tools", "ISO-03", PASS, "có deny rule Read(...) cho các vị trí credential có trên máy (tool file built-in của Claude Code)", kind="config")


# Agent clients whose sandbox and approval settings asal does not read yet: the paths that show
# one is installed, and what the vendor's docs say. Claude Code is checked by collect_claude_code.
OTHER_CLIENTS = [
    ("Codex", [".codex"], ["codex"], ""),
    ("opencode", [".config/opencode", ".local/share/opencode", ".opencode/bin/opencode"], ["opencode"],
     "tài liệu không mô tả sandbox cho lệnh shell, và phần lớn quyền mặc định là allow; chạy cả client trong container hay VM (ISO-04)"),
    ("Antigravity", [".gemini/antigravity", ".gemini/antigravity-cli", "/Applications/Antigravity.app"], ["agy", "antigravity"],
     "sandbox bật mặc định trên macOS và Linux, nhưng preset Turbo và Request Review tắt nó; cấu hình của IDE không có đường dẫn trong tài liệu"),
    ("Cursor", [".cursor", "/Applications/Cursor.app"], ["cursor-agent"], ""),
    ("Gemini CLI", [".gemini/settings.json"], ["gemini"], ""),
]


def other_clients():
    found = []
    for name, paths, commands, note in OTHER_CLIENTS:
        seen = []
        for p in [p if os.path.isabs(p) else os.path.join(HOME, *p.split("/")) for p in paths] + \
                 [shutil.which(c) for c in commands]:
            if p and p not in seen and path_state(p) != "absent":
                seen.append(p)
        if seen:
            found.append("%s: %s%s" % (name, ", ".join(tilde(p) for p in seen), (" (%s)" % note) if note else ""))
    return found


def collect_antigravity_cli(run):
    """ISO-02 and ACT-03 from ~/.gemini/antigravity-cli/settings.json, the one Antigravity settings
    file with a documented path and keys (https://antigravity.google/docs/settings/,
    https://antigravity.google/docs/sandbox/). Only settings that turn protection off are judged;
    leaving a key out keeps the documented default."""
    path = os.path.join(HOME, ".gemini", "antigravity-cli", "settings.json")
    if path_state(path) == "absent":
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.loads(strip_jsonc(f.read()) or "{}")
    except (OSError, ValueError) as e:
        run.add("iso02.antigravity_cli.sandbox", "ISO-02", UNTESTED, "không đọc được settings của Antigravity CLI", ["%s: %s" % (tilde(path), e)], kind="config")
        return
    if data.get("enableTerminalSandbox") is False:
        run.add("iso02.antigravity_cli.sandbox", "ISO-02", FAIL, "Antigravity CLI tắt sandbox của terminal (enableTerminalSandbox = false)", [tilde(path)], kind="config")
    if data.get("toolPermission") == "always-proceed":
        run.add("act03.antigravity_cli.always_proceed", "ACT-03", FAIL, "Antigravity CLI chạy tool không hỏi (toolPermission = always-proceed); chỉ chấp nhận khi cả client chạy trong container (ISO-04)", [tilde(path)], kind="config")


def collect_other_clients(run):
    """ISO-02 for clients asal cannot judge. A sandboxed Claude Code says nothing about another
    agent on the same machine, so each one found is review until someone checks it or attests
    that the use case does not use it."""
    found = other_clients()
    if found:
        run.add("iso02.other_clients", "ISO-02", REVIEW,
                "trên máy còn %d client agent mà asal chưa kiểm sandbox và phê duyệt; kiểm tay, hoặc ghi xác nhận tay "
                "rằng use case không dùng chúng" % len(found), found, kind="config")


def do_collect(run, args):
    workspace = os.path.abspath(args.workspace)
    collect_mcp(run, workspace)
    collect_claude_code(run, workspace)
    collect_antigravity_cli(run)
    collect_other_clients(run)


# ----------------------------------------------------------------------------------------
# probe: what the agent's process can do

SENSITIVE = [".ssh", ".aws", ".config/gcloud", ".azure", ".kube", ".docker/config.json", ".gnupg",
             ".netrc", ".git-credentials", ".bash_history", ".zsh_history",
             ".config/gh/hosts.yml", ".npmrc", ".pypirc"] + AGENT_TOKENS
BROWSER = ["Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
           ".config/google-chrome", ".mozilla/firefox", "AppData/Local/Google/Chrome/User Data"]


def probe_iso01(run):
    if IS_WIN:
        try:
            import ctypes
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            run.add("iso01.privilege", "ISO-01", UNTESTED, "không xác định được quyền admin trên Windows")
            return
        run.add("iso01.privilege", "ISO-01", FAIL if admin else PASS,
                "tiến trình chạy với quyền Administrator" if admin else "không chạy với quyền Administrator")
        return
    if os.geteuid() == 0:
        in_container = container_kind() is not None
        run.add("iso01.privilege", "ISO-01", REVIEW if in_container else FAIL,
                "tiến trình chạy bằng root" + (" bên trong container; nên chạy rootless (ISO-04)" if in_container else ""))
        return
    if shutil.which("sudo") and run_quiet(["sudo", "-n", "true"]) == 0:
        run.add("iso01.privilege", "ISO-01", FAIL, "tiến trình dùng được sudo không cần mật khẩu", ["uid=%d" % os.geteuid()])
        return
    run.add("iso01.privilege", "ISO-01", PASS, "không chạy bằng root, không có sudo không mật khẩu", ["uid=%d" % os.geteuid()])


def probe_iso03(run, workspace, keychain_item, extra_homes):
    homes = [HOME] + list(extra_homes)
    readable, blocked = [], []
    for home in homes:
        for rel in SENSITIVE + BROWSER:
            p = os.path.join(home, *rel.split("/"))
            state = path_state(p)
            if state != "absent":
                (readable if state == "readable" else blocked).append(p)
    if readable:
        run.add("iso03.read.credentials", "ISO-03", FAIL, "đọc được %d vị trí credential ngoài workspace" % len(readable), readable)
    elif blocked:
        run.add("iso03.read.credentials", "ISO-03", PASS, "không đọc được %d vị trí credential (bị chặn hoặc bị ẩn)" % len(blocked), blocked)
    else:
        run.add("iso03.read.credentials", "ISO-03", UNTESTED, "không thấy vị trí credential nào để thử (có thể sandbox ẩn cả sự tồn tại, hoặc máy không có)")

    target = next((os.path.join(h, ".ssh") for h in homes if path_state(os.path.join(h, ".ssh")) != "absent"), None)
    if not target:
        run.add("iso03.read.symlink", "ISO-03", UNTESTED, "không có ~/.ssh để thử đọc qua symlink")
    elif IS_WIN:
        run.add("iso03.read.symlink", "ISO-03", UNTESTED, "chưa hỗ trợ phép thử symlink trên Windows")
    else:
        tmp = None
        try:
            tmp = tempfile.mkdtemp(prefix=".asal-", dir=workspace)
            link = os.path.join(tmp, "link")
            os.symlink(target, link)
            ok = can_read(link)
            run.add("iso03.read.symlink", "ISO-03", FAIL if ok else PASS,
                    ("đọc được %s qua symlink trong workspace" if ok else "không đọc được %s qua symlink trong workspace") % tilde(target))
        except OSError as e:
            run.add("iso03.read.symlink", "ISO-03", UNTESTED, "không tạo được symlink thử trong workspace", [str(e)])
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    probe_file = os.path.join(HOME, ".asal-write-test")
    try:
        with open(probe_file, "x") as f:
            f.write("x")
        os.remove(probe_file)
        mount = home_mount()
        if container_kind() and mount and mount[1] in ("tmpfs", "overlay"):
            run.add("iso03.write.home", "ISO-03", PASS, "home trong container là tạm (%s tại %s), không phải home của host" % (mount[1], mount[0]))
        else:
            run.add("iso03.write.home", "ISO-03", FAIL, "ghi được file vào thư mục home, ngoài workspace", [HOME])
    except FileExistsError:
        run.add("iso03.write.home", "ISO-03", UNTESTED, "file thử %s đã tồn tại; xóa nó rồi chạy lại" % tilde(probe_file))
    except OSError:
        run.add("iso03.write.home", "ISO-03", PASS, "không ghi được vào thư mục home ngoài workspace")

    socks = []
    if os.environ.get("SSH_AUTH_SOCK"):
        socks.append(("SSH agent ($SSH_AUTH_SOCK)", os.environ["SSH_AUTH_SOCK"]))
    socks += [("SSH agent", p) for p in glob.glob("/tmp/ssh-*/agent.*") + glob.glob("/private/tmp/com.apple.launchd.*/Listeners")]
    uid = None if IS_WIN else os.getuid()
    socks += [("GPG agent", p) for p in [os.path.join(HOME, ".gnupg", "S.gpg-agent"), "/run/user/%s/gnupg/S.gpg-agent" % uid]]
    socks += [("Docker socket", p) for p in ["/var/run/docker.sock", "/run/docker.sock",
                                             os.path.join(HOME, ".docker", "run", "docker.sock"),
                                             os.path.join(HOME, ".colima", "default", "docker.sock"),
                                             "/run/user/%s/podman/podman.sock" % uid, "/run/user/%s/docker.sock" % uid]]
    reachable = sorted({"%s: %s" % (n, p) for n, p in socks if unix_socket_connectable(p)})
    if IS_WIN:
        for n, pipe in [("SSH agent", r"\\.\pipe\openssh-ssh-agent"), ("Docker", r"\\.\pipe\docker_engine")]:
            try:
                with open(pipe, "rb"):
                    reachable.append("%s: %s" % (n, pipe))
            except OSError:
                pass
    if reachable:
        run.add("iso03.socket.agents", "ISO-03", FAIL, "kết nối được tới socket cấp quyền (SSH/GPG agent, Docker)", reachable)
    else:
        run.add("iso03.socket.agents", "ISO-03", PASS, "không kết nối được tới SSH agent, GPG agent hay Docker socket đã biết")

    if IS_MAC:
        if keychain_item:
            rc = run_quiet(["security", "find-generic-password", "-s", keychain_item])
            run.add("iso03.os_store", "ISO-03", FAIL if rc == 0 else PASS,
                    ("truy vấn được item '%s' trong Keychain" if rc == 0 else "không truy vấn được item '%s' trong Keychain") % keychain_item)
        else:
            run.add("iso03.os_store", "ISO-03", UNTESTED, "chưa thử Keychain; chạy lại với --keychain-item <tên một item có thật>")
    elif IS_WIN:
        rc = run_quiet(["cmdkey", "/list"])
        run.add("iso03.os_store", "ISO-03", REVIEW if rc == 0 else PASS,
                "liệt kê được Windows Credential Manager (cmdkey /list)" if rc == 0 else "không liệt kê được Windows Credential Manager")
    else:
        m = re.search(r"unix:path=([^,;]+)", os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""))
        path = m.group(1) if m else "/run/user/%s/bus" % uid
        if unix_socket_connectable(path):
            run.add("iso03.os_store", "ISO-03", REVIEW, "kết nối được session D-Bus; Secret Service/gnome-keyring có thể truy cập được", [path])
        else:
            run.add("iso03.os_store", "ISO-03", PASS, "không kết nối được session D-Bus")


def probe_iso04(run):
    kind = container_kind()
    if not kind:
        run.add("iso04.container", "ISO-04", NA, "không phát hiện đang chạy trong container (Windows Sandbox và VM cần kiểm tay)")
        return
    run.add("iso04.container", "ISO-04", PASS, "đang chạy trong container (%s)" % kind)
    try:
        with open("/proc/self/status") as f:
            status = dict(l.split(":", 1) for l in f.read().splitlines() if ":" in l)
        cap = int(status.get("CapEff", "0").strip(), 16)
        bnd = int(status.get("CapBnd", "0").strip(), 16)
        if cap & (1 << 21):
            run.add("iso04.cap_sys_admin", "ISO-04", FAIL, "tiến trình có CAP_SYS_ADMIN (container privileged hoặc thêm capability)")
        elif bnd & (1 << 21):
            run.add("iso04.cap_sys_admin", "ISO-04", FAIL, "CAP_SYS_ADMIN nằm trong bounding set: container có thể chạy --privileged; tiến trình nào lên được root sẽ có quyền đó")
        else:
            run.add("iso04.cap_sys_admin", "ISO-04", PASS, "không có CAP_SYS_ADMIN, kể cả trong bounding set")
        nnp = status.get("NoNewPrivs", "").strip() == "1"
        run.add("iso04.no_new_privs", "ISO-04", PASS if nnp else FAIL, "no-new-privileges đang bật" if nnp else "no-new-privileges chưa bật")
        seccomp_off = status.get("Seccomp", "").strip() == "0"
        run.add("iso04.seccomp", "ISO-04", FAIL if seccomp_off else PASS, "seccomp đang tắt" if seccomp_off else "seccomp đang bật")
    except (OSError, ValueError):
        run.add("iso04.cap_sys_admin", "ISO-04", UNTESTED, "không đọc được /proc/self/status")
    if shutil.which("mount"):
        tmp = tempfile.mkdtemp(prefix="asal-mnt-")
        mounted = run_quiet(["mount", "-t", "tmpfs", "tmpfs", tmp]) == 0
        if mounted:
            run_quiet(["umount", tmp])
        os.rmdir(tmp)
        run.add("iso04.mount", "ISO-04", FAIL if mounted else PASS, "mount được tmpfs" if mounted else "không mount được tmpfs")
    else:
        run.add("iso04.mount", "ISO-04", UNTESTED, "không có lệnh mount để thử")
    ok, why = tcp_connect("169.254.169.254", 80, socket.AF_INET, timeout=2)
    run.add("iso04.metadata", "ISO-04", FAIL if ok else PASS,
            "kết nối được metadata endpoint 169.254.169.254" if ok else "không kết nối được metadata endpoint 169.254.169.254 (%s)" % why)


def _proxy_connect(proxy, target):
    """CONNECT to target:443 through proxy. Returns (status line or None, error or None).
    Credentials in the proxy URL are sent so the answer reflects the allowlist; never printed."""
    m = re.match(r"^(?:https?://)?(?:([^@/]*)@)?([^:/]+)(?::(\d+))?", proxy)
    if not m:
        return None, "không hiểu địa chỉ proxy"
    userinfo, host, port = m.group(1), m.group(2), int(m.group(3) or 80)
    auth = ""
    if userinfo:
        token = base64.b64encode(urllib.parse.unquote(userinfo).encode()).decode()
        auth = "Proxy-Authorization: Basic %s\r\n" % token
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n%s\r\n" % (target, target, auth)).encode())
        line = s.recv(64).split(b"\r\n")[0].decode("latin-1", "replace")
        s.close()
        return line, None
    except OSError as e:
        return None, str(e)


def probe_net(run, args):
    def tcp(probe, label, host, family=socket.AF_UNSPEC):
        ok, why = tcp_connect(host, 443, family)
        run.add(probe, "NET-01", FAIL if ok else PASS, "%s: %s" % (label, why))

    def udp(probe, label, server, control="NET-01"):
        ok, why = udp_dns_reply(server)
        run.add(probe, control, FAIL if ok else PASS, "%s: %s" % (label, why))

    tcp("net01.tcp.domain", "TCP thẳng tới domain ngoài allowlist %s:443" % args.probe_host, args.probe_host)
    tcp("net01.tcp.ipv4", "TCP thẳng tới IPv4 trần %s:443" % args.ipv4, args.ipv4, socket.AF_INET)
    if socket.has_ipv6:
        tcp("net01.tcp.ipv6", "TCP thẳng tới IPv6 trần [%s]:443" % args.ipv6, args.ipv6, socket.AF_INET6)
        udp("net01.udp.ipv6", "UDP qua IPv6 (DNS tới [%s]:53)" % args.ipv6, args.ipv6)
    udp("net01.udp.ipv4", "UDP ra ngoài (DNS tới %s:53)" % args.ipv4, args.ipv4)

    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        shown = proxy.split("@")[-1]
        line, err = _proxy_connect(proxy, args.probe_host)
        if err:
            run.add("net01.proxy.allowlist", "NET-01", UNTESTED, "không thử được proxy %s: %s" % (shown, err))
        elif " 407" in line:
            run.add("net01.proxy.allowlist", "NET-01", UNTESTED, "proxy %s đòi xác thực (%s); không kiểm được allowlist" % (shown, line))
        else:
            run.add("net01.proxy.allowlist", "NET-01", FAIL if " 200" in line else PASS,
                    "proxy %s trả lời CONNECT tới %s: %s" % (shown, args.probe_host, line or "không trả lời"))
    else:
        run.add("net01.proxy.allowlist", "NET-01", UNTESTED, "không có HTTPS_PROXY; không thử được allowlist của proxy")

    udp("net02.dns.udp", "DNS UDP thẳng tới %s" % args.dns, args.dns, control="NET-02")
    for probe, port, label in [("net02.dns.tcp", 53, "DNS qua TCP"), ("net02.dns.dot", 853, "DNS-over-TLS")]:
        ok, why = tcp_connect(args.dns, port, socket.AF_INET)
        run.add(probe, "NET-02", FAIL if ok else PASS, "%s tới %s:%d: %s" % (label, args.dns, port, why))
    try:
        socket.getaddrinfo(args.probe_host, 443)
        run.add("net02.resolver", "NET-02", REVIEW, "resolver của hệ thống phân giải được %s; chấp nhận được nếu đó là resolver nội bộ có log" % args.probe_host)
    except socket.gaierror:
        run.add("net02.resolver", "NET-02", PASS, "tiến trình không tự phân giải tên miền (proxy phân giải)")


SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)", re.I)
NOT_SECRET = re.compile(r"(PATH|FILE|DIR|URL|HOST|SOCK|ID$|_NAME$|KEYCHAIN)", re.I)


LOOPBACK = ("localhost", "127.0.0.1", "::1")


def local_proxy_passwords():
    """Passwords in proxy URLs that point at this machine. A sandbox that filters egress through
    a local proxy (Claude Code, srt) gives each session such a password, and copies it to
    variables like CLOUDSDK_PROXY_PASSWORD; it only unlocks that proxy."""
    found = set()
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        try:
            p = urllib.parse.urlsplit(os.environ.get(name, ""))
            if p.hostname in LOOPBACK and p.password:
                found.add(urllib.parse.unquote(p.password))
        except ValueError:
            pass
    return found


def probe_cred01(run, workspace):
    proxy_pw = local_proxy_passwords()
    named = [(n, v) for n, v in os.environ.items()
             if SECRET_NAME.search(n) and not NOT_SECRET.search(n) and len(v) >= 16 and os.sep not in v]
    suspicious = [n for n, v in named if v not in proxy_pw]
    proxy_vars = ["%s: mật khẩu của proxy trên localhost trong HTTPS_PROXY, không tính" % n for n, v in named if v in proxy_pw]
    if os.environ.get("AWS_ACCESS_KEY_ID", "").startswith("AKIA"):
        run.add("cred01.env.static_key", "CRED-01", FAIL, "có credential dài hạn trong biến môi trường", ["AWS_ACCESS_KEY_ID là access key dài hạn (AKIA…)"])
    else:
        run.add("cred01.env.static_key", "CRED-01", PASS, "không thấy access key dài hạn đã biết trong biến môi trường")
    if suspicious:
        run.add("cred01.env.names", "CRED-01", REVIEW, "biến môi trường có tên giống secret (chỉ in tên, không in giá trị)", sorted(suspicious) + sorted(proxy_vars))
    else:
        run.add("cred01.env.names", "CRED-01", PASS, "không thấy biến môi trường có tên giống secret", sorted(proxy_vars))
    dotenv = []
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    base_depth = workspace.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in skip]
        if root.count(os.sep) - base_depth >= 4:
            dirs[:] = []
        for fn in files:
            if (fn == ".env" or fn.startswith(".env.")) and not fn.endswith((".example", ".sample", ".template")):
                dotenv.append(os.path.join(root, fn))
    parent = os.path.dirname(os.path.abspath(workspace))
    while parent and parent != os.path.dirname(parent):
        p = os.path.join(parent, ".env")
        if exists(p) and can_read(p):
            dotenv.append(p + " (thư mục cha của workspace)")
        if os.path.abspath(parent) == os.path.abspath(HOME):
            break
        parent = os.path.dirname(parent)
    if dotenv:
        run.add("cred01.dotenv", "CRED-01", REVIEW, "có file .env trong workspace hoặc thư mục cha; kiểm tra bằng gitleaks", dotenv)
    else:
        run.add("cred01.dotenv", "CRED-01", PASS, "không thấy file .env trong workspace hay thư mục cha")


def detect_context():
    """Hints about where the probe runs. The declared --context is what the report uses."""
    hints = []
    kind = container_kind()
    if kind:
        hints.append("container:%s" % kind)
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    if re.match(r"^https?://[^@/]+@(localhost|127\.0\.0\.1)", proxy):
        hints.append("local-authenticated-proxy")
    if os.environ.get("CLAUDECODE"):
        hints.append("env:CLAUDECODE")
    return hints


def do_probe(run, args):
    workspace = os.path.abspath(args.workspace)
    probe_iso01(run)
    probe_iso03(run, workspace, args.keychain_item, args.host_home)
    probe_iso04(run)
    if not args.no_network:
        probe_net(run, args)
    probe_cred01(run, workspace)


# ----------------------------------------------------------------------------------------
# Report of one run

def pseudonym(value, key):
    if not value:
        return ""
    if key:
        return "hmac:" + hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()[:16]
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


def build_report(run, args, command):
    key = args.pseudonym_key or os.environ.get("ASAL_PSEUDONYM_KEY", "")
    try:
        user = os.getlogin()
    except OSError:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    report = {
        "schema": REPORT_SCHEMA,
        "tool": {"name": "asal", "version": VERSION},
        "run": {"id": str(uuid.uuid4()),
                "time": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "command": command,
                "context": args.context or ("host" if command == "collect" else "unknown"),
                "detected": detect_context() if command == "probe" else []},
        "host": {"id": args.host_id or pseudonym(socket.gethostname(), key),
                 "user": pseudonym(user, key),
                 "pseudonym": "hmac" if key else "sha256",
                 "os": "%s %s" % (platform.system(), platform.release())},
        "use_case": args.use_case or "",
        "results": sorted(run.results, key=lambda r: (r["control"], r["probe"])),
    }
    if command == "collect":
        report["inventory"] = run.inventory
    return report


def print_run(report, out=None):
    out = out or sys.stdout
    by_control = {}
    for r in report["results"]:
        by_control.setdefault(r["control"], []).append(r)
    width = max(len(v) for v in LABEL.values())
    for control in sorted(by_control, key=lambda c: min(SEVERITY[r["status"]] for r in by_control[c])):
        for r in sorted(by_control[control], key=lambda r: SEVERITY[r["status"]]):
            print("[%-*s] %-7s %s%s" % (width, LABEL[r["status"]], control, r["message"],
                                        "  (cấu hình)" if r["kind"] == "config" else ""), file=out)
            for e in r["evidence"]:
                print("%s%s" % (" " * (width + 12), e), file=out)
    counts = [(LABEL[s], sum(1 for r in report["results"] if r["status"] == s)) for s in (FAIL, REVIEW, UNTESTED, PASS, NA)]
    print("\n" + " · ".join("%s: %d" % c for c in counts), file=out)
    print(CAVEAT, file=out)


# ----------------------------------------------------------------------------------------
# report: aggregate runs against the matrix, policy and attestations

def load_json(path, schema=None):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if schema and (not isinstance(data, dict) or data.get("schema") != schema):
        raise ValueError("%s: không phải %s" % (path, schema))
    return data


def find_reports(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "**", "*.json"), recursive=True))
        else:
            files.append(p)
    reports, skipped = [], []
    for f in files:
        try:
            data = load_json(f)
        except (OSError, ValueError) as e:
            skipped.append("%s: %s" % (f, e))
            continue
        if isinstance(data, dict) and data.get("schema") == REPORT_SCHEMA:
            reports.append(data)
        else:
            skipped.append("%s: không phải %s" % (f, REPORT_SCHEMA))
    return reports, skipped


def worst(statuses):
    return min(statuses, key=SEVERITY.get) if statuses else UNTESTED


def evaluate(reports, matrix, policy, attestations, today):
    """Compute per (use case, host) control statuses and achieved levels.

    Rules (guideline Mục 0.5): a level is reached only when every control marked required at
    that level is pass or na. review blocks until a person settles it with a pass attestation:
    the machine saw a sign it cannot judge. A control with no machine result and no valid
    attestation is untested, which also blocks. A waived required control blocks the level
    even with risk_accepted_by; the report shows who accepted the risk. Machine evidence of
    fail is never overridden by an attestation.
    """
    levels = matrix["levels"]
    controls = matrix["controls"]
    use_cases = {u["id"]: u for u in (policy or {}).get("use_cases", [])}
    approved = set(a["identity"] if isinstance(a, dict) else a for a in (policy or {}).get("approved_mcp_servers", []))
    has_approved = "approved_mcp_servers" in (policy or {})

    valid_attest, expired_attest = {}, []
    for a in (attestations or {}).get("items", []):
        if a.get("expires") and a["expires"] < today:
            expired_attest.append(a)
            continue
        valid_attest.setdefault((a.get("use_case", ""), a["control"]), a)

    groups, ignored = {}, []
    for rep in reports:
        uc = rep.get("use_case") or ""
        allowed = use_cases.get(uc, {}).get("contexts")
        ctx = rep["run"].get("context", "")
        if rep["run"].get("command") == "probe" and allowed and ctx not in allowed:
            ignored.append((rep["host"].get("id"), uc, ctx))
            continue
        g = groups.setdefault((uc, rep["host"].get("id") or rep["run"]["id"]),
                              {"results": [], "contexts": set(), "inventory": [], "os": rep["host"].get("os", "")})
        g["results"] += rep["results"]
        g["contexts"].add("%s:%s" % (rep["run"].get("command"), ctx))
        g["inventory"] += rep.get("inventory", [])

    evaluated = []
    for (uc, host), g in sorted(groups.items()):
        per = {}
        for r in g["results"]:
            per.setdefault(r["control"], []).append(r)
        status, source = {}, {}
        for cid in controls:
            machine = [r["status"] for r in per.get(cid, [])]
            relevant = [s for s in machine if s != NA]
            if relevant:
                st = worst([s for s in relevant if s != UNTESTED] or [UNTESTED])
            elif machine:
                st = NA
            else:
                st = UNTESTED
            src = "máy" if machine else ""
            a = valid_attest.get((uc, cid)) or valid_attest.get(("", cid))
            if a and st in (UNTESTED, REVIEW, NA):
                if a.get("status") == "pass":
                    st, src = PASS, "xác nhận tay"
                elif a.get("status") == "waived":
                    st, src = "waived", "miễn trừ"
                elif a.get("status") == "na":
                    st, src = NA, "xác nhận tay"
            status[cid], source[cid] = st, src
        # ISO-02 is skipped when the whole client already runs in a container or VM (card ISO-02).
        if any(r["probe"] == "iso04.container" and r["status"] == PASS for r in g["results"]) and status["ISO-02"] in (FAIL, UNTESTED):
            status["ISO-02"], source["ISO-02"] = NA, "chạy trong container"
        # SC-02 needs an approved list. Machine results only cover project-level configuration,
        # so without the policy's list (or an attestation) SC-02 is not proven.
        if not has_approved and source.get("SC-02") == "máy" and status["SC-02"] in (NA, PASS):
            status["SC-02"], source["SC-02"] = UNTESTED, "cần danh sách server được duyệt trong policy"
        unapproved = []
        if has_approved:
            for item in g["inventory"]:
                if item["identity"] not in approved:
                    unapproved.append(item)
            if unapproved:
                status["SC-02"], source["SC-02"] = FAIL, "policy"
            elif g["inventory"] and status.get("SC-02") in (REVIEW, UNTESTED, NA):
                status["SC-02"], source["SC-02"] = PASS, "policy"

        achieved = {}
        for lvl in levels:
            req = [c for c in controls if controls[c]["levels"][lvl] == "required"]
            blocking = [c for c in req if status[c] not in (PASS, NA)]
            achieved[lvl] = not blocking
        claimed = use_cases.get(uc, {}).get("level")
        evaluated.append({"use_case": uc, "host": host, "os": g["os"], "contexts": sorted(g["contexts"]),
                          "status": status, "source": source, "achieved": achieved, "claimed": claimed,
                          "unapproved": unapproved, "inventory": g["inventory"],
                          "results": g["results"]})
    return evaluated, ignored, expired_attest, valid_attest


NEXT_LEVELS = {"ASAL-0": ["ASAL-1"], "ASAL-1": ["ASAL-2"], "ASAL-2": ["ASAL-3a", "ASAL-3b"]}


def highest(achieved, levels):
    best = "chưa đạt ASAL-0"
    for lvl in ("ASAL-0", "ASAL-1", "ASAL-2"):
        if achieved.get(lvl):
            best = lvl
        else:
            break
    extra = [l for l in ("ASAL-3a", "ASAL-3b") if achieved.get(l) and best == "ASAL-2"]
    return best + ("".join(", " + l for l in extra) if extra else "")


def render_markdown(evaluated, matrix, policy, ignored, expired, valid_attest, skipped, n_reports, today):
    controls = matrix["controls"]
    out = io.StringIO()
    w = lambda s="": out.write(s + "\n")
    w("# Báo cáo tư thế agent")
    w()
    w("Ngày: %s · Số file kết quả: %d · Số máy: %d · Ma trận: guideline %s · asal %s" % (
        today, n_reports, len({e["host"] for e in evaluated}), matrix.get("guideline_version", "?"), VERSION))
    w()
    for uc in sorted({e["use_case"] for e in evaluated}):
        rows = [e for e in evaluated if e["use_case"] == uc]
        claimed = rows[0]["claimed"]
        w("## Use case: %s" % (uc or "(chưa khai báo)"))
        w()
        if claimed:
            ok = sum(1 for e in rows if e["achieved"].get(claimed))
            w("Cam kết **%s**: %d trên %d máy đạt." % (claimed, ok, len(rows)))
        else:
            w("Policy không khai báo cấp cho use case này; báo cáo chỉ ghi cấp đạt được.")
        w()
        w("| Máy | Hệ điều hành | Nguồn kết quả | Cấp đạt được | Chưa đạt | Chưa có bằng chứng | Cần xem |")
        w("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for e in rows:
            lvl = claimed or "ASAL-0"
            req = [c for c in controls if controls[c]["levels"].get(lvl) == "required"]
            fails = [c for c in req if e["status"][c] in (FAIL, "waived")]
            untested = [c for c in req if e["status"][c] == UNTESTED]
            reviews = sorted({c for c, s in e["status"].items() if s == REVIEW})
            w("| `%s` | %s | %s | %s | %s | %s | %s |" % (
                e["host"], e["os"], ", ".join(e["contexts"]), highest(e["achieved"], matrix["levels"]),
                ", ".join(fails) or "—", ", ".join(untested) or "—", ", ".join(reviews) or "—"))
        w()
        lvl = claimed or "ASAL-0"
        req = [c for c in controls if controls[c]["levels"].get(lvl) == "required"]
        w("### Control bắt buộc ở %s" % lvl)
        w()
        w("| Control | Đạt | Chưa đạt | Chưa có bằng chứng | Cần xem | Không áp dụng |")
        w("| :--- | :---: | :---: | :---: | :---: | :---: |")
        for c in sorted(req, key=lambda c: (-sum(1 for e in rows if e["status"][c] in (FAIL, "waived")), c)):
            cnt = lambda st: sum(1 for e in rows if e["status"][c] in st)
            w("| %s %s | %d | %d | %d | %d | %d |" % (c, controls[c]["name"], cnt((PASS,)), cnt((FAIL, "waived")),
                                                     cnt((UNTESTED,)), cnt((REVIEW,)), cnt((NA,))))
        w()
        w("Control *chưa có bằng chứng* là control không có phép thử tự động và chưa có xác nhận tay hợp lệ. "
          "Control *cần xem* là control máy thấy dấu hiệu nhưng không tự kết luận được. Cả hai đều chặn việc đạt cấp, "
          "như Mục 0.5 yêu cầu, cho tới khi có xác nhận tay hợp lệ.")
        w()
        for nxt in NEXT_LEVELS.get(lvl, []):
            extra = [c for c in controls if controls[c]["levels"].get(nxt) == "required" and c not in req]
            ok = sum(1 for e in rows if e["achieved"].get(nxt))
            w("### Cấp kế tiếp: %s" % nxt)
            w()
            w("Control bắt buộc thêm ở %s so với %s: %d trên %d máy đạt %s. Use case chưa cam kết cấp này; "
              "bảng cho biết còn thiếu gì." % (nxt, lvl, ok, len(rows), nxt))
            w()
            w("| Control | Đạt | Chưa đạt | Chưa có bằng chứng | Cần xem | Không áp dụng |")
            w("| :--- | :---: | :---: | :---: | :---: | :---: |")
            for c in sorted(extra, key=lambda c: (-sum(1 for e in rows if e["status"][c] in (FAIL, "waived")), c)):
                cnt = lambda st: sum(1 for e in rows if e["status"][c] in st)
                w("| %s %s | %d | %d | %d | %d | %d |" % (c, controls[c]["name"], cnt((PASS,)), cnt((FAIL, "waived")),
                                                         cnt((UNTESTED,)), cnt((REVIEW,)), cnt((NA,))))
            w()
        fails = [(e["host"], r) for e in rows for r in e["results"] if r["status"] == FAIL]
        unapproved = [(e["host"], i) for e in rows for i in e["unapproved"]]
        if fails or unapproved:
            w("### Chi tiết chưa đạt")
            w()
            for host, r in fails:
                w("- `%s` · %s · `%s`: %s%s" % (host, r["control"], r["probe"], r["message"],
                                                  (" (%s)" % "; ".join(r["evidence"][:4])) if r["evidence"] else ""))
            for host, i in unapproved:
                w("- `%s` · SC-02 · policy: MCP server `%s` (%s, trong %s) không có trong danh sách được duyệt" % (host, i["identity"], i["name"], i["config"]))
            w()
    inv = {}
    for e in evaluated:
        for item in e["inventory"]:
            inv.setdefault(item["identity"], {"hosts": set(), "item": item})["hosts"].add(e["host"])
    if inv:
        approved = set(a["identity"] if isinstance(a, dict) else a for a in (policy or {}).get("approved_mcp_servers", []))
        has_approved = "approved_mcp_servers" in (policy or {})
        w("## Danh mục MCP server (SC-01)")
        w()
        w("| Danh tính | Tên trong cấu hình | Số máy | Được duyệt |")
        w("| :--- | :--- | :---: | :--- |")
        for ident in sorted(inv):
            d = inv[ident]
            ok = ("có" if ident in approved else "**không**") if has_approved else "policy chưa có danh sách"
            w("| `%s` | %s | %d | %s |" % (ident, d["item"]["name"], len(d["hosts"]), ok))
        w()
    if valid_attest or expired:
        w("## Xác nhận tay")
        w()
        w("| Control | Use case | Trạng thái | Người xác nhận | Ngày | Hết hạn | Chấp nhận rủi ro |")
        w("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for a in list(valid_attest.values()) + expired:
            state = a.get("status", "") + (" (**đã hết hạn**, không tính)" if a in expired else "")
            w("| %s | %s | %s | %s | %s | %s | %s |" % (a["control"], a.get("use_case", "") or "mọi use case", state,
                                                     a.get("by", ""), a.get("date", ""), a.get("expires", ""), a.get("risk_accepted_by", "")))
        w()
        w("Miễn trừ một control *bắt buộc* nghĩa là use case không đạt cấp đó, kể cả khi đã có người chấp nhận rủi ro (Mục 0.5).")
        w()
    if ignored or skipped:
        w("## Không được tính")
        w()
        for host, uc, ctx in ignored:
            w("- Kết quả probe của `%s` (use case %s) chạy ở context `%s`, không nằm trong danh sách context của policy." % (host, uc or "?", ctx))
        for s in skipped:
            w("- %s" % s)
        w()
    w("---")
    w()
    w(CAVEAT)
    return out.getvalue()


def render_csv(evaluated):
    out = io.StringIO()
    wr = csv.writer(out)
    wr.writerow(["use_case", "host", "control", "status", "source"])
    for e in evaluated:
        for c in sorted(e["status"]):
            wr.writerow([e["use_case"], e["host"], c, e["status"][c], e["source"].get(c, "")])
    return out.getvalue()


def do_report(args):
    matrix = load_json(args.matrix, MATRIX_SCHEMA)
    policy = load_json(args.policy, POLICY_SCHEMA) if args.policy else None
    attest = load_json(args.attest, ATTEST_SCHEMA) if args.attest else None
    today = args.date or datetime.date.today().isoformat()
    reports, skipped = find_reports(args.paths)
    if not reports:
        sys.exit("asal report: không tìm thấy file %s nào" % REPORT_SCHEMA)
    evaluated, ignored, expired, valid = evaluate(reports, matrix, policy, attest, today)
    text = render_csv(evaluated) if args.format == "csv" else \
        render_markdown(evaluated, matrix, policy, ignored, expired, valid, skipped, len(reports), today)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print("đã ghi %s" % args.output)
    else:
        sys.stdout.write(text)


# ----------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="asal", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command")

    def common(p):
        p.add_argument("--workspace", default=os.getcwd(), help="thư mục dự án (mặc định: thư mục hiện tại)")
        p.add_argument("--use-case", help="mã use case trong policy, ví dụ coding-agent-internal")
        p.add_argument("--context", help="nơi chạy: host, devcontainer, container, srt, claude-code-bash, ci, windows-sandbox…")
        p.add_argument("--pseudonym-key", help="khóa HMAC để băm hostname và tên người dùng (hoặc biến ASAL_PSEUDONYM_KEY)")
        p.add_argument("--host-id", help="đặt mã máy thay cho giá trị băm từ hostname")
        p.add_argument("--json", action="store_true", help="in báo cáo JSON ra stdout")
        p.add_argument("-o", "--output", help="ghi báo cáo JSON vào file này")

    pc = sub.add_parser("collect", help="đọc cấu hình MCP và settings của client (chạy ngoài sandbox)")
    common(pc)
    pp = sub.add_parser("probe", help="thử những gì tiến trình của agent làm được (chạy trong môi trường của agent)")
    common(pp)
    pp.add_argument("--probe-host", default="example.org", help="một domain KHÔNG nằm trong allowlist (mặc định example.org)")
    pp.add_argument("--ipv4", default="1.1.1.1", help="IPv4 công cộng để thử kết nối thẳng (mặc định 1.1.1.1)")
    pp.add_argument("--ipv6", default="2606:4700:4700::1111", help="IPv6 công cộng để thử (mặc định 2606:4700:4700::1111)")
    pp.add_argument("--dns", default="8.8.8.8", help="DNS resolver công cộng để thử NET-02 (mặc định 8.8.8.8)")
    pp.add_argument("--keychain-item", help="macOS: tên một item có thật trong Keychain để thử ISO-03")
    pp.add_argument("--host-home", action="append", default=[], help="thêm thư mục home cần thử (khi agent chạy dưới user khác)")
    pp.add_argument("--no-network", action="store_true", help="bỏ qua phép thử mạng")
    pr = sub.add_parser("report", help="gom kết quả nhiều máy, đối chiếu với policy, xuất báo cáo")
    pr.add_argument("paths", nargs="+", help="file hoặc thư mục chứa kết quả JSON của collect và probe")
    pr.add_argument("--policy", help="file policy (%s)" % POLICY_SCHEMA)
    pr.add_argument("--attest", help="file xác nhận tay (%s)" % ATTEST_SCHEMA)
    pr.add_argument("--matrix", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "asal_matrix.json"),
                    help="ma trận control (mặc định: asal_matrix.json cạnh script)")
    pr.add_argument("--format", choices=["md", "csv"], default="md")
    pr.add_argument("--date", help="ngày dùng để xét hạn xác nhận tay, YYYY-MM-DD (mặc định: hôm nay)")
    pr.add_argument("-o", "--output", help="ghi báo cáo vào file này")
    sub.add_parser("version", help="in phiên bản")

    args = ap.parse_args(argv)
    if args.command == "version":
        print("asal", VERSION)
        return 0
    if args.command == "report":
        do_report(args)
        return 0
    if args.command not in ("collect", "probe"):
        ap.print_help()
        return 2

    run = Run()
    (do_collect if args.command == "collect" else do_probe)(run, args)
    report = build_report(run, args, args.command)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
            f.write("\n")
    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        print_run(report)
        if args.output:
            print("đã ghi %s" % args.output)
    return 1 if any(r["status"] == FAIL for r in report["results"]) else 0


if __name__ == "__main__":
    sys.exit(main())
