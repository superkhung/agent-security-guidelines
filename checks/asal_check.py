#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Chạy tự động một phần phép kiểm chứng của ASAL-0 và phần máy trạm của ASAL-1.

Hai nhóm phép thử:

  config   Đọc cấu hình MCP và cấu hình client trên máy (SC-01, SC-02, SC-03, NET-04,
           ACT-03). Chạy như người dùng bình thường, ngoài sandbox.
  probe    Thử những gì tiến trình của agent làm được (ISO-01, ISO-03, ISO-04, NET-01,
           NET-02, CRED-01). Phải chạy BÊN TRONG môi trường của agent: yêu cầu agent
           chạy lệnh này, hoặc chạy qua srt, trong devcontainer, trong Windows Sandbox.

Cách dùng:
  python3 checks/asal_check.py                 # cả hai nhóm
  python3 checks/asal_check.py config
  python3 checks/asal_check.py probe --workspace .
  python3 checks/asal_check.py probe --json > ket-qua.json

Script không in nội dung secret nào. Phép thử đọc file chỉ đọc một byte rồi bỏ đi;
phép thử socket chỉ mở kết nối rồi đóng, không gửi yêu cầu. Phép thử mạng kết nối
tới các địa chỉ công cộng ghi trong --help; đổi bằng tham số nếu cần.

Kết quả chỉ nói về những đường đi mà script đã thử (guideline, Mục 0.5). Đạt ở đây
không chứng minh hệ thống an toàn; chưa đạt thì chắc chắn có đường hở.
"""
import argparse, glob, json, os, platform, re, shutil, socket, subprocess, sys, tempfile

PASS, FAIL, WARN, NA, UNKNOWN = "Đạt", "Chưa đạt", "Cần xem", "Không áp dụng", "Chưa kiểm được"
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
HOME = os.path.expanduser("~")

results = []


def record(control, status, message, detail=None):
    results.append({"control": control, "status": status, "message": message, "detail": detail or []})


# ----------------------------------------------------------------------------------------
# Helpers

def can_read(path):
    """True if the process can read the path. Reads at most one byte; never prints content."""
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            with open(path, "rb") as f:
                f.read(1)
        return True
    except (PermissionError, OSError):
        return False


def exists(path):
    try:
        return os.path.lexists(path)
    except OSError:
        return False


def path_state(path):
    """'absent', 'blocked' or 'readable'. A sandbox that hides a path (EPERM/EACCES on lstat)
    counts as blocked, not absent."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return "absent"
    except (PermissionError, OSError):
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
    """Direct TCP connect, bypassing any proxy settings. Returns (connected, reason)."""
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
    """Send one DNS query for example.org over UDP; True if any reply comes back."""
    query = (b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03org\x00\x00\x01\x00\x01")
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (server, 53))
        data, _ = s.recvfrom(512)
        return data[:2] == b"\x13\x37", "có trả lời"
    except OSError as e:
        return False, e.strerror or type(e).__name__
    finally:
        s.close()


def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return p.returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


# ----------------------------------------------------------------------------------------
# config: MCP configuration and client settings

def mcp_config_files(workspace):
    """(path, scope, loader) for every known MCP configuration location. guideline SC-01."""
    appdata = os.environ.get("APPDATA", "")
    user = [
        (os.path.join(HOME, ".claude.json"), "user", "claude_json"),
        (os.path.join(HOME, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "user", "mcpServers"),
        (os.path.join(HOME, ".config", "Claude", "claude_desktop_config.json"), "user", "mcpServers"),
        (os.path.join(appdata, "Claude", "claude_desktop_config.json"), "user", "mcpServers"),
        (os.path.join(HOME, ".cursor", "mcp.json"), "user", "mcpServers"),
        (os.path.join(HOME, ".codex", "config.toml"), "user", "codex_toml"),
    ]
    project = [
        (os.path.join(workspace, ".mcp.json"), "project", "mcpServers"),
        (os.path.join(workspace, ".cursor", "mcp.json"), "project", "mcpServers"),
        (os.path.join(workspace, ".vscode", "mcp.json"), "project", "servers"),
    ]
    return [(p, s, l) for p, s, l in user + project if p and os.path.isfile(p)]


def parse_codex_toml(text):
    """Minimal reader for [mcp_servers.NAME] tables in Codex config.toml (command, args, url)."""
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
        m = re.match(r"(command|url)\s*=\s*\"(.*)\"", line)
        if m:
            current[m.group(1)] = m.group(2)
        m = re.match(r"args\s*=\s*\[(.*)\]", line)
        if m:
            current["args"] = re.findall(r"\"((?:[^\"\\]|\\.)*)\"", m.group(1))
    return servers


def load_servers(path, loader, workspace):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if loader == "codex_toml":
        return parse_codex_toml(text)
    data = json.loads(text)
    if loader == "claude_json":
        servers = dict(data.get("mcpServers") or {})
        # Servers added per project with "local" scope live under projects.<path>.mcpServers.
        for proj, cfg in (data.get("projects") or {}).items():
            for name, srv in ((cfg or {}).get("mcpServers") or {}).items():
                servers["%s (local, %s)" % (name, proj)] = srv
        return servers
    return dict(data.get(loader) or {})


VERSION_RE = re.compile(r"^(@[^/]+/)?[^@]+@(\d[^@]*)$")


def pin_status(server):
    """Classify how a server is started. Returns (status, reason). guideline SC-03."""
    command = os.path.basename(str(server.get("command", "")))
    args = [str(a) for a in server.get("args", []) or []]
    url = server.get("url")
    if url:
        return None, None
    if command in ("npx", "npx.cmd", "bunx", "pnpx") or (command in ("pnpm", "npm") and args[:1] in (["dlx"], ["exec"])):
        pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx", "exec")]
        if not pkgs:
            return FAIL, "%s không rõ package" % command
        pkg = pkgs[0]
        if pkg.endswith("@latest"):
            return FAIL, "%s %s dùng @latest" % (command, pkg)
        if not VERSION_RE.match(pkg):
            return FAIL, "%s %s không kèm phiên bản" % (command, pkg)
        return PASS, "%s %s ghim phiên bản (chưa ghim dependency, xem SC-03)" % (command, pkg)
    if command in ("uvx", "uvx.exe") or (command == "uv" and args[:2] == ["tool", "run"]):
        rest = args[2:] if command == "uv" else args
        if "--from" in rest:
            spec = rest[rest.index("--from") + 1] if rest.index("--from") + 1 < len(rest) else ""
        else:
            spec = next((a for a in rest if not a.startswith("-")), "")
        if re.search(r"(==|@)\d", spec):
            return PASS, "uvx %s ghim phiên bản" % spec
        return FAIL, "uvx %s không kèm phiên bản" % (spec or "?")
    if command in ("docker", "podman") and "run" in args:
        after = args[args.index("run") + 1:]
        image = next((a for a in after if not a.startswith("-") and "=" not in a), "")
        if "@sha256:" in image:
            return PASS, "%s ghim theo digest" % image
        if ":" not in image.split("/")[-1] or image.endswith(":latest"):
            return FAIL, "image %s không ghim tag hay digest" % (image or "?")
        return WARN, "image %s ghim tag, chưa ghim digest" % image
    return PASS, "chạy trực tiếp %s" % (server.get("command") or "?")


def check_config(workspace):
    files = mcp_config_files(workspace)
    inventory, pins, remotes, project = [], [], [], []
    for path, scope, loader in files:
        try:
            servers = load_servers(path, loader, workspace)
        except (OSError, ValueError) as e:
            record("SC-01", WARN, "không đọc được %s" % path, [str(e)])
            continue
        for name, srv in servers.items():
            srv = srv or {}
            where = "%s: %s" % (path, name)
            inventory.append(where)
            if scope == "project":
                project.append(where)
            st, why = pin_status(srv)
            if st:
                pins.append((st, "%s → %s" % (where, why)))
            url = srv.get("url")
            if url:
                transport = str(srv.get("type") or srv.get("transport") or "")
                remotes.append((where, url, transport))

    record("SC-01", PASS if inventory else NA,
           "tìm thấy %d MCP server trong %d file cấu hình" % (len(inventory), len(files)) if inventory
           else "không thấy file cấu hình MCP ở các vị trí mặc định", inventory)

    if project:
        record("SC-02", WARN, "có cấu hình MCP cấp project: coi là không tin cậy, thay đổi phải được duyệt", project)
    else:
        record("SC-02", NA, "không có cấu hình MCP cấp project trong workspace")

    if pins:
        worst = FAIL if any(s == FAIL for s, _ in pins) else WARN if any(s == WARN for s, _ in pins) else PASS
        record("SC-03", worst, "cách khởi động MCP server", ["[%s] %s" % (s, d) for s, d in pins])
    else:
        record("SC-03", NA, "không có MCP server local")

    if remotes:
        bad = []
        for where, url, transport in remotes:
            host = re.sub(r"^[a-z]+://([^/:]+).*$", r"\1", url)
            loopback = host in ("localhost", "127.0.0.1", "::1", "[::1]")
            if url.startswith("http://") and not loopback:
                bad.append("[%s] %s: %s không dùng HTTPS" % (FAIL, where, url))
            elif transport == "sse":
                bad.append("[%s] %s: transport HTTP+SSE đã deprecated" % (WARN, where))
        st = FAIL if any(b.startswith("[" + FAIL) for b in bad) else WARN if bad else PASS
        record("NET-04", st, "%d remote MCP server; phần xác thực OAuth cần kiểm tay" % len(remotes),
               bad or ["%s: %s" % (w, u) for w, u, _ in remotes])
    else:
        record("NET-04", NA, "không có remote MCP server")

    # ACT-03: Claude Code "bypassPermissions" outside a container disables every approval prompt.
    bypass = []
    for path in [os.path.join(HOME, ".claude", "settings.json"),
                 os.path.join(workspace, ".claude", "settings.json"),
                 os.path.join(workspace, ".claude", "settings.local.json")]:
        try:
            with open(path, encoding="utf-8") as f:
                mode = ((json.load(f).get("permissions") or {}).get("defaultMode"))
            if mode == "bypassPermissions":
                bypass.append(path)
        except (OSError, ValueError, AttributeError):
            pass
    if bypass:
        record("ACT-03", FAIL, "Claude Code đặt defaultMode = bypassPermissions (bỏ mọi phê duyệt); chỉ chấp nhận bên trong container (ISO-04)", bypass)
    else:
        record("ACT-03", UNKNOWN, "không thấy chế độ bỏ phê duyệt trong settings của Claude Code; client khác cần kiểm tay")


# ----------------------------------------------------------------------------------------
# probe: what the agent's process can do

SENSITIVE = [".ssh", ".aws", ".config/gcloud", ".azure", ".kube", ".docker/config.json", ".gnupg",
             ".netrc", ".git-credentials", ".bash_history", ".zsh_history",
             ".config/gh/hosts.yml", ".npmrc", ".pypirc"]
BROWSER = ["Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
           ".config/google-chrome", ".mozilla/firefox", "AppData/Local/Google/Chrome/User Data"]


def probe_iso01():
    if IS_WIN:
        try:
            import ctypes
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            record("ISO-01", UNKNOWN, "không xác định được quyền admin trên Windows")
            return
        record("ISO-01", FAIL if admin else PASS,
               "tiến trình chạy với quyền Administrator" if admin else "không chạy với quyền Administrator")
        return
    if os.geteuid() == 0:
        in_container = container_kind() is not None
        record("ISO-01", WARN if in_container else FAIL,
               "tiến trình chạy bằng root" + (" bên trong container; nên chạy rootless (ISO-04)" if in_container else ""))
        return
    detail = ["uid=%d" % os.geteuid()]
    if shutil.which("sudo") and run(["sudo", "-n", "true"]) == 0:
        record("ISO-01", FAIL, "tiến trình dùng được sudo không cần mật khẩu", detail)
        return
    record("ISO-01", PASS, "không chạy bằng root, không có sudo không mật khẩu", detail)


def probe_iso03(workspace, keychain_item, extra_homes):
    homes = [HOME] + list(extra_homes)
    readable, blocked = [], []
    for home in homes:
        for rel in SENSITIVE + BROWSER:
            p = os.path.join(home, *rel.split("/"))
            state = path_state(p)
            if state != "absent":
                (readable if state == "readable" else blocked).append(p)
    if readable:
        record("ISO-03", FAIL, "đọc được %d vị trí credential ngoài workspace" % len(readable), readable)
    elif blocked:
        record("ISO-03", PASS, "không đọc được %d vị trí credential (bị chặn hoặc bị ẩn)" % len(blocked), blocked)
    else:
        record("ISO-03", UNKNOWN, "không thấy vị trí credential nào để thử (có thể sandbox ẩn cả sự tồn tại, hoặc máy không có)")

    # Symlink from the workspace to ~/.ssh
    target = next((os.path.join(h, ".ssh") for h in homes if path_state(os.path.join(h, ".ssh")) != "absent"), None)
    if target and not IS_WIN:
        tmp = None
        try:
            tmp = tempfile.mkdtemp(prefix=".asal-check-", dir=workspace)
            link = os.path.join(tmp, "link")
            os.symlink(target, link)
            ok = can_read(link)
            record("ISO-03", FAIL if ok else PASS,
                   ("đọc được %s qua symlink trong workspace" if ok else "không đọc được %s qua symlink trong workspace") % target)
        except OSError as e:
            record("ISO-03", UNKNOWN, "không tạo được symlink thử trong workspace", [str(e)])
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    # Writing outside the workspace
    probe_file = os.path.join(HOME, ".asal-check-write-test")
    try:
        with open(probe_file, "x") as f:
            f.write("x")
        os.remove(probe_file)
        mount = home_mount()
        if container_kind() and mount and mount[1] in ("tmpfs", "overlay"):
            record("ISO-03", PASS, "home trong container là tạm (%s tại %s), không phải home của host" % (mount[1], mount[0]))
        else:
            record("ISO-03", FAIL, "ghi được file vào thư mục home, ngoài workspace", [HOME])
    except FileExistsError:
        record("ISO-03", UNKNOWN, "file thử %s đã tồn tại; xóa nó rồi chạy lại" % probe_file)
    except OSError:
        record("ISO-03", PASS, "không ghi được vào thư mục home ngoài workspace")

    # Agent sockets
    socks = []
    if os.environ.get("SSH_AUTH_SOCK"):
        socks.append(("SSH agent ($SSH_AUTH_SOCK)", os.environ["SSH_AUTH_SOCK"]))
    socks += [("SSH agent", p) for p in glob.glob("/tmp/ssh-*/agent.*") + glob.glob("/private/tmp/com.apple.launchd.*/Listeners")]
    uid = None if IS_WIN else os.getuid()
    socks += [("GPG agent", p) for p in [os.path.join(HOME, ".gnupg", "S.gpg-agent"),
                                         "/run/user/%s/gnupg/S.gpg-agent" % uid]]
    socks += [("Docker socket", p) for p in ["/var/run/docker.sock", "/run/docker.sock",
                                             os.path.join(HOME, ".docker", "run", "docker.sock"),
                                             os.path.join(HOME, ".colima", "default", "docker.sock"),
                                             "/run/user/%s/podman/podman.sock" % uid,
                                             "/run/user/%s/docker.sock" % uid]]
    reachable = sorted({"%s: %s" % (n, p) for n, p in socks if unix_socket_connectable(p)})
    if IS_WIN:
        for n, pipe in [("SSH agent", r"\\.\pipe\openssh-ssh-agent"), ("Docker", r"\\.\pipe\docker_engine")]:
            try:
                with open(pipe, "rb"):
                    reachable.append("%s: %s" % (n, pipe))
            except OSError:
                pass
    if reachable:
        record("ISO-03", FAIL, "kết nối được tới socket cấp quyền (SSH/GPG agent, Docker)", reachable)
    else:
        record("ISO-03", PASS, "không kết nối được tới SSH agent, GPG agent hay Docker socket đã biết")

    # OS credential stores
    if IS_MAC:
        if keychain_item:
            rc = run(["security", "find-generic-password", "-s", keychain_item])
            record("ISO-03", FAIL if rc == 0 else PASS,
                   ("truy vấn được item '%s' trong Keychain" if rc == 0 else "không truy vấn được item '%s' trong Keychain") % keychain_item)
        else:
            record("ISO-03", UNKNOWN, "chưa thử Keychain; chạy lại với --keychain-item <tên một item có thật>")
    elif IS_WIN:
        rc = run(["cmdkey", "/list"])
        record("ISO-03", WARN if rc == 0 else PASS,
               "liệt kê được Windows Credential Manager (cmdkey /list)" if rc == 0 else "không liệt kê được Windows Credential Manager")
    else:
        bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
        m = re.search(r"unix:path=([^,;]+)", bus)
        path = m.group(1) if m else "/run/user/%s/bus" % uid
        if unix_socket_connectable(path):
            record("ISO-03", WARN, "kết nối được session D-Bus; Secret Service/gnome-keyring có thể truy cập được", [path])
        else:
            record("ISO-03", PASS, "không kết nối được session D-Bus")


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


def container_kind():
    if exists("/.dockerenv"):
        return "docker"
    if exists("/run/.containerenv"):
        return "podman"
    try:
        with open("/proc/1/cgroup") as f:
            text = f.read()
        if re.search(r"docker|containerd|kubepods|libpod", text):
            return "container"
    except OSError:
        pass
    return None


def probe_iso04():
    kind = container_kind()
    if not kind:
        record("ISO-04", NA, "không phát hiện đang chạy trong container (Windows Sandbox và VM cần kiểm tay)")
        return
    detail, bad = ["loại: %s" % kind], False
    try:
        with open("/proc/self/status") as f:
            status = dict(l.split(":", 1) for l in f.read().splitlines() if ":" in l)
        cap = int(status.get("CapEff", "0").strip(), 16)
        bnd = int(status.get("CapBnd", "0").strip(), 16)
        if cap & (1 << 21):
            bad = True
            detail.append("[%s] có CAP_SYS_ADMIN (container privileged hoặc thêm capability)" % FAIL)
        elif bnd & (1 << 21):
            bad = True
            detail.append("[%s] CAP_SYS_ADMIN nằm trong bounding set: container có thể chạy --privileged; "
                          "tiến trình nào lên được root sẽ có quyền đó" % FAIL)
        nnp = status.get("NoNewPrivs", "").strip()
        if nnp != "1":
            bad = True
            detail.append("[%s] no-new-privileges chưa bật" % FAIL)
        if status.get("Seccomp", "").strip() == "0":
            bad = True
            detail.append("[%s] seccomp đang tắt" % FAIL)
    except (OSError, ValueError):
        detail.append("không đọc được /proc/self/status")
    if shutil.which("mount"):
        tmp = tempfile.mkdtemp(prefix="asal-mnt-")
        if run(["mount", "-t", "tmpfs", "tmpfs", tmp]) == 0:
            bad = True
            detail.append("[%s] mount được tmpfs" % FAIL)
            run(["umount", tmp])
        os.rmdir(tmp)
    ok, why = tcp_connect("169.254.169.254", 80, socket.AF_INET, timeout=2)
    if ok:
        bad = True
        detail.append("[%s] kết nối được metadata endpoint 169.254.169.254" % FAIL)
    record("ISO-04", FAIL if bad else PASS, "cấu hình container", detail)


def probe_net(args):
    detail, bad = [], False

    def check(label, ok, why):
        nonlocal bad
        if ok:
            bad = True
        detail.append("[%s] %s: %s" % (FAIL if ok else PASS, label, why))

    check("TCP thẳng tới domain ngoài allowlist %s:443" % args.probe_host, *tcp_connect(args.probe_host, 443))
    check("TCP thẳng tới IPv4 trần %s:443" % args.ipv4, *tcp_connect(args.ipv4, 443, socket.AF_INET))
    if socket.has_ipv6:
        check("TCP thẳng tới IPv6 trần [%s]:443" % args.ipv6, *tcp_connect(args.ipv6, 443, socket.AF_INET6))
    check("UDP ra ngoài (DNS tới %s:53)" % args.ipv4, *udp_dns_reply(args.ipv4))
    if socket.has_ipv6:
        check("UDP qua IPv6 (DNS tới [%s]:53)" % args.ipv6, *udp_dns_reply(args.ipv6))

    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        m = re.match(r"^(?:https?://)?(?:[^@/]*@)?([^:/]+)(?::(\d+))?", proxy)
        host, port = (m.group(1), int(m.group(2) or 80)) if m else (None, None)
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (args.probe_host, args.probe_host)).encode())
            line = s.recv(64).split(b"\r\n")[0].decode("latin-1", "replace")
            s.close()
            allowed = " 200" in line
            check("proxy %s cho CONNECT tới %s" % (proxy.split("@")[-1], args.probe_host), allowed, line or "không trả lời")
        except OSError as e:
            detail.append("[%s] không thử được proxy %s: %s" % (UNKNOWN, proxy.split("@")[-1], e))
    else:
        detail.append("[%s] không có HTTPS_PROXY; không thử được allowlist của proxy" % UNKNOWN)
    record("NET-01", FAIL if bad else PASS, "đường ra mạng ngoài proxy", detail)

    # NET-02
    detail2, bad2 = [], False
    ok, why = udp_dns_reply(args.dns)
    bad2 |= ok
    detail2.append("[%s] DNS UDP thẳng tới %s: %s" % (FAIL if ok else PASS, args.dns, why))
    for port, label in [(53, "DNS qua TCP"), (853, "DNS-over-TLS")]:
        ok, why = tcp_connect(args.dns, port, socket.AF_INET)
        bad2 |= ok
        detail2.append("[%s] %s tới %s:%d: %s" % (FAIL if ok else PASS, label, args.dns, port, why))
    try:
        socket.getaddrinfo(args.probe_host, 443)
        detail2.append("[%s] resolver của hệ thống phân giải được %s; chấp nhận được nếu đó là resolver nội bộ có log" % (WARN, args.probe_host))
        resolver_warn = True
    except socket.gaierror:
        detail2.append("[%s] tiến trình không tự phân giải tên miền (proxy phân giải)" % PASS)
        resolver_warn = False
    record("NET-02", FAIL if bad2 else (WARN if resolver_warn else PASS), "DNS không đi thẳng ra ngoài", detail2)


SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)", re.I)
NOT_SECRET = re.compile(r"(PATH|FILE|DIR|URL|HOST|SOCK|ID$|_NAME$|KEYCHAIN)", re.I)


def probe_cred01(workspace):
    suspicious, static_keys = [], []
    for name, value in os.environ.items():
        if SECRET_NAME.search(name) and not NOT_SECRET.search(name) and len(value) >= 16 and os.sep not in value:
            suspicious.append(name)
    akid = os.environ.get("AWS_ACCESS_KEY_ID", "")
    if akid.startswith("AKIA"):
        static_keys.append("AWS_ACCESS_KEY_ID là access key dài hạn (AKIA…)")
    dotenv = []
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    base_depth = workspace.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in skip]
        if root.count(os.sep) - base_depth >= 4:
            dirs[:] = []
        for fn in files:
            if fn == ".env" or fn.startswith(".env."):
                if not fn.endswith((".example", ".sample", ".template")):
                    dotenv.append(os.path.join(root, fn))
    parent = os.path.dirname(os.path.abspath(workspace))
    while parent and parent != os.path.dirname(parent):
        p = os.path.join(parent, ".env")
        if exists(p) and can_read(p):
            dotenv.append(p + " (thư mục cha của workspace)")
        if os.path.abspath(parent) == os.path.abspath(HOME):
            break
        parent = os.path.dirname(parent)
    if static_keys:
        record("CRED-01", FAIL, "có credential dài hạn trong biến môi trường", static_keys)
    if suspicious:
        record("CRED-01", WARN, "biến môi trường có tên giống secret (chỉ in tên, không in giá trị)", sorted(suspicious))
    if dotenv:
        record("CRED-01", WARN, "có file .env trong workspace hoặc thư mục cha; kiểm tra bằng gitleaks", dotenv)
    if not (static_keys or suspicious or dotenv):
        record("CRED-01", PASS, "không thấy biến môi trường giống secret hay file .env (heuristic; chạy thêm gitleaks)")


# ----------------------------------------------------------------------------------------

ORDER = ["SC-01", "SC-02", "SC-03", "ISO-01", "ISO-03", "ISO-04", "NET-01", "NET-02", "NET-04", "CRED-01", "ACT-03"]
RANK = {FAIL: 0, WARN: 1, UNKNOWN: 2, PASS: 3, NA: 4}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", nargs="?", choices=["all", "config", "probe"], default="all")
    ap.add_argument("--workspace", default=os.getcwd(), help="thư mục dự án (mặc định: thư mục hiện tại)")
    ap.add_argument("--probe-host", default="example.org", help="một domain KHÔNG nằm trong allowlist (mặc định example.org)")
    ap.add_argument("--ipv4", default="1.1.1.1", help="IPv4 công cộng để thử kết nối thẳng (mặc định 1.1.1.1)")
    ap.add_argument("--ipv6", default="2606:4700:4700::1111", help="IPv6 công cộng để thử (mặc định 2606:4700:4700::1111)")
    ap.add_argument("--dns", default="8.8.8.8", help="DNS resolver công cộng để thử NET-02 (mặc định 8.8.8.8)")
    ap.add_argument("--keychain-item", help="macOS: tên một item có thật trong Keychain để thử ISO-03")
    ap.add_argument("--host-home", action="append", default=[], help="thêm thư mục home cần thử (khi agent chạy dưới user khác)")
    ap.add_argument("--no-network", action="store_true", help="bỏ qua phép thử mạng")
    ap.add_argument("--json", action="store_true", help="in kết quả dạng JSON")
    args = ap.parse_args()
    workspace = os.path.abspath(args.workspace)

    if args.mode in ("all", "config"):
        check_config(workspace)
    if args.mode in ("all", "probe"):
        probe_iso01()
        probe_iso03(workspace, args.keychain_item, args.host_home)
        probe_iso04()
        if not args.no_network:
            probe_net(args)
        probe_cred01(workspace)

    results.sort(key=lambda r: (ORDER.index(r["control"]) if r["control"] in ORDER else 99, RANK[r["status"]]))
    if args.json:
        json.dump({"platform": platform.platform(), "mode": args.mode, "workspace": workspace,
                   "results": results}, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        width = max(len(s) for s in (PASS, FAIL, WARN, NA, UNKNOWN))
        for r in results:
            print("[%-*s] %-7s %s" % (width, r["status"], r["control"], r["message"]))
            for d in r["detail"]:
                print("%s%s" % (" " * (width + 12), d))
        counts = {s: sum(1 for r in results if r["status"] == s) for s in (FAIL, WARN, UNKNOWN, PASS, NA)}
        print("\n" + " · ".join("%s: %d" % (k, v) for k, v in counts.items()))
        print("Kết quả chỉ nói về những đường đi script đã thử (Mục 0.5). "
              "Phần probe phải chạy bên trong môi trường của agent mới có ý nghĩa.")
    sys.exit(1 if any(r["status"] == FAIL for r in results) else 0)


if __name__ == "__main__":
    main()
