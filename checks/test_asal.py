# SPDX-License-Identifier: Apache-2.0
"""Unit tests for asal.py. Run: python3 -m unittest discover -s checks"""
import contextlib, io, json, os, shutil, sys, tempfile, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))
import asal  # noqa: E402

MATRIX = asal.load_json(os.path.join(HERE, "asal_matrix.json"), asal.MATRIX_SCHEMA)
ASAL0 = [c for c, v in MATRIX["controls"].items() if v["levels"]["ASAL-0"] == "required"]


class PinStatus(unittest.TestCase):
    def status(self, command, *args):
        return asal.pin_status({"command": command, "args": list(args)})[0]

    def test_npx(self):
        self.assertEqual(self.status("npx", "-y", "@modelcontextprotocol/server-filesystem", "/p"), asal.FAIL)
        self.assertEqual(self.status("npx", "-y", "@modelcontextprotocol/server-filesystem@latest"), asal.FAIL)
        self.assertEqual(self.status("npx", "-y", "@modelcontextprotocol/server-filesystem@2025.8.1", "/p"), asal.PASS)
        self.assertEqual(self.status("npx", "some-server"), asal.FAIL)
        self.assertEqual(self.status("npx", "some-server@1.2.3"), asal.PASS)
        self.assertEqual(self.status("/usr/local/bin/npx", "-y", "@scope/pkg"), asal.FAIL)

    def test_uvx(self):
        self.assertEqual(self.status("uvx", "mcp-server-git"), asal.FAIL)
        self.assertEqual(self.status("uvx", "mcp-server-git==0.6.2"), asal.PASS)
        self.assertEqual(self.status("uvx", "mcp-server-git@0.6.2"), asal.PASS)
        self.assertEqual(self.status("uvx", "--from", "mcp-server-git==0.6.2", "mcp-server-git"), asal.PASS)
        self.assertEqual(self.status("uv", "tool", "run", "mcp-server-git"), asal.FAIL)

    def test_container(self):
        self.assertEqual(self.status("docker", "run", "-i", "--rm", "mcp/fetch"), asal.FAIL)
        self.assertEqual(self.status("docker", "run", "-i", "mcp/fetch:latest"), asal.FAIL)
        self.assertEqual(self.status("docker", "run", "-i", "mcp/fetch:1.2"), asal.REVIEW)
        self.assertEqual(self.status("docker", "run", "-i", "mcp/fetch@sha256:" + "a" * 64), asal.PASS)

    def test_remote_is_not_a_pin_question(self):
        self.assertEqual(asal.pin_status({"url": "https://mcp.example/"}), (None, None))


    def test_relative_command(self):
        self.assertEqual(self.status("./bin/server", "mcp"), asal.REVIEW)
        self.assertEqual(self.status("bin/server"), asal.REVIEW)
        self.assertEqual(asal.pin_status({"command": "./bin/server", "cwd": "/opt/srv"})[0], asal.PASS)
        self.assertEqual(asal.pin_status({"command": "./bin/server", "cwd": "."})[0], asal.REVIEW)
        self.assertEqual(self.status("${CLAUDE_PLUGIN_ROOT}/bin/server"), asal.PASS)
        self.assertEqual(self.status("/usr/local/bin/server"), asal.PASS)
        self.assertEqual(self.status("node", "server.js"), asal.PASS)


class ServerIdentity(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(asal.server_identity({"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"]}), "pkg:npm:@scope/pkg@1.2.3")
        self.assertEqual(asal.server_identity({"command": "uvx", "args": ["mcp-server-git==0.6.2"]}), "pkg:pypi:mcp-server-git==0.6.2")
        self.assertEqual(asal.server_identity({"command": "docker", "args": ["run", "-i", "--rm", "img@sha256:" + "b" * 64]}), "oci:img@sha256:" + "b" * 64)
        self.assertEqual(asal.server_identity({"url": "https://MCP.Example:443/x"}), "url:https://mcp.example/x")
        self.assertEqual(asal.server_identity({"url": "https://mcp.example:8443"}), "url:https://mcp.example:8443/")


class CodexToml(unittest.TestCase):
    def test_servers_and_subtables(self):
        text = "\n".join([
            '[mcp_servers.git]', 'command = "uvx"', 'args = ["mcp-server-git"]',
            '[mcp_servers.git.env]', 'TOKEN = "x"',
            '[mcp_servers."docs site"]', 'url = "https://mcp.example/"',
            '[profile]', 'command = "ignored"'])
        servers = asal.parse_codex_toml(text)
        self.assertEqual(sorted(servers), ["docs site", "git"])
        self.assertEqual(servers["git"], {"command": "uvx", "args": ["mcp-server-git"]})
        self.assertEqual(servers["docs site"], {"url": "https://mcp.example/"})

    def test_enabled_and_cwd(self):
        servers = asal.parse_codex_toml('[mcp_servers.a]\ncommand = "./a"\ncwd = "."\nenabled = false\n')
        self.assertEqual(servers["a"], {"command": "./a", "cwd": ".", "enabled": False})

    def test_plugins(self):
        text = '[plugins."a@m"]\nenabled = true\n\n[plugins."b@m"]\nenabled = false\n[features]\nenabled = true\n'
        self.assertEqual(asal.parse_codex_plugins(text), {"a@m": True, "b@m": False})


class TempHome(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = os.path.join(self.tmp, "home")
        self.ws = os.path.join(self.tmp, "ws")
        for d in (os.path.join(self.home, ".claude"), os.path.join(self.ws, ".claude"), os.path.join(self.home, ".ssh")):
            os.makedirs(d)
        self.saved = asal.HOME
        asal.HOME = self.home

    def tearDown(self):
        asal.HOME = self.saved
        shutil.rmtree(self.tmp)

    def write(self, path, data):
        with open(path, "w") as f:
            json.dump(data, f)


class ClaudeCodeSettings(TempHome):
    def statuses(self, probe):
        run = asal.Run()
        asal.collect_claude_code(run, self.ws)
        return [r["status"] for r in run.results if r["probe"] == probe]

    def test_bypass_in_project_settings_is_review_only(self):
        self.write(os.path.join(self.ws, ".claude", "settings.json"), {"permissions": {"defaultMode": "bypassPermissions"}})
        self.assertEqual(self.statuses("act03.claude.bypass"), [asal.REVIEW])

    def test_bypass_in_user_settings_fails(self):
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"permissions": {"defaultMode": "bypassPermissions"}})
        self.assertEqual(self.statuses("act03.claude.bypass"), [asal.FAIL])

    def test_disable_bypass(self):
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"permissions": {"disableBypassPermissionsMode": "disable"}})
        self.assertEqual(self.statuses("act03.claude.bypass"), [asal.PASS])

    def test_sandbox_setting(self):
        self.write(os.path.join(self.ws, ".claude", "settings.local.json"), {"sandbox": {"enabled": True}})
        self.assertEqual(self.statuses("iso02.claude.sandbox"), [asal.PASS])
        self.write(os.path.join(self.ws, ".claude", "settings.local.json"), {"sandbox": {"enabled": False}})
        self.assertEqual(self.statuses("iso02.claude.sandbox"), [asal.FAIL])

    def test_file_tools(self):
        self.assertEqual(self.statuses("iso03.claude.file_tools"), [asal.FAIL])
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
        self.assertEqual(self.statuses("iso03.claude.file_tools"), [asal.PASS])
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"permissions": {"blockReadsOutsideWorkingDirectories": True}})
        self.assertEqual(self.statuses("iso03.claude.file_tools"), [asal.PASS])

    def test_no_claude_code_is_untested_not_na(self):
        shutil.rmtree(os.path.join(self.home, ".claude"))
        shutil.rmtree(os.path.join(self.ws, ".claude"))
        self.assertEqual(self.statuses("act03.claude.bypass"), [asal.UNTESTED])

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs a non-root POSIX user")
    def test_unreadable_settings_are_untested(self):
        path = os.path.join(self.home, ".claude", "settings.json")
        self.write(path, {"sandbox": {"enabled": True}})
        os.chmod(path, 0)
        try:
            self.assertEqual(self.statuses("iso02.claude.sandbox"), [asal.UNTESTED])
            self.assertEqual(self.statuses("act03.claude.bypass"), [asal.UNTESTED])
        finally:
            os.chmod(path, 0o600)

    def test_example_settings_pass(self):
        with open(os.path.join(os.path.dirname(HERE), "examples", "claude-code", "settings.json")) as f:
            self.write(os.path.join(self.home, ".claude", "settings.json"), json.load(f))
        run = asal.Run()
        asal.collect_claude_code(run, self.ws)
        self.assertEqual({r["probe"]: r["status"] for r in run.results},
                         {"act03.claude.bypass": asal.PASS, "iso02.claude.sandbox": asal.PASS, "iso03.claude.file_tools": asal.PASS})


class Plugins(TempHome):
    def collect(self):
        run = asal.Run()
        asal.collect_mcp(run, self.ws)
        return run, {r["probe"]: r for r in run.results}

    def codex_plugin(self, market, name, version, manifest, files=()):
        root = os.path.join(self.home, ".codex", "plugins", "cache", market, name, version)
        os.makedirs(os.path.join(root, ".codex-plugin"))
        self.write(os.path.join(root, ".codex-plugin", "plugin.json"), manifest)
        for rel, data in files:
            self.write(os.path.join(root, rel), data)
        return root

    def test_codex_plugins(self):
        os.makedirs(os.path.join(self.home, ".codex"))
        with open(os.path.join(self.home, ".codex", "config.toml"), "w") as f:
            f.write('[plugins."tools@m"]\nenabled = true\n[plugins."chat@m"]\nenabled = true\n'
                    '[plugins."gone@m"]\nenabled = true\n[plugins."off@m"]\nenabled = false\n')
        self.codex_plugin("m", "tools", "1.0", {"mcpServers": "./.mcp.json", "hooks": "./hooks.json"}, [
            (".mcp.json", {"mcpServers": {"cu": {"command": "./bin/cu", "args": ["mcp"], "cwd": "."},
                                          "app": {"command": "/abs/launch", "enabled": False}}})])
        self.codex_plugin("m", "chat", "2.0", {"apps": "./.app.json"}, [(".app.json", {"apps": {"chat": {"id": "asdk_1"}}})])
        self.codex_plugin("m", "off", "1.0", {"mcpServers": {"x": {"command": "/x"}}})
        run, res = self.collect()
        idents = sorted(i["identity"] for i in run.inventory)
        self.assertEqual(idents, ["app:codex:asdk_1", "plugin:codex:tools@m/1.0/cu"])
        self.assertIn("tắt, không tính: Codex CLI plugin tools@m: app", res["sc01.inventory"]["evidence"])
        self.assertEqual(res["sc01.plugins"]["status"], asal.REVIEW)
        self.assertIn("gone@m", res["sc01.plugins"]["evidence"][0])
        self.assertEqual(res["sc01.plugin.hooks"]["status"], asal.REVIEW)
        self.assertEqual(res["sc03.launch"]["status"], asal.REVIEW)

    def claude_plugin(self, name, manifest=None, files=()):
        root = os.path.join(self.home, ".claude", "plugins", "cache", "mk", name, "1.2.0")
        os.makedirs(root)
        if manifest is not None:
            os.makedirs(os.path.join(root, ".claude-plugin"))
            self.write(os.path.join(root, ".claude-plugin", "plugin.json"), manifest)
        for rel, data in files:
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            self.write(os.path.join(root, rel), data)
        return root

    def test_claude_plugins(self):
        root = self.claude_plugin("gh", files=[(".mcp.json", {"mcpServers": {"github": {"url": "https://api.example/mcp"}}}),
                                               ("hooks/hooks.json", {"hooks": {}})])
        self.claude_plugin("db", {"mcpServers": {"pg": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/pg"}}})
        self.claude_plugin("quiet", files=[(".mcp.json", {"mcpServers": {"q": {"command": "/q"}}})])
        self.write(os.path.join(self.home, ".claude", "plugins", "installed_plugins.json"),
                   {"version": 2, "plugins": {"gh@mk": [{"scope": "user", "installPath": root, "version": "1.2.0"}]}})
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"enabledPlugins": {"gh@mk": True, "quiet@mk": True}})
        self.write(os.path.join(self.ws, ".claude", "settings.json"), {"enabledPlugins": {"db@mk": True}})
        self.write(os.path.join(self.ws, ".claude", "settings.local.json"), {"enabledPlugins": {"quiet@mk": False}})
        run, res = self.collect()
        self.assertEqual(sorted(i["identity"] for i in run.inventory),
                         ["plugin:claude:db@mk/1.2.0/pg", "plugin:claude:gh@mk/1.2.0/github"])
        self.assertEqual(res["sc01.plugin.hooks"]["status"], asal.REVIEW)
        self.assertEqual(res["sc02.project.config"]["status"], asal.REVIEW)
        self.assertIn("db@mk (enabledPlugins trong settings cấp project)", res["sc02.project.config"]["evidence"])
        self.assertEqual(res["net04.remote.https"]["status"], asal.PASS)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs a non-root POSIX user")
    def test_unreadable_config_is_untested_not_na(self):
        path = os.path.join(self.home, ".cursor", "mcp.json")
        os.makedirs(os.path.dirname(path))
        self.write(path, {"mcpServers": {}})
        os.chmod(path, 0)
        try:
            _, res = self.collect()
        finally:
            os.chmod(path, 0o600)
        self.assertEqual(res["sc01.config.unreadable"]["status"], asal.REVIEW)
        self.assertEqual(res["sc01.inventory"]["status"], asal.UNTESTED)
        self.assertEqual(res["sc03.launch"]["status"], asal.UNTESTED)

    def test_empty_config_file_has_no_servers(self):
        path = os.path.join(self.home, ".cursor", "mcp.json")
        os.makedirs(os.path.dirname(path))
        open(path, "w").close()
        _, res = self.collect()
        self.assertNotIn("sc01.config.unreadable", res)
        self.assertEqual(res["sc01.inventory"]["status"], asal.NA)

    def test_no_plugins_no_plugin_results(self):
        _, res = self.collect()
        self.assertNotIn("sc01.plugins", res)
        self.assertNotIn("sc01.plugin.hooks", res)


class OtherClients(TempHome):
    def run_collect(self):
        # Only home-relative locations: /Applications depends on the machine running the tests.
        clients = [(n, [p for p in paths if not os.path.isabs(p)], cmds, note) for n, paths, cmds, note in asal.OTHER_CLIENTS]
        run = asal.Run()
        with mock.patch.dict(os.environ, {"PATH": self.tmp}), mock.patch.object(asal, "OTHER_CLIENTS", clients):
            asal.collect_other_clients(run)
        return run.results

    def test_other_agent_clients_are_review(self):
        os.makedirs(os.path.join(self.home, ".config", "opencode"))
        os.makedirs(os.path.join(self.home, ".gemini", "antigravity"))
        results = self.run_collect()
        self.assertEqual([(r["probe"], r["status"]) for r in results], [("iso02.other_clients", asal.REVIEW)])
        self.assertEqual([e.split(":")[0] for e in results[0]["evidence"]], ["opencode", "Antigravity"])

    def test_claude_code_alone_adds_nothing(self):
        self.assertEqual(self.run_collect(), [])


class OtherClientConfigs(TempHome):
    def collect(self):
        run = asal.Run()
        asal.collect_mcp(run, self.ws)
        return run, {r["probe"]: r for r in run.results}

    def test_opencode_v1_and_v2(self):
        os.makedirs(os.path.join(self.home, ".config", "opencode"))
        with open(os.path.join(self.home, ".config", "opencode", "opencode.jsonc"), "w") as f:
            f.write('{\n  // v1\n  "mcp": {\n    "fs": {"type": "local", "command": ["npx", "-y", "@scope/fs@1.0.0"]},\n'
                    '    "off": {"type": "local", "command": ["npx", "x"], "enabled": false},\n'
                    '    "docs": {"type": "remote", "url": "http://docs.example/mcp"}, /* trailing comma */\n  },\n}\n')
        self.write(os.path.join(self.ws, "opencode.json"),
                   {"mcp": {"servers": {"git": {"type": "local", "command": ["uvx", "mcp-server-git"]},
                                        "old": {"type": "local", "command": ["/x"], "disabled": True}}}})
        run, res = self.collect()
        self.assertEqual(sorted(i["identity"] for i in run.inventory),
                         ["pkg:npm:@scope/fs@1.0.0", "pkg:pypi:mcp-server-git", "url:http://docs.example/mcp"])
        self.assertEqual(res["sc03.launch"]["status"], asal.FAIL)
        self.assertEqual(res["net04.remote.https"]["status"], asal.FAIL)
        self.assertEqual(res["sc02.project.config"]["status"], asal.REVIEW)
        self.assertEqual(len([e for e in res["sc01.inventory"]["evidence"] if e.startswith("tắt, không tính")]), 2)

    def test_antigravity_server_url(self):
        os.makedirs(os.path.join(self.home, ".gemini", "config"))
        self.write(os.path.join(self.home, ".gemini", "config", "mcp_config.json"),
                   {"mcpServers": {"k": {"serverUrl": "https://mcp.example/k"}, "d": {"command": "/d", "disabled": True}}})
        run, _ = self.collect()
        self.assertEqual([i["identity"] for i in run.inventory], ["url:https://mcp.example/k"])

    def test_antigravity_cli_settings(self):
        path = os.path.join(self.home, ".gemini", "antigravity-cli", "settings.json")
        os.makedirs(os.path.dirname(path))
        self.write(path, {"enableTerminalSandbox": False, "toolPermission": "always-proceed"})
        run = asal.Run()
        asal.collect_antigravity_cli(run)
        self.assertEqual({r["probe"]: r["status"] for r in run.results},
                         {"iso02.antigravity_cli.sandbox": asal.FAIL, "act03.antigravity_cli.always_proceed": asal.FAIL})
        self.write(path, {"toolPermission": "request-review"})
        run = asal.Run()
        asal.collect_antigravity_cli(run)
        self.assertEqual(run.results, [])


class EnvSecrets(TempHome):
    def names(self, env):
        run = asal.Run()
        with mock.patch.dict(os.environ, env, clear=True):
            asal.probe_cred01(run, self.ws)
        return {r["probe"]: r for r in run.results}["cred01.env.names"]

    def test_sandbox_proxy_password_is_not_a_secret(self):
        pw = "p" * 32
        r = self.names({"HTTPS_PROXY": "http://u:%s@localhost:5000" % pw, "CLOUDSDK_PROXY_PASSWORD": pw})
        self.assertEqual(r["status"], asal.PASS)
        self.assertIn("CLOUDSDK_PROXY_PASSWORD", r["evidence"][0])

    def test_other_tokens_still_review(self):
        pw = "p" * 32
        r = self.names({"HTTPS_PROXY": "http://u:%s@localhost:5000" % pw, "CLOUDSDK_PROXY_PASSWORD": pw, "SERVICE_TOKEN": "t" * 32})
        self.assertEqual(r["status"], asal.REVIEW)
        self.assertEqual(r["evidence"][0], "SERVICE_TOKEN")

    def test_remote_proxy_password_is_a_secret(self):
        pw = "p" * 32
        r = self.names({"HTTPS_PROXY": "http://u:%s@proxy.corp.example:3128" % pw, "PROXY_PASSWORD": pw})
        self.assertEqual(r["status"], asal.REVIEW)


def report(host, results, command="probe", context="devcontainer", use_case="uc", inventory=None):
    rep = {"schema": asal.REPORT_SCHEMA, "tool": {"name": "asal", "version": asal.VERSION},
           "run": {"id": host + command + context, "time": "2026-09-24T00:00:00Z", "command": command, "context": context, "detected": []},
           "host": {"id": host, "user": "", "pseudonym": "sha256", "os": "Linux"},
           "use_case": use_case,
           "results": [{"probe": p, "control": c, "kind": "test", "status": s, "message": "", "evidence": []} for p, c, s in results]}
    if inventory is not None:
        rep["inventory"] = inventory
    return rep


def asal0_pass_results(skip=()):
    return [("x." + c.lower(), c, asal.PASS) for c in ASAL0 if c not in skip and c not in ("RES-01", "OBS-04")]


ATTEST_RES_OBS = {"schema": asal.ATTEST_SCHEMA, "items": [
    {"control": "RES-01", "use_case": "uc", "status": "pass", "by": "a", "date": "2026-09-01", "expires": "2027-01-01"},
    {"control": "OBS-04", "use_case": "uc", "status": "pass", "by": "a", "date": "2026-09-01", "expires": "2027-01-01"}]}


class Evaluate(unittest.TestCase):
    def eval1(self, reports, policy=None, attest=ATTEST_RES_OBS, today="2026-09-24"):
        policy = policy or {"schema": asal.POLICY_SCHEMA, "use_cases": [{"id": "uc", "level": "ASAL-0"}],
                            "approved_mcp_servers": []}
        evaluated, ignored, expired, valid = asal.evaluate(reports, MATRIX, policy, attest, today)
        return evaluated, ignored, expired

    def test_asal0_reached_with_machine_results_and_attestations(self):
        ev, _, _ = self.eval1([report("h1", asal0_pass_results())])
        self.assertTrue(ev[0]["achieved"]["ASAL-0"], {c: ev[0]["status"][c] for c in ASAL0})
        self.assertFalse(ev[0]["achieved"]["ASAL-1"])

    def test_missing_attestation_blocks(self):
        ev, _, _ = self.eval1([report("h1", asal0_pass_results())], attest=None)
        self.assertEqual(ev[0]["status"]["RES-01"], asal.UNTESTED)
        self.assertFalse(ev[0]["achieved"]["ASAL-0"])

    def test_expired_attestation_is_not_counted(self):
        ev, _, expired = self.eval1([report("h1", asal0_pass_results())], today="2027-02-01")
        self.assertEqual(len(expired), 2)
        self.assertFalse(ev[0]["achieved"]["ASAL-0"])

    def test_attestation_never_overrides_machine_fail(self):
        attest = {"schema": asal.ATTEST_SCHEMA, "items": ATTEST_RES_OBS["items"] + [
            {"control": "ISO-01", "use_case": "uc", "status": "pass", "by": "a", "date": "2026-09-01", "expires": "2027-01-01"}]}
        results = asal0_pass_results(skip=("ISO-01",)) + [("iso01.privilege", "ISO-01", asal.FAIL)]
        ev, _, _ = self.eval1([report("h1", results)], attest=attest)
        self.assertEqual(ev[0]["status"]["ISO-01"], asal.FAIL)
        self.assertFalse(ev[0]["achieved"]["ASAL-0"])

    def test_waived_required_control_blocks(self):
        attest = {"schema": asal.ATTEST_SCHEMA, "items": [ATTEST_RES_OBS["items"][1],
            {"control": "RES-01", "use_case": "uc", "status": "waived", "by": "a", "risk_accepted_by": "b",
             "date": "2026-09-01", "expires": "2027-01-01"}]}
        ev, _, _ = self.eval1([report("h1", asal0_pass_results())], attest=attest)
        self.assertEqual(ev[0]["status"]["RES-01"], "waived")
        self.assertFalse(ev[0]["achieved"]["ASAL-0"])

    def test_review_blocks_until_attested(self):
        results = asal0_pass_results(skip=("CRED-01",)) + [("cred01.env.names", "CRED-01", asal.REVIEW)]
        ev, _, _ = self.eval1([report("h1", results)])
        self.assertEqual(ev[0]["status"]["CRED-01"], asal.REVIEW)
        self.assertFalse(ev[0]["achieved"]["ASAL-0"])
        attest = {"schema": asal.ATTEST_SCHEMA, "items": ATTEST_RES_OBS["items"] + [
            {"control": "CRED-01", "use_case": "uc", "status": "pass", "by": "a", "date": "2026-09-01", "expires": "2027-01-01"}]}
        ev, _, _ = self.eval1([report("h1", results)], attest=attest)
        self.assertEqual(ev[0]["status"]["CRED-01"], asal.PASS)
        self.assertTrue(ev[0]["achieved"]["ASAL-0"])

    def test_untested_subprobe_does_not_hide_a_fail(self):
        results = asal0_pass_results(skip=("ISO-01",)) + [("a", "ISO-01", asal.UNTESTED), ("b", "ISO-01", asal.FAIL)]
        ev, _, _ = self.eval1([report("h1", results)])
        self.assertEqual(ev[0]["status"]["ISO-01"], asal.FAIL)

    def test_probe_from_a_context_outside_the_policy_is_ignored(self):
        policy = {"schema": asal.POLICY_SCHEMA, "use_cases": [{"id": "uc", "level": "ASAL-0", "contexts": ["devcontainer"]}],
                  "approved_mcp_servers": []}
        ev, ignored, _ = self.eval1([report("h1", asal0_pass_results(), context="host")], policy=policy)
        self.assertEqual(ignored, [("h1", "uc", "host")])
        self.assertEqual(ev, [])

    def test_approved_servers(self):
        item = {"client": "Claude Code", "config": "~/.claude.json", "scope": "user", "name": "fs",
                "identity": "pkg:npm:fs@1.0.0", "remote": False, "launch": asal.PASS, "launch_note": ""}
        collect = report("h1", [], command="collect", context="host", inventory=[item])
        probe = report("h1", asal0_pass_results())
        policy = {"schema": asal.POLICY_SCHEMA, "use_cases": [{"id": "uc", "level": "ASAL-0"}], "approved_mcp_servers": []}
        ev, _, _ = self.eval1([collect, probe], policy=policy)
        self.assertEqual(ev[0]["status"]["SC-02"], asal.FAIL)
        policy["approved_mcp_servers"] = [{"identity": "pkg:npm:fs@1.0.0"}]
        ev, _, _ = self.eval1([collect, probe], policy=policy)
        self.assertEqual(ev[0]["status"]["SC-02"], asal.PASS)

    def test_sc02_without_an_approved_list_is_not_proven(self):
        results = asal0_pass_results(skip=("SC-02",)) + [("sc02.project.config", "SC-02", asal.NA)]
        policy = {"schema": asal.POLICY_SCHEMA, "use_cases": [{"id": "uc", "level": "ASAL-0"}]}
        ev, _, _ = self.eval1([report("h1", results)], policy=policy)
        self.assertEqual(ev[0]["status"]["SC-02"], asal.UNTESTED)

    def test_iso02_is_na_when_the_client_runs_in_a_container(self):
        results = asal0_pass_results(skip=("ISO-02",)) + [("iso04.container", "ISO-04", asal.PASS),
                                                           ("iso02.claude.sandbox", "ISO-02", asal.FAIL)]
        ev, _, _ = self.eval1([report("h1", results)])
        self.assertEqual(ev[0]["status"]["ISO-02"], asal.NA)

    def test_markdown_and_csv_render(self):
        reports = [report("h1", asal0_pass_results())]
        ev, ignored, expired, valid = asal.evaluate(reports, MATRIX, None, ATTEST_RES_OBS, "2026-09-24")
        md = asal.render_markdown(ev, MATRIX, None, ignored, expired, valid, [], 1, "2026-09-24")
        self.assertIn("# Báo cáo tư thế agent", md)
        self.assertIn(asal.CAVEAT, md)
        self.assertTrue(asal.render_csv(ev).startswith("use_case,host,control,status,source"))

    def test_markdown_shows_the_next_level(self):
        reports = [report("h1", asal0_pass_results() + [("iso03.read.credentials", "ISO-03", asal.PASS)])]
        policy = {"schema": asal.POLICY_SCHEMA, "use_cases": [{"id": "uc", "level": "ASAL-0"}]}
        ev, ignored, expired, valid = asal.evaluate(reports, MATRIX, policy, ATTEST_RES_OBS, "2026-09-24")
        md = asal.render_markdown(ev, MATRIX, policy, ignored, expired, valid, [], 1, "2026-09-24")
        section = md.split("### Cấp kế tiếp: ASAL-1", 1)[1].split("###", 1)[0]
        row = next(l for l in section.splitlines() if l.startswith("| ISO-03 "))
        self.assertEqual(row.split("|")[2].strip(), "1")
        self.assertNotIn("| SC-02 ", section)


class Matrix(unittest.TestCase):
    def test_matrix_file_matches_the_guideline(self):
        import export_matrix
        with open(export_matrix.GUIDE, encoding="utf-8") as f:
            expected = export_matrix.render(export_matrix.build(f.read()))
        with open(os.path.join(HERE, "asal_matrix.json"), encoding="utf-8") as f:
            self.assertEqual(f.read(), expected, "run python3 scripts/export_matrix.py")


class Cli(TempHome):
    def test_collect_writes_a_report(self):
        out = os.path.join(self.tmp, "c.json")
        with contextlib.redirect_stdout(io.StringIO()):
            asal.main(["collect", "--workspace", self.ws, "--host-id", "h", "--use-case", "uc", "-o", out])
        rep = asal.load_json(out, asal.REPORT_SCHEMA)
        self.assertEqual(rep["host"]["id"], "h")
        self.assertEqual(rep["run"]["context"], "host")
        self.assertIn("inventory", rep)

    def test_home_is_replaced_in_evidence(self):
        run = asal.Run()
        run.add("p", "ISO-03", asal.FAIL, "m", [os.path.join(self.home, ".ssh")])
        self.assertEqual(run.results[0]["evidence"], ["~/.ssh"])

    def test_version(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(asal.main(["version"]), 0)


if __name__ == "__main__":
    unittest.main()
