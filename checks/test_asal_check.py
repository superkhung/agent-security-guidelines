# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the configuration parsers of asal_check.py. Run: python3 -m unittest discover -s checks"""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asal_check as ac


class PinStatus(unittest.TestCase):
    def status(self, command, *args):
        return ac.pin_status({"command": command, "args": list(args)})[0]

    def test_npx(self):
        self.assertEqual(self.status("npx", "-y", "@modelcontextprotocol/server-filesystem", "/p"), ac.FAIL)
        self.assertEqual(self.status("npx", "-y", "@modelcontextprotocol/server-filesystem@latest"), ac.FAIL)
        self.assertEqual(self.status("npx", "-y", "@modelcontextprotocol/server-filesystem@2025.8.1", "/p"), ac.PASS)
        self.assertEqual(self.status("npx", "some-server"), ac.FAIL)
        self.assertEqual(self.status("npx", "some-server@1.2.3"), ac.PASS)
        self.assertEqual(self.status("/usr/local/bin/npx", "-y", "@scope/pkg"), ac.FAIL)

    def test_uvx(self):
        self.assertEqual(self.status("uvx", "mcp-server-git"), ac.FAIL)
        self.assertEqual(self.status("uvx", "mcp-server-git==0.6.2"), ac.PASS)
        self.assertEqual(self.status("uvx", "mcp-server-git@0.6.2"), ac.PASS)
        self.assertEqual(self.status("uvx", "--from", "mcp-server-git==0.6.2", "mcp-server-git"), ac.PASS)
        self.assertEqual(self.status("uv", "tool", "run", "mcp-server-git"), ac.FAIL)

    def test_container(self):
        self.assertEqual(self.status("docker", "run", "-i", "--rm", "mcp/fetch"), ac.FAIL)
        self.assertEqual(self.status("docker", "run", "-i", "mcp/fetch:latest"), ac.FAIL)
        self.assertEqual(self.status("docker", "run", "-i", "mcp/fetch:1.2"), ac.WARN)
        self.assertEqual(self.status("docker", "run", "-i", "mcp/fetch@sha256:" + "a" * 64), ac.PASS)

    def test_remote_is_not_a_pin_question(self):
        self.assertEqual(ac.pin_status({"url": "https://mcp.example/"}), (None, None))


class CodexToml(unittest.TestCase):
    def test_servers_and_subtables(self):
        text = '\n'.join([
            '[mcp_servers.git]', 'command = "uvx"', 'args = ["mcp-server-git"]',
            '[mcp_servers.git.env]', 'TOKEN = "x"',
            '[mcp_servers."docs site"]', 'url = "https://mcp.example/"',
            '[profile]', 'command = "ignored"'])
        servers = ac.parse_codex_toml(text)
        self.assertEqual(sorted(servers), ["docs site", "git"])
        self.assertEqual(servers["git"], {"command": "uvx", "args": ["mcp-server-git"]})
        self.assertEqual(servers["docs site"], {"url": "https://mcp.example/"})


class ClaudeCodeSettings(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.home = os.path.join(self.tmp, "home")
        self.ws = os.path.join(self.tmp, "ws")
        for d in (os.path.join(self.home, ".claude"), os.path.join(self.ws, ".claude"), os.path.join(self.home, ".ssh")):
            os.makedirs(d)
        self.saved_home = ac.HOME
        ac.HOME = self.home
        del ac.results[:]

    def tearDown(self):
        import shutil
        ac.HOME = self.saved_home
        del ac.results[:]
        shutil.rmtree(self.tmp)

    def write(self, path, data):
        import json
        with open(path, "w") as f:
            json.dump(data, f)

    def statuses(self, control):
        return [r["status"] for r in ac.results if r["control"] == control]

    def test_bypass_in_project_settings_is_only_a_warning(self):
        self.write(os.path.join(self.ws, ".claude", "settings.json"), {"permissions": {"defaultMode": "bypassPermissions"}})
        ac.check_claude_code(self.ws)
        self.assertEqual(self.statuses("ACT-03"), [ac.WARN])

    def test_bypass_in_user_settings_fails(self):
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"permissions": {"defaultMode": "bypassPermissions"}})
        ac.check_claude_code(self.ws)
        self.assertEqual(self.statuses("ACT-03"), [ac.FAIL])

    def test_sandbox_enabled_in_local_settings(self):
        self.write(os.path.join(self.ws, ".claude", "settings.local.json"), {"sandbox": {"enabled": True}})
        ac.check_claude_code(self.ws)
        self.assertEqual(self.statuses("ISO-02"), [ac.PASS])

    def test_sandbox_disabled_is_reported(self):
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"sandbox": {"enabled": False}})
        ac.check_claude_code(self.ws)
        self.assertEqual(self.statuses("ISO-02"), [ac.FAIL])

    def test_read_deny_rules(self):
        ac.check_claude_code(self.ws)
        self.assertEqual(self.statuses("ISO-03"), [ac.WARN])
        del ac.results[:]
        self.write(os.path.join(self.home, ".claude", "settings.json"), {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
        ac.check_claude_code(self.ws)
        self.assertEqual(self.statuses("ISO-03"), [ac.PASS])

    def test_no_claude_code(self):
        import shutil
        shutil.rmtree(os.path.join(self.home, ".claude"))
        shutil.rmtree(os.path.join(self.ws, ".claude"))
        ac.check_claude_code(self.ws)
        self.assertEqual(self.statuses("ACT-03"), [ac.NA])


if __name__ == "__main__":
    unittest.main()
