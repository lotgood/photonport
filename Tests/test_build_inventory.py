import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts/provenance/build_inventory.py"
spec = importlib.util.spec_from_file_location("build_inventory", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class BuildInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "PhotonPort")
        self.git("config", "user.email", "photon@example.test")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True).strip()

    def commit(self, message, author=None):
        env = None
        if author:
            env = {"GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1],
                   "GIT_COMMITTER_NAME": "Committer", "GIT_COMMITTER_EMAIL": "c@example.test"}
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", message], check=True, env=env)
        return self.git("rev-parse", "HEAD")

    def run_build(self, mit, transition, output=None, authors=("photon@example.test",)):
        output = output or self.repo.parent / "inventory.json"
        args = ["--repo", str(self.repo), "--root", ".", "--mit-through", mit,
                "--gpl-transition", transition, "--output", str(output)]
        for author in authors:
            args += ["--photonport-author", author]
        self.assertEqual(mod.main(args), 0)
        return json.loads(output.read_text())

    def test_mixed_regions_binary_and_marker(self):
        (self.repo / "a.txt").write_text("one\ntwo\n")
        (self.repo / "image.bin").write_bytes(b"\x00\x01\xff")
        mit = self.commit("MIT")
        (self.repo / "a.txt").write_text("one\ntwo\nthree\n")
        transition = self.commit("transition", ("Upstream", "up@example.test"))
        result = self.run_build(mit, transition)
        self.assertEqual(result["approval_status"], mod.APPROVAL)
        self.assertEqual([e["path"] for e in result["entries"]], ["a.txt", "image.bin"])
        self.assertTrue(next(e for e in result["entries"] if e["binary"])["whole_file"])
        self.assertIn("MIT_EXACT", result["summary"]["classifications"])

    def test_dirty_and_missing_root_fail_closed(self):
        (self.repo / "a.txt").write_text("one\n")
        commit = self.commit("base")
        (self.repo / "a.txt").write_text("dirty\n")
        args = ["--repo", str(self.repo), "--root", ".", "--mit-through", commit,
                "--gpl-transition", commit, "--output", str(self.repo / "x.json")]
        self.assertNotEqual(mod.main(args), 0)

    def test_output_is_deterministic(self):
        (self.repo / "a.txt").write_text("one\n")
        commit = self.commit("base")
        first = self.run_build(commit, commit)
        second = self.run_build(commit, commit, self.repo.parent / "second.json")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
