import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


WRAPPER = Path(__file__).with_name("cargo_targets.py")
SEVEN_DAYS = 7 * 24 * 60 * 60


class CargoTargetExpiry(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.root = Path(self.home.name) / ".cache" / "oiran-polaris-cargo-targets"
        self.bin = Path(self.home.name) / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text('#!/bin/sh\nset -eu\ntouch "$CARGO_TARGET_DIR/compiled"\n')
        cargo.chmod(0o755)
        self.env = dict(os.environ, HOME=self.home.name, PATH=f"{self.bin}:{os.environ['PATH']}")

    def invoke(self, *args, check=True):
        return subprocess.run(
            ["python3", str(WRAPPER), *args], env=self.env, check=check,
            text=True, capture_output=True,
        )

    def build(self, key):
        self.invoke("run", key, "--", "build")
        return self.root / key

    def age(self, target):
        timestamp = time.time() - SEVEN_DAYS - 60
        os.utime(target / ".last-cargo-use", (timestamp, timestamp))

    def test_only_expired_managed_targets_are_removed(self):
        old = self.build("old")
        fresh = self.build("fresh")
        self.age(old)
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "data").touch()
        outside = Path(self.home.name) / "release"
        outside.mkdir()
        (self.root / "linked").symlink_to(outside, target_is_directory=True)
        self.invoke("expire")
        self.assertFalse(old.exists())
        self.assertTrue((fresh / "compiled").is_file())
        self.assertTrue((foreign / "data").is_file())
        self.assertTrue((self.root / "linked").is_symlink())
        self.assertTrue(outside.is_dir())

    def test_running_build_protects_its_target(self):
        old = self.build("old")
        self.age(old)
        with (self.root / ".lock").open() as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            self.assertEqual(self.invoke("expire", check=False).returncode, 75)
            self.assertTrue(old.is_dir())
        self.invoke("expire")
        self.assertFalse(old.exists())

    def test_build_refuses_an_unmanaged_existing_directory(self):
        self.build("initial")
        foreign = self.root / "foreign"
        foreign.mkdir()
        self.assertNotEqual(self.invoke("run", "foreign", "--", "build", check=False).returncode, 0)
        self.assertFalse((foreign / "compiled").exists())
