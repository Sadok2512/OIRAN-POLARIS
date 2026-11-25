#!/usr/bin/env python3
"""Run Cargo in a managed cache, or expire inactive managed targets."""

import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


RETENTION_SECONDS = 7 * 24 * 60 * 60
STAMP = ".last-cargo-use"
KEY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}")


class CacheBusy(Exception):
    pass


def cache_root():
    root = Path.home() / ".cache" / "oiran-polaris-cargo-targets"
    if root.resolve() != root:
        raise ValueError("managed cache path must not traverse symlinks")
    if any(root.is_relative_to(Path(path)) for path in ("/opt", "/var/lib/oiran")):
        raise ValueError("managed cache must be outside deployment and capture trees")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.stat(follow_symlinks=False)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("managed cache root must be private and owned by the caller")
    return root


@contextmanager
def lock_file(path, operation, parent_fd=None):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    try:
        try:
            fcntl.flock(fd, operation)
        except BlockingIOError as error:
            raise CacheBusy from error
        yield fd
    finally:
        os.close(fd)


def stamp_info(target):
    try:
        folder = target.stat(follow_symlinks=False)
        if not stat.S_ISDIR(folder.st_mode) or target.is_mount():
            return None
        stamp = (target / STAMP).stat(follow_symlinks=False)
        if stat.S_ISREG(stamp.st_mode) and folder.st_uid == stamp.st_uid == os.getuid():
            return stamp
    except FileNotFoundError:
        pass
    return None


class MountedCachePath(Exception):
    pass


@contextmanager
def directory_fd(path, parent_fd=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def mount_id(fd):
    # st_dev and os.path.ismount() cannot identify same-device bind mounts.
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as info:
        for line in info:
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1])
    raise OSError("cannot determine mount boundary for Cargo expiry")


def remove_open_directory(parent_fd, name, fd, cache_mount, preserve_stamp=False):
    if mount_id(fd) != cache_mount:
        raise MountedCachePath(name)
    with os.scandir(fd) as entries:
        for entry in entries:
            if preserve_stamp and entry.name == STAMP:
                continue
            if entry.is_dir(follow_symlinks=False):
                with directory_fd(entry.name, fd) as child:
                    remove_open_directory(fd, entry.name, child, cache_mount)
            else:
                # unlink removes links themselves and refuses mounted files.
                os.unlink(entry.name, dir_fd=fd)
    if preserve_stamp:
        os.unlink(STAMP, dir_fd=fd)
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    opened = os.fstat(fd)
    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise OSError(f"Cargo directory replaced during expiry: {name}")
    os.rmdir(name, dir_fd=parent_fd)


def expire(root):
    with directory_fd(root.parent) as parent_fd, directory_fd(root.name, parent_fd) as root_fd:
        cache_mount = mount_id(root_fd)
        if cache_mount != mount_id(parent_fd):
            raise OSError("refusing to expire a mounted Cargo cache root")
        with lock_file(".lock", fcntl.LOCK_EX | fcntl.LOCK_NB, root_fd):
            cutoff = time.time() - RETENTION_SECONDS
            for name in sorted(os.listdir(root_fd)):
                if not KEY.fullmatch(name):
                    continue
                target = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if not stat.S_ISDIR(target.st_mode) or target.st_uid != os.getuid():
                    continue
                with directory_fd(name, root_fd) as target_fd:
                    opened = os.fstat(target_fd)
                    if (target.st_dev, target.st_ino, target.st_uid) != (opened.st_dev, opened.st_ino, opened.st_uid):
                        raise OSError(f"Cargo target replaced before expiry: {name}")
                    if mount_id(target_fd) != cache_mount:
                        print(f"cargo-target-expiry retained mounted target {name}", file=sys.stderr)
                        continue
                    try:
                        stamp = os.stat(STAMP, dir_fd=target_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if not stat.S_ISREG(stamp.st_mode) or stamp.st_uid != os.getuid() or stamp.st_mtime >= cutoff:
                        continue
                    try:
                        remove_open_directory(root_fd, name, target_fd, cache_mount, preserve_stamp=True)
                    except MountedCachePath:
                        print(f"cargo-target-expiry retained target with mounted directory {name}", file=sys.stderr)
                        continue
                    print(f"cargo-target-expired {name}", file=sys.stderr)



def run_cargo(root, key, args):
    if not KEY.fullmatch(key) or not args or args[0] not in ("build", "test", "check"):
        raise ValueError("expected a cache key and a Cargo build, test or check command")
    if any(arg == "--target-dir" or arg.startswith("--target-dir=") for arg in args):
        raise ValueError("the managed cache supplies CARGO_TARGET_DIR")
    try:
        expire(root)
    except CacheBusy:
        pass  # A running build takes priority over this opportunistic sweep.

    with lock_file(root / ".lock", fcntl.LOCK_SH) as lifetime_lock:
        target = root / key
        with lock_file(root / ".create-lock", fcntl.LOCK_EX):
            try:
                target.mkdir(mode=0o700)
            except FileExistsError:
                if stamp_info(target) is None:
                    raise ValueError(f"refusing unmanaged Cargo target: {target}")
            (target / STAMP).touch()
        try:
            return subprocess.run(
                ["cargo", *args],
                env=dict(os.environ, CARGO_TARGET_DIR=str(target)),
                pass_fds=(lifetime_lock,),
            ).returncode
        finally:
            (target / STAMP).touch()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("expire")
    run = commands.add_parser("run")
    run.add_argument("key")
    run.add_argument("cargo_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        root = cache_root()
        if args.command == "expire":
            expire(root)
            return 0
        cargo_args = args.cargo_args
        if cargo_args[:1] == ["--"]:
            cargo_args = cargo_args[1:]
        return run_cargo(root, args.key, cargo_args)
    except CacheBusy:
        print("cargo-target-expiry deferred: managed build active", file=sys.stderr)
        return 75
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"cargo-targets: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
