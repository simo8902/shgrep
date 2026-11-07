#!/usr/bin/env python3
"""Install pinned Windows x64 language servers beside shgrep."""
import argparse
import base64
from collections.abc import Callable
import functools
import hashlib
import http.client
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

# Archive hashes are pinned independently of the downloaded files.
PINS = {
    "lua": ("https://github.com/LuaLS/lua-language-server/releases/download/3.19.2/lua-language-server-3.19.2-win32-x64.zip",
            "4a3dc851b3b31e7b75a23f645d1ba4a2137579a55f5fa4edbb17a3e2a6254044", "bin/lua-language-server.exe"),
    "xml": ("https://github.com/redhat-developer/vscode-xml/releases/download/0.29.3/lemminx-win32.zip",
            "7eaefaac68253b0ec8e0ad1f1c0f2d0755423d4e99e52497428b52f80df28eb7", "lemminx.exe"),
    "clangd": ("https://github.com/clangd/clangd/releases/download/23.1.0/clangd-windows-23.1.0.zip",
               "23412a240756a162e7b98a282f36aa2a23a88db5ce16a0cbc4fef7253768c810", "bin/clangd.exe"),
    "rust": ("https://github.com/rust-lang/rust-analyzer/releases/download/2026-10-12/rust-analyzer-x86_64-pc-windows-msvc.zip",
             "77f7a907f0e6f179281bac38e2d08435c974db9a5b99de52c5c963aff52883ec", "rust-analyzer.exe"),
    "python": ("https://github.com/astral-sh/ty/releases/download/0.0.89/ty-x86_64-pc-windows-msvc.zip",
               "59232824e08b30b5aed11bab9a2d1296eab75c736938f6b8884e4597700a0fb2", "ty.exe"),
    "cmake": ("https://github.com/neocmakelsp/neocmakelsp/releases/download/v0.11.2/neocmakelsp-x86_64-pc-windows-msvc.zip",
              "011aedd26fa5855490b612280482832ad10367ab4807d4e89f2d6fa4f8bae3cb", "neocmakelsp.exe"),
}
# JavaScript/TypeScript: node.exe from the pinned Node.js LTS zip, plus the npm tarballs of typescript-language-server
# and typescript, verified against their registry integrity. npm itself never runs, so nothing else is fetched.
NODE = ("https://nodejs.org/dist/v26.13.0/node-v26.13.0-win-x64.zip",
        "dcc60d59a0746999f99064a01c020445d54d84228c691cdbf25b49ac3b59150a", "node.exe")
NPM_PACKAGES = {
    "typescript-language-server": (
        "https://registry.npmjs.org/typescript-language-server/-/typescript-language-server-6.0.2.tgz",
        "sha512-Ph7Ql+xkUJvMamnkh1h+aKP6HxLR7lrWIYkPn9/LZBkJdJZgtIj7OoVhkDYtQ7zFPTPmqZHOVXaUKGyz9M2q1Q=="),
    "typescript": (
        "https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz",
        "sha512-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdBw=="),
}
ROSLYN_VERSION = "5.13.0-1.26514.10"
MAX_DOWNLOAD = 1024 * 1024 * 1024
MAX_UNPACKED = 2 * 1024 * 1024 * 1024
DOWNLOAD_ATTEMPTS = 3


def download(url, target, expected, algorithm="sha256"):
    # Network failures (timeouts, resets, 5xx, 429) are retried; a wrong hash or a 4xx answer is not.
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            actual = fetch(url, target, algorithm)
            break
        except (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError) as error:
            target.unlink(missing_ok=True)
            permanent = isinstance(error, urllib.error.HTTPError) and error.code < 500 and error.code != 429
            if permanent or attempt == DOWNLOAD_ATTEMPTS:
                raise RuntimeError("download failed after " + str(attempt) + " attempt(s): " + url + ": " + str(error)) from error
            print("  retry " + str(attempt) + "/" + str(DOWNLOAD_ATTEMPTS - 1) + " after: " + str(error), flush=True)
            time.sleep(2 * attempt)
    if actual != expected:
        raise RuntimeError("archive " + algorithm.upper() + " mismatch: " + url)


def fetch(url, target, algorithm):
    digest = hashlib.new(algorithm)
    total = 0
    request = urllib.request.Request(url, headers={"User-Agent": "shgrep-language-server-installer"})
    with urllib.request.urlopen(request, timeout=60) as response, target.open("xb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD:
                raise RuntimeError("download exceeds size limit")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest() if algorithm == "sha256" else "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


def unpack(archive, directory):
    with zipfile.ZipFile(archive) as zf:
        entries = zf.infolist()
        if len(entries) > 100000 or sum(entry.file_size for entry in entries) > MAX_UNPACKED:
            raise RuntimeError("archive exceeds extraction limits")
        seen = set()
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            path = PurePosixPath(name)
            parts = path.parts
            if (not parts or name.startswith("/") or any(part in ("", ".", "..") for part in parts)
                    or ":" in name or stat.S_ISLNK(entry.external_attr >> 16)):
                raise RuntimeError("unsafe path in archive: " + name)
            key = name.rstrip("/").casefold()
            if key in seen:
                raise RuntimeError("duplicate path in archive: " + name)
            seen.add(key)
            target = directory.joinpath(*parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(entry) as source, target.open("xb") as out:
                    shutil.copyfileobj(source, out, 1024 * 1024)


def install_zip(root, name, pin):
    url, digest, executable = pin
    destination = root / name
    if destination.exists():
        if (destination / executable).is_file():
            print(name + ": already installed")
            return
        raise RuntimeError("refusing to replace existing incomplete directory: " + str(destination))
    with tempfile.TemporaryDirectory(prefix=".shgrep-lsp-", dir=root) as temporary:
        temporary = Path(temporary)
        archive = temporary / "server.zip"
        extracted = temporary / "extracted"
        extracted.mkdir()
        print(name + ": downloading", flush=True)
        download(url, archive, digest)
        unpack(archive, extracted)
        parts = PurePosixPath(executable).parts
        matches = [p for p in extracted.rglob(parts[-1])
                   if p.is_file() and tuple(p.relative_to(extracted).parts[-len(parts):]) == parts]
        if len(matches) != 1:
            raise RuntimeError("archive does not contain exactly one " + executable)
        source = matches[0]
        for _ in parts:
            source = source.parent
        os.rename(source, destination)
        print(name + ": installed")


def unpack_npm(archive, directory):
    """Extract an npm tarball's package/ tree into directory: regular files and folders only."""
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > 100000 or sum(member.size for member in members) > MAX_UNPACKED:
            raise RuntimeError("archive exceeds extraction limits")
        seen = set()
        for member in members:
            name = member.name.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if (len(parts) < 2 or parts[0] != "package" or name.startswith("/") or ":" in name
                    or any(part in ("", ".", "..") for part in parts)):
                raise RuntimeError("unsafe path in npm archive: " + name)
            if not (member.isfile() or member.isdir()):
                raise RuntimeError("npm archive entry is not a file or folder: " + name)
            key = "/".join(parts[1:]).casefold()
            if key in seen:
                raise RuntimeError("duplicate path in npm archive: " + name)
            seen.add(key)
            target = directory.joinpath(*parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise RuntimeError("cannot read npm archive entry: " + name)
            with source, target.open("xb") as out:
                shutil.copyfileobj(source, out, 1024 * 1024)


def install_typescript(root):
    destination = root / "typescript"
    server = destination / "node_modules" / "typescript-language-server" / "lib" / "cli.mjs"
    if destination.exists():
        if (destination / "node.exe").is_file() and server.is_file():
            print("typescript: already installed")
            return
        raise RuntimeError("refusing to replace existing incomplete directory: " + str(destination))
    with tempfile.TemporaryDirectory(prefix=".shgrep-typescript-", dir=root) as temporary:
        temporary = Path(temporary)
        staged = temporary / "typescript"
        modules = staged / "node_modules"
        modules.mkdir(parents=True)
        url, digest, executable = NODE
        print("typescript: downloading Node.js", flush=True)
        download(url, temporary / "node.zip", digest)
        extracted = temporary / "node"
        extracted.mkdir()
        unpack(temporary / "node.zip", extracted)
        matches = [p for p in extracted.rglob(executable) if p.is_file() and len(p.relative_to(extracted).parts) == 2]
        if len(matches) != 1:
            raise RuntimeError("Node.js archive does not contain exactly one top-level " + executable)
        os.rename(matches[0], staged / executable)
        for name, (url, integrity) in NPM_PACKAGES.items():
            print("typescript: downloading " + name, flush=True)
            archive = temporary / (name + ".tgz")
            download(url, archive, integrity, "sha512")
            unpack_npm(archive, modules / name)
        if not (modules / "typescript" / "lib" / "tsserver.js").is_file() or not (staged / "node_modules" /
                "typescript-language-server" / "lib" / "cli.mjs").is_file():
            raise RuntimeError("TypeScript packages are missing tsserver.js or the language server entry point")
        os.rename(staged, destination)
        print("typescript: installed")


def install_roslyn(root):
    destination = root / "csharp" / "roslyn"
    if destination.exists():
        if (destination / "Microsoft.CodeAnalysis.LanguageServer.exe").is_file():
            print("csharp: already installed")
            return
        raise RuntimeError("refusing to replace existing incomplete directory: " + str(destination))
    dotnet = shutil.which("dotnet")
    if not dotnet:
        raise RuntimeError("Roslyn requires the .NET 10 SDK on PATH")
    with tempfile.TemporaryDirectory(prefix=".shgrep-roslyn-", dir=root) as temporary:
        temporary = Path(temporary)
        print("csharp: installing Roslyn " + ROSLYN_VERSION, flush=True)
        subprocess.run([dotnet, "tool", "install", "roslyn-language-server", "--version", ROSLYN_VERSION,
                        "--tool-path", str(temporary / "tool")], check=True)
        matches = list((temporary / "tool").rglob("Microsoft.CodeAnalysis.LanguageServer.exe"))
        if len(matches) != 1:
            raise RuntimeError("Roslyn package does not contain exactly one server executable")
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.rename(matches[0].parent, destination)
        print("csharp: installed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="directory where the lsp folder will be created")
    args = parser.parse_args()
    root = args.root.resolve() / "lsp"
    root.mkdir(parents=True, exist_ok=True)
    installers: list[tuple[str, Callable[[], object]]] = [(name, functools.partial(install_zip, root, name, pin)) for name, pin in PINS.items()]
    installers.append(("typescript", functools.partial(install_typescript, root)))
    installers.append(("csharp", functools.partial(install_roslyn, root)))
    # Each server installs on its own: one failed download must not stop the others. A failed server leaves no
    # folder behind (it is staged in a temporary directory), so a later run retries only what is missing.
    failed = []
    for name, install in installers:
        try:
            install()
        except Exception as error:
            failed.append(name)
            print(name + ": FAILED: " + (str(error) or type(error).__name__), file=sys.stderr, flush=True)
    if failed:
        print("shgrep LSP installer: " + str(len(failed)) + " of " + str(len(installers)) + " servers failed (" +
              ", ".join(failed) + "); the others are installed. Run the same command again to retry them.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:  # the lsp folder itself could not be created
        print("shgrep LSP installer: " + str(error), file=sys.stderr)
        sys.exit(1)
