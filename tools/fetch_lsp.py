"""Download the language servers shgrep starts without any user configuration.

Build-time step, run once per output folder: python tools/fetch_lsp.py dist
Installs <folder>/lsp/{lua,xml,clangd,rust,python,csharp}; shgrep.exe in <folder> finds them by itself.
OmniSharp (csharp) also needs the .NET 10 or newer SDK on the machine; shgrep reports it when missing.
Every archive is pinned to an exact upstream release and SHA-256. Nothing is installed globally.
python tools/fetch_lsp.py --resolve prints the newest upstream releases and digests for bumping PINS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import urllib.parse
import urllib.request
import uuid
import zipfile

# CONTRACT: exe paths must match bundled_servers() in src/lsp.cpp. A zip whose entries share one top folder is unpacked
#   without it; "find" moves the one matching .exe to "exe" when the archive keeps it elsewhere.
PINS = {
    "lua": {"version": "3.19.2", "exe": "bin/lua-language-server.exe",
            "url": "https://github.com/LuaLS/lua-language-server/releases/download/3.19.2/lua-language-server-3.19.2-win32-x64.zip",
            "sha256": "4a3dc851b3b31e7b75a23f645d1ba4a2137579a55f5fa4edbb17a3e2a6254044"},
    "xml": {"version": "0.29.3", "exe": "lemminx.exe", "find": "lemminx",
            "url": "https://github.com/redhat-developer/vscode-xml/releases/download/0.29.3/lemminx-win32.zip",
            "sha256": "7eaefaac68253b0ec8e0ad1f1c0f2d0755423d4e99e52497428b52f80df28eb7"},
    "clangd": {"version": "23.1.0", "exe": "bin/clangd.exe",
               "url": "https://github.com/clangd/clangd/releases/download/23.1.0/clangd-windows-23.1.0.zip",
               "sha256": "23412a240756a162e7b98a282f36aa2a23a88db5ce16a0cbc4fef7253768c810"},
    "rust": {"version": "2026-10-12", "exe": "rust-analyzer.exe", "find": "rust-analyzer",
             "url": "https://github.com/rust-lang/rust-analyzer/releases/download/2026-10-12/rust-analyzer-x86_64-pc-windows-msvc.zip",
             "sha256": "77f7a907f0e6f179281bac38e2d08435c974db9a5b99de52c5c963aff52883ec"},
    "python": {"version": "0.0.89", "exe": "ty.exe", "find": "ty",
               "url": "https://github.com/astral-sh/ty/releases/download/0.0.89/ty-x86_64-pc-windows-msvc.zip",
               "sha256": "59232824e08b30b5aed11bab9a2d1296eab75c736938f6b8884e4597700a0fb2"},
    # OmniSharp 2 is framework-dependent: it runs on the machine's .NET 10+ runtime and loads projects with its SDK.
    "csharp": {"version": "v2.0.0", "exe": "OmniSharp.exe",
               "url": "https://github.com/OmniSharp/omnisharp-roslyn/releases/download/v2.0.0/omnisharp-win-x64.zip",
               "sha256": "05e961233b4b620f46e6bd46d762122e3008f49b01e6fd31c8d7a70e917f7bfb"},
}
ALLOWED_HOSTS = {"github.com", "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


def fetch(url, accept="*/*"):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise RuntimeError(f"Unsupported download URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "shgrep-fetch-lsp", "Accept": accept})
    response = urllib.request.urlopen(request, timeout=120)
    final = urllib.parse.urlsplit(response.url)
    if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
        response.close()
        raise RuntimeError(f"Unsupported download redirect: {response.url}")
    return response


def digest_stream(stream, output=None):
    value = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(chunk)
        if output:
            output.write(chunk)
    return value.hexdigest()


def download(url, expected, cache):
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise RuntimeError(f"No usable SHA-256 pinned for {url}; run --resolve and fill PINS")
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / f"{expected}.zip"
    if target.is_file():
        with target.open("rb") as stream:
            if digest_stream(stream) == expected:
                return target
    temporary = cache / f"{expected}.{uuid.uuid4().hex}.part"
    try:
        print(f"Downloading {url}", flush=True)
        with fetch(url) as response, temporary.open("xb") as output:
            actual = digest_stream(response, output)
        if actual != expected:
            raise RuntimeError(f"SHA-256 mismatch for {url}: expected {expected}, received {actual}")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def unpack(package, destination):
    with zipfile.ZipFile(package) as bundle:
        # SAFETY: validate every entry before extracting any of them.
        entries = []
        for item in bundle.infolist():
            parts = PurePosixPath(item.filename.replace("\\", "/"))
            if parts.is_absolute() or ".." in parts.parts or ":" in item.filename:
                raise RuntimeError(f"Unsafe archive entry: {item.filename}")
            if stat.S_ISLNK(item.external_attr >> 16):
                raise RuntimeError(f"Archive link is unsupported: {item.filename}")
            entries.append((item, parts.parts))
        files = [parts for item, parts in entries if not item.is_dir()]
        strip = 1 if files and all(len(parts) > 1 and parts[0] == files[0][0] for parts in files) else 0
        entries = [(item, parts[strip:]) for item, parts in entries if len(parts) > strip]
        for item, parts in entries:
            target = destination.joinpath(*parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)


def install(name, pin, servers, cache):
    package = download(pin["url"], pin["sha256"], cache)
    staging = servers / f".{name}.{uuid.uuid4().hex}"
    staging.mkdir(parents=True)
    try:
        unpack(package, staging)
        executable = staging.joinpath(*pin["exe"].split("/"))
        if not executable.is_file() and pin.get("find"):
            found = [path for path in staging.rglob("*.exe") if path.stem.lower().startswith(pin["find"])]
            if len(found) != 1:
                raise RuntimeError(f"Expected one {pin['find']} executable in {pin['url']}, found {found}")
            executable.parent.mkdir(parents=True, exist_ok=True)
            os.replace(found[0], executable)
        if not executable.is_file():
            raise RuntimeError(f"{pin['url']} has no {pin['exe']}")
        with executable.open("rb") as stream:
            executable_sha256 = digest_stream(stream)
        final = servers / name
        retired = servers / f".{name}.old.{uuid.uuid4().hex}"
        if final.exists():
            os.replace(final, retired)
        os.replace(staging, final)
        shutil.rmtree(retired, ignore_errors=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return executable_sha256


def github_latest(repo):
    with fetch(f"https://api.github.com/repos/{repo}/releases/latest", "application/vnd.github+json") as response:
        return json.load(response)


def asset_digest(asset):
    value = asset.get("digest") or ""
    if value.startswith("sha256:"):
        return value.removeprefix("sha256:").lower()
    with fetch(asset["browser_download_url"]) as response:
        return digest_stream(response)


def resolve():
    choices = {
        "lua": ("LuaLS/lua-language-server", lambda n: n.endswith("-win32-x64.zip")),
        "clangd": ("clangd/clangd", lambda n: n.startswith("clangd-windows-") and n.endswith(".zip")),
        "rust": ("rust-lang/rust-analyzer", lambda n: n == "rust-analyzer-x86_64-pc-windows-msvc.zip"),
        "python": ("astral-sh/ty", lambda n: n == "ty-x86_64-pc-windows-msvc.zip"),
        "csharp": ("OmniSharp/omnisharp-roslyn", lambda n: n == "omnisharp-win-x64.zip"),
    }
    found = {}
    for name, (repo, wanted) in choices.items():
        try:
            release = github_latest(repo)
            asset = next(item for item in release["assets"] if wanted(item["name"]))
            found[name] = {"version": release["tag_name"], "url": asset["browser_download_url"], "sha256": asset_digest(asset)}
        except Exception as error:
            found[name] = {"error": str(error)}
    # LemMinX binaries ship as vscode-xml release assets; the rolling "latest" tag is skipped because it is not pinnable.
    try:
        with fetch("https://api.github.com/repos/redhat-developer/vscode-xml/releases?per_page=10",
                   "application/vnd.github+json") as response:
            releases = json.load(response)
        release = next(item for item in releases if item["tag_name"] != "latest" and not item["prerelease"])
        asset = next(item for item in release["assets"] if item["name"] == "lemminx-win32.zip")
        found["xml"] = {"version": release["tag_name"], "url": asset["browser_download_url"], "sha256": asset_digest(asset)}
    except Exception as error:
        found["xml"] = {"error": str(error)}
    print(json.dumps(found, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("folder", type=Path, nargs="?", help="Folder holding shgrep.exe, for example dist")
    parser.add_argument("--resolve", action="store_true", help="Print newest upstream releases instead of installing")
    parser.add_argument("--only", choices=sorted(PINS), action="append", help="Install only these servers")
    args = parser.parse_args()
    if args.resolve:
        return resolve()
    if args.folder is None:
        parser.error("folder is required")
    if sys.platform != "win32":
        parser.error("The bundled servers are Windows x64 builds")
    folder = args.folder.resolve()
    servers = folder / "lsp"
    servers.mkdir(parents=True, exist_ok=True)
    cache = servers / ".downloads"
    manifest_path = servers / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    for name in args.only or PINS:
        pin = PINS[name]
        installed = manifest.get(name, {})
        executable = servers / name / pin["exe"]
        if installed.get("archive_sha256") == pin["sha256"] and executable.is_file():
            print(f"{name} {pin['version']} already installed")
            continue
        manifest[name] = {"version": pin["version"], "url": pin["url"], "archive_sha256": pin["sha256"],
                          "exe": pin["exe"], "exe_sha256": install(name, pin, servers, cache)}
        print(f"Installed {name} {pin['version']}")
        temporary = manifest_path.with_name(f"manifest.{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, manifest_path)
    shutil.rmtree(cache, ignore_errors=True)
    print(f"Language servers ready in {servers}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"fetch_lsp failed: {error}")
