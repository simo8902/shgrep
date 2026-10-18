"""User-run local Lua/XML setup. No PATH, registry, global installs, builds, or server launches.
From the workspace: python shgrep/tools/setup_lsp.py --root .
Downloads official Windows x64 releases, verifies SHA-256, preserves their bundled licenses,
then atomically merges .shgrep/lsp.json. Existing custom servers require --replace.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import sys
import urllib.parse
import urllib.request
import uuid
import zipfile

LUA_VERSION = "3.15.0"
LUA_SHA256 = "76a10c05e8c947a448f00a61acead4240484cd1e2e8c66d54401c67d99b77535"
LUA_URL = f"https://github.com/LuaLS/lua-language-server/releases/download/{LUA_VERSION}/lua-language-server-{LUA_VERSION}-win32-x64.zip"
XML_RELEASE = "https://api.github.com/repos/redhat-developer/vscode-xml/releases/tags/latest"
ALLOWED_HOSTS = {"github.com", "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
MANAGER = "shgrep/tools/setup_lsp.py"


def confined(root, path):
    # Every written path, including existing ancestors, must remain physically inside this workspace.
    path = Path(path).absolute()
    path.relative_to(root)
    current = path
    while current != root.parent:
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            raise RuntimeError(f"Refusing link or junction: {current}")
        if current == root:
            break
        current = current.parent
    path.resolve().relative_to(root)
    if "original copy of the game, dont write!" in str(path).lower():
        raise RuntimeError(f"Refusing the read-only original package: {path}")
    return path


def folder(root, path):
    path = confined(root, path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def fetch(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise RuntimeError(f"Unsupported download URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "shgrep-local-lsp-setup",
                                                  "Accept": "application/vnd.github+json" if parsed.hostname == "api.github.com" else "*/*"})
    response = urllib.request.urlopen(request, timeout=60)
    final = urllib.parse.urlsplit(response.url)
    if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
        response.close()
        raise RuntimeError(f"Unsupported download redirect: {response.url}")
    return response


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def archive(root, url, expected):
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise RuntimeError("Publisher did not supply a usable SHA-256 digest")
    cache = folder(root, root / ".shgrep" / "downloads")
    target = confined(root, cache / f"{expected}.zip")
    if target.is_file() and digest(target) == expected:
        return target
    temporary = confined(root, cache / f"{expected}.{uuid.uuid4().hex}.part")
    try:
        print(f"Downloading {url}", flush=True)
        with fetch(url) as response, temporary.open("xb") as output:
            shutil.copyfileobj(response, output)
        actual = digest(temporary)
        if actual != expected:
            raise RuntimeError(f"SHA-256 mismatch: expected {expected}, received {actual}")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def unpack(root, package, destination):
    destination = folder(root, destination)
    with zipfile.ZipFile(package) as bundle:
        # Validate the entire archive before extracting any entry.
        for item in bundle.infolist():
            parts = PurePosixPath(item.filename.replace("\\", "/"))
            if parts.is_absolute() or ".." in parts.parts or ":" in item.filename:
                raise RuntimeError(f"Unsafe archive entry: {item.filename}")
            if stat.S_ISLNK(item.external_attr >> 16):
                raise RuntimeError(f"Archive link is unsupported: {item.filename}")
            confined(root, destination.joinpath(*parts.parts))
        for item in bundle.infolist():
            parts = PurePosixPath(item.filename.replace("\\", "/"))
            target = confined(root, destination.joinpath(*parts.parts))
            if item.is_dir():
                folder(root, target)
                continue
            folder(root, target.parent)
            temporary = confined(root, target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp"))
            try:
                with bundle.open(item) as source, temporary.open("xb") as output:
                    shutil.copyfileobj(source, output)
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    temporary.unlink()


def one_executable(directory, name):
    matches = [path for path in directory.rglob("*.exe") if name.lower() in path.name.lower()]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one {name} executable in {directory}, found {matches}")
    return matches[0].resolve()


def save_json(root, path, value):
    folder(root, path.parent)
    path = confined(root, path)
    temporary = confined(root, path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp"))
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--replace", action="store_true", help="Replace conflicting custom Lua/XML server entries, retaining a backup")
    args = parser.parse_args()
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        parser.error("This setup targets native Windows x64")
    workspace = Path(__file__).resolve().parents[2]
    root = args.root.absolute()
    root.relative_to(workspace)
    root = confined(workspace, root).resolve()
    config_path = confined(root, root / ".shgrep" / "lsp.json")
    config_bytes = config_path.read_bytes() if config_path.exists() else None
    configuration = json.loads(config_bytes.decode("utf-8-sig")) if config_bytes else {"servers": []}
    if not isinstance(configuration, dict) or not isinstance(configuration.get("servers"), list):
        raise RuntimeError("Existing .shgrep/lsp.json must contain a servers array")
    keep = []
    for server in configuration["servers"]:
        extensions = {"." + ext.lower().lstrip(".") for ext in server.get("extensions", [])}
        conflict = extensions.intersection({".lua", ".xml", ".xsd", ".xsl", ".xslt", ".svg"})
        if conflict and server.get("managed_by") != MANAGER and not args.replace:
            raise RuntimeError(f"Custom server already owns {sorted(conflict)}. Use --replace to replace its entry with a backup.")
        if not conflict:
            keep.append(server)

    lua_package = archive(root, LUA_URL, LUA_SHA256)
    lua_directory = root / ".shgrep" / "servers" / f"lua-{LUA_VERSION}"
    unpack(root, lua_package, lua_directory)
    lua = one_executable(lua_directory, "lua-language-server")
    with fetch(XML_RELEASE) as response:
        release = json.load(response)
    asset = next((item for item in release["assets"] if item["name"] == "lemminx-win32.zip"), None)
    if asset is None:
        raise RuntimeError("Official vscode-xml rolling binary release has no lemminx-win32.zip asset")
    checksum = asset.get("digest") or ""
    if not checksum.startswith("sha256:"):
        raise RuntimeError("Official XML release metadata has no SHA-256 digest; configuration was not changed")
    checksum = checksum.removeprefix("sha256:").lower()
    xml_package = archive(root, asset["browser_download_url"], checksum)
    xml_directory = root / ".shgrep" / "servers" / ("xml-" + checksum[:16])
    unpack(root, xml_package, xml_directory)
    xml = one_executable(xml_directory, "lemminx")
    cache = folder(root, root / ".shgrep" / "server-state")
    lua_logs = folder(root, cache / "lua-logs")
    lua_meta = folder(root, cache / "lua-meta")
    xml_cache = folder(root, cache / "xml")
    xml_settings = {"xml": {"server": {"workDir": str(xml_cache)},
                            "logs": {"file": str(xml_cache / "lemminx.log")},
                            "telemetry": {"enabled": False},
                            "downloadExternalResources": {"enabled": False},
                            "validation": {"resolveExternalEntities": False}}}
    keep.extend([
        {"managed_by": MANAGER, "language_id": "lua", "extensions": [".lua"],
         "command": [str(lua), f"--logpath={lua_logs}", f"--metapath={lua_meta}"],
         "settings": {"Lua": {"runtime": {"version": "Lua 5.1"}, "telemetry": {"enable": False},
                              "workspace": {"checkThirdParty": False}}}},
        {"managed_by": MANAGER, "language_id": "xml", "extensions": [".xml", ".xsd", ".xsl", ".xslt", ".svg"],
         "command": [str(xml)],
         "initialization_options": {"settings": xml_settings},
         "settings": xml_settings},
    ])
    # Detect an intervening user edit before replacing configuration.
    if (config_path.read_bytes() if config_path.exists() else None) != config_bytes:
        raise RuntimeError("lsp.json changed during setup; rerun to merge the current version")
    if config_bytes is not None:
        backup = confined(root, config_path.with_name("lsp.json.before-" + uuid.uuid4().hex))
        with backup.open("xb") as stream:
            stream.write(config_bytes)
        print(f"Configuration backup: {backup}")
    configuration["servers"] = keep
    save_json(root, config_path, configuration)
    save_json(root, root / ".shgrep" / "servers" / "manifest.json",
              {"lua": {"version": LUA_VERSION, "archive_sha256": LUA_SHA256, "executable": str(lua), "sha256": digest(lua)},
               "xml": {"release": release.get("tag_name"), "archive_sha256": checksum, "executable": str(xml), "sha256": digest(xml)}})
    print(f"Configured Lua and XML: {config_path}")
    print("No servers were launched. Restart the rebuilt shgrep MCP process to use this configuration.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"Setup failed: {error}")
