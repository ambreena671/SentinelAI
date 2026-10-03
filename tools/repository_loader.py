import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_FILES = 250

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".cs",
    ".go", ".rb", ".rs", ".kt", ".kts", ".swift", ".c", ".h",
    ".cpp", ".hpp", ".cc", ".hh", ".m", ".mm", ".scala", ".sh",
    ".bash", ".sql", ".html", ".htm", ".css", ".scss", ".vue",
    ".svelte", ".dart", ".lua", ".r", ".pl", ".ex", ".exs",
}

SKIP_DIRS = {
    ".git", ".github", "node_modules", "vendor", "dist", "build",
    ".next", ".nuxt", "coverage", "__pycache__", ".venv", "venv",
    "env", ".idea", ".vscode", "target", "bin", "obj",
}


def parse_github_url(repo_url: str) -> Tuple[str, str]:
    """Return (owner, repo) for a public/private GitHub repository URL."""
    value = repo_url.strip()
    match = re.match(
        r"^https?://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?(?:#.*)?$",
        value,
        re.IGNORECASE,
    )
    if not match:
        raise ValueError(
            "Enter a GitHub repository URL such as https://github.com/owner/repository"
        )
    owner, repo = match.group(1), match.group(2)
    if owner in {"", ".", ".."} or repo in {"", ".", ".."}:
        raise ValueError("Invalid GitHub repository URL")
    return owner, repo


def _github_headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SentinelAI-Code-Security-Scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _download_to_file(url: str, destination: str, token: Optional[str] = None) -> int:
    headers = _github_headers(token)
    with requests.get(url, headers=headers, stream=True, timeout=(10, 60), allow_redirects=True) as response:
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_ARCHIVE_BYTES:
            raise ValueError("Repository archive is larger than the 25 MB download limit.")

        total = 0
        with open(destination, "wb") as output:
            for chunk in response.iter_content(chunk_size=1024 * 128):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("Repository archive exceeded the 25 MB download limit.")
                output.write(chunk)
    return total


def _safe_extract_zip(zip_path: str, destination: str) -> None:
    destination_root = Path(destination).resolve()
    extracted_bytes = 0
    extracted_files = 0

    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or "../" in name.split("/"):
                raise ValueError("Repository archive contains an unsafe path.")

            target = (destination_root / name).resolve()
            if os.path.commonpath([str(destination_root), str(target)]) != str(destination_root):
                raise ValueError("Repository archive contains an unsafe path.")

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            # Do not extract symlinks or other special ZIP entries.
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ValueError("Repository archive contains a symbolic link and was rejected.")

            extracted_files += 1
            extracted_bytes += info.file_size
            if extracted_files > MAX_FILES:
                raise ValueError(f"Repository contains more than {MAX_FILES} files.")
            if extracted_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError("Repository expands beyond the 100 MB extraction limit.")

            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 128)


def clone_github_repository(repo_url: str, token: Optional[str] = None) -> Tuple[str, Dict[str, str]]:
    """Download a GitHub repository as an archive into a temporary directory.

    No project code is executed. Public repositories work without a token;
    a GitHub token may be supplied for repositories accessible to that token.
    """
    owner, repo = parse_github_url(repo_url)
    headers = _github_headers(token)
    api_url = f"https://api.github.com/repos/{owner}/{repo}"

    response = requests.get(api_url, headers=headers, timeout=20)
    if response.status_code == 404:
        raise ValueError("GitHub repository was not found or is not accessible with the supplied token.")
    response.raise_for_status()
    metadata = response.json()

    default_branch = metadata.get("default_branch") or "main"
    full_name = metadata.get("full_name") or f"{owner}/{repo}"

    temp_dir = tempfile.mkdtemp(prefix="sentinelai_repo_")
    archive_path = os.path.join(temp_dir, "repository.zip")
    extract_dir = os.path.join(temp_dir, "source")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{default_branch}"
        _download_to_file(archive_url, archive_path, token=token)
        _safe_extract_zip(archive_path, extract_dir)
        os.remove(archive_path)

        # GitHub archives normally contain a single top-level directory.
        children = [p for p in Path(extract_dir).iterdir()]
        if len(children) == 1 and children[0].is_dir():
            scan_root = str(children[0])
        else:
            scan_root = extract_dir

        return scan_root, {
            "repository": full_name,
            "branch": default_branch,
            "source_url": repo_url,
        }
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def iter_source_files(root: str, max_files: int = MAX_FILES) -> List[str]:
    """Return source files suitable for static analysis, excluding generated/vendor trees."""
    root_path = Path(root).resolve()
    files: List[str] = []

    for current, dirs, filenames in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in filenames:
            path = Path(current) / filename
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    continue
            except OSError:
                continue
            files.append(str(path))
            if len(files) >= max_files:
                return files
    return files


def read_source_file(path: str, root: str, max_chars: int = 300_000) -> Tuple[str, str]:
    """Read a source file and return (relative_path, text)."""
    root_path = Path(root).resolve()
    file_path = Path(path).resolve()
    relative = os.path.relpath(file_path, root_path).replace(os.sep, "/")
    text = file_path.read_text(encoding="utf-8", errors="replace")
    if len(text) > max_chars:
        raise ValueError(f"{relative} is larger than the supported 300,000-character limit.")
    return relative, text
