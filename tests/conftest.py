from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

import pytest

# Fixed base flags so compiled fixtures behave the same on every host.
# Callers must pass an explicit PIE choice ("-pie" or "-no-pie") because
# gcc's default varies by distro/version and changes binary layout.
BASE_FLAGS: List[str] = ["-O0", "-g0", "-fno-stack-protector"]


def _gcc() -> str:
    exe = shutil.which("gcc")
    if exe is None:
        pytest.skip("gcc not available")
    return exe


def compile_c(
    src: str,
    name: str,
    flags: Optional[List[str]] = None,
    dest_dir: Optional[Path] = None,
) -> Path:
    """Compile C source deterministically, rebuilding only when needed.

    The binary is (re)compiled when the hash of ``src`` + ``flags``
    differs from the ``<name>.sha256`` sidecar next to it.  This fixes
    the stale-cache trap where editing the source had no effect because
    an old ``/tmp`` binary was reused.
    """
    dst_dir = dest_dir or Path(tempfile.gettempdir()) / "angrsolve_tests"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / name
    sidecar = dst_dir / f"{name}.sha256"

    digest = hashlib.sha256(
        (src + "\x00" + " ".join(flags or [])).encode()
    ).hexdigest()

    if dst.exists() and sidecar.exists() and sidecar.read_text().strip() == digest:
        return dst

    cmd = [_gcc(), *BASE_FLAGS]
    if flags:
        cmd.extend(flags)
    cmd.extend(["-o", str(dst), "-x", "c", "-"])
    subprocess.run(
        cmd,
        input=src,
        capture_output=True,
        text=True,
        check=True,
    )
    sidecar.write_text(digest)
    return dst


@pytest.fixture(scope="session")
def argv_binary() -> Path:
    src = r"""
#include <stdio.h>
#include <string.h>
void win(void) { puts("win"); }
void fail(void) { puts("lose"); }
int main(int argc, char **argv) {
    if (argc < 2) { fail(); return 1; }
    if (strcmp(argv[1], "s3cr3t") == 0) { win(); }
    else { fail(); }
    return 0;
}
"""
    return compile_c(src, "test_argv_bin", flags=["-no-pie"])


@pytest.fixture(scope="session")
def stdin_binary() -> Path:
    src = r"""
#include <stdio.h>
#include <string.h>
void win(void) { puts("win"); }
void fail(void) { puts("lose"); }
int main(void) {
    char buf[64];
    if (fgets(buf, 64, stdin) == NULL) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (strcmp(buf, "s3cr3t") == 0) { win(); }
    else { fail(); }
    return 0;
}
"""
    return compile_c(src, "test_stdin_bin", flags=["-no-pie"])


@pytest.fixture(scope="session")
def file_binary() -> Path:
    src = r"""
#include <stdio.h>
#include <string.h>
void win(void) { puts("win"); }
int main(void) {
    char buf[64];
    FILE *f = fopen("flag.txt", "r");
    if (!f) return 1;
    fgets(buf, 64, f);
    fclose(f);
    if (strncmp(buf, "s3cr3t", 6) == 0) { win(); }
    else { puts("fail"); }
    return 0;
}
"""
    return compile_c(src, "test_file_bin", flags=["-no-pie"])


@pytest.fixture(scope="session")
def pie_binary() -> Path:
    src = r"""
#include <stdio.h>
#include <string.h>
void win(void) { puts("win"); }
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    if (strcmp(argv[1], "secret") == 0) { win(); }
    return 0;
}
"""
    return compile_c(src, "test_pie_bin", flags=["-pie"])


@pytest.fixture(scope="session")
def nostdlib_binary() -> Path:
    """A minimal binary with NO libc symbols for testing auto-avoid failure."""
    src = r"""
void _start(void) {
    __asm__("mov $60, %%eax; xor %%edi, %%edi; syscall" ::: "eax", "edi");
}
"""
    return compile_c(src, "test_nostdlib_bin", flags=["-nostdlib"])
