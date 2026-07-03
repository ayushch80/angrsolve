from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Generator

import pytest


def _compile_c(src: str, name: str) -> Path:
    dst = Path(tempfile.gettempdir()) / name
    if dst.exists():
        return dst
    subprocess.run(
        ["gcc", "-o", str(dst), "-x", "c", "-"],
        input=src,
        capture_output=True,
        text=True,
        check=True,
    )
    return dst


@pytest.fixture(scope="session")
def argv_binary() -> Generator[Path, None, None]:
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
    yield _compile_c(src, "test_argv_bin")


@pytest.fixture(scope="session")
def stdin_binary() -> Generator[Path, None, None]:
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
    yield _compile_c(src, "test_stdin_bin")


@pytest.fixture(scope="session")
def file_binary() -> Generator[Path, None, None]:
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
    yield _compile_c(src, "test_file_bin")


@pytest.fixture(scope="session")
def pie_binary() -> Generator[Path, None, None]:
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
    dst = Path(tempfile.gettempdir()) / "test_pie_bin"
    if not dst.exists():
        subprocess.run(
            ["gcc", "-pie", "-fno-stack-protector", "-o", str(dst), "-x", "c", "-"],
            input=src,
            capture_output=True,
            text=True,
            check=True,
        )
    yield dst


@pytest.fixture(scope="session")
def nostdlib_binary() -> Generator[Path, None, None]:
    """A minimal binary with NO libc symbols for testing auto-avoid failure."""
    src = r"""
void _start(void) {
    __asm__("mov $60, %%eax; xor %%edi, %%edi; syscall" ::: "eax", "edi");
}
"""
    dst = Path(tempfile.gettempdir()) / "test_nostdlib_bin"
    if not dst.exists():
        subprocess.run(
            ["gcc", "-nostdlib", "-o", str(dst), "-x", "c", "-"],
            input=src,
            capture_output=True,
            text=True,
            check=True,
        )
    yield dst
