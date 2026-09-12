from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CommandResult:

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 120.0) -> CommandResult: ...


class SubprocessRunner:

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 120.0) -> CommandResult:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(list(argv), proc.returncode, proc.stdout, proc.stderr)
