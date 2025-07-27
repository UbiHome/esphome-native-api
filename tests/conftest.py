import asyncio
from asyncio.subprocess import Process
import os
import socket
from typing import Optional

import pytest


class EspHomeTestServer:
    """A context manager to run a test server in the background."""

    process: Optional[Process] = None
    _stdout_task = None
    _stderr_task = None
    noise_psk = "px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA="

    def __init__(self, name: str = "test_server", port: int = 7000):
        self.name = name
        self.port = port

    async def __aenter__(self):
        my_env = os.environ.copy()
        my_env["RUST_LOG"] = "debug"
        my_env["RUSTFLAGS"] = "-Awarnings"
        self.process = await asyncio.create_subprocess_shell(
            f"cargo run --example {self.name}",
            env=my_env,
            cwd=os.path.join(os.getcwd(), ".."),
        )

        self._stdout_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._read_stderr())

        print("Waiting for server to start...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            result = sock.connect_ex(('127.0.0.1', self.port))
            if result == 0:
                print("Port is open")
                break
            else:
                await asyncio.sleep(0.1)
        sock.close()

        return self

    async def __aexit__(self, exctype, value, tb):
        print("killing process...")

        if self.process:

            # Try to terminate gracefully
            self.process.terminate()
            try:
                print("waiting...")
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                print("Force killing process...")
                self.process.kill()
                await self.process.wait()

            print("remove readers...")
            # Cancel the stdout/stderr reading tasks
            if self._stdout_task:
                self._stdout_task.cancel()
                try:
                    await self._stdout_task
                except asyncio.CancelledError:
                    pass

            if self._stderr_task:
                self._stderr_task.cancel()
                try:
                    await self._stderr_task
                except asyncio.CancelledError:
                    pass
            # Works on windows?!
            # os.kill(self.process.pid, signal.CTRL_BREAK_EVENT)

            # self.process = None

    async def _read_stdout(self):
        """Read and print stdout from the server process."""

        while True:
            if not self.process or not self.process.stdout:
                return
            line = await self.process.stdout.readline()
            if not line:
                break
            message = line.decode('utf-8').rstrip()
            print(f"[SERVER] {message}")

    async def _read_stderr(self):
        """Read and print stderr from the server process."""

        while True:
            if not self.process or not self.process.stderr:
                return
            line = await self.process.stderr.readline()
            if not line:
                break
            message = line.decode('utf-8').rstrip()
            print(f"[SERVER] {message}")


@pytest.fixture
async def test_server():
    """Fixture to run the test server."""
    async with EspHomeTestServer() as s:
        yield s


@pytest.fixture
async def encrypted_server():
    """Fixture to run the test encrypted_server."""
    async with EspHomeTestServer("encrypted_server", port=7001) as s:
        yield s


@pytest.fixture
async def password_server():
    """Fixture to run the test password_server."""
    async with EspHomeTestServer("password_server", port=7002) as s:
        yield s
