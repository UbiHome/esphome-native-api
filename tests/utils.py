from asyncio import sleep
import asyncio
from asyncio.subprocess import Process
import os
from subprocess import PIPE, Popen
import time
from typing import Optional


class TestServer:
                
    process: Optional[Process] = None
    _stdout_task = None
    _stderr_task = None

    async def __aenter__(self):
        my_env = os.environ.copy()
        my_env["RUST_LOG"] = "debug"
        self.process = await asyncio.create_subprocess_shell(
            "cargo run --example server",
            shell=True,
            stdout=PIPE,
            stderr=PIPE,
            env=my_env,
            cwd=os.path.join(__file__, ".."),
        )

        self._stdout_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._read_stderr())

        await sleep(2)
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
                    
            self.process = None

    async def _read_stdout(self):
        """Read and print stdout from the server process."""
        if not self.process or not self.process.stdout:
            return
        
        while True:
            line = await self.process.stdout.readline()
            if not line:
                break
            message = line.decode('utf-8').rstrip()
            print(f"[SERVER] {message}")

    async def _read_stderr(self):
        """Read and print stderr from the server process."""
        if not self.process or not self.process.stderr:
            return
            
        while True:
            line = await self.process.stderr.readline()
            if not line:
                break
            message = line.decode('utf-8').rstrip()
            print(f"[SERVER] {message}")