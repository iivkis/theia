#!/usr/bin/env python3
"""M4.2f: drive the compiled Theia TUI in a real Linux PTY / Windows ConPTY.

Only a test tool: no fake ratatui events, injected IPC responses or snapshots.
The real compiled server and its native IPC are started by the Rust test.
"""
import argparse
import codecs
import os
import re
import subprocess
import sys
import threading
import time

import pyte

CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
OSC = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")
TIMEOUT = 12.0


class Terminal:
    def __init__(self, command):
        self.raw = ""
        self.screen = pyte.Screen(160, 42)
        self.stream = pyte.Stream(self.screen)
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.lock = threading.Lock()
        self.error = None
        self.posix_master = None
        self.win = None
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        if os.name == "nt":
            # Actual Windows ConPTY: neither pipes nor synthetic keyboard events.
            from winpty import PtyProcess

            self.win = PtyProcess.spawn(command, env=env, dimensions=(42, 160))
        else:
            import fcntl
            import pty
            import struct
            import termios

            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 42, 160, 0, 0))
            self.posix_master = master
            try:
                self.child = subprocess.Popen(
                    command, stdin=slave, stdout=slave, stderr=slave,
                    close_fds=True, start_new_session=True, env=env,
                )
            finally:
                os.close(slave)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            if self.win:
                while self.win.isalive():
                    chunk = self.win.read()
                    if chunk:
                        with self.lock:
                            text = chunk if isinstance(chunk, str) else self.decoder.decode(chunk)
                            self.raw += text
                            self.stream.feed(text)
            else:
                import select

                while True:
                    ready, _, _ = select.select([self.posix_master], [], [], 0.2)
                    if not ready:
                        if self.child.poll() is not None:
                            break
                        continue
                    try:
                        chunk = os.read(self.posix_master, 65536)
                    except OSError:  # Linux PTY EIO means terminal was closed.
                        break
                    if not chunk:
                        break
                    with self.lock:
                        text = self.decoder.decode(chunk)
                        self.raw += text
                        self.stream.feed(text)
        except EOFError:
            pass
        except Exception as exc:
            self.error = str(exc)

    def snapshot(self):
        with self.lock:
            return len(self.raw)

    def visible(self):
        with self.lock:
            return "\n".join(self.screen.display)

    def wait(self, text, since=0, seconds=TIMEOUT):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if text in self.visible():
                return
            if self.error:
                raise AssertionError("PTY read failed: " + self.error)
            if not self.alive():
                raise AssertionError("TUI exited before modal " + repr(text))
            time.sleep(0.05)
        # Never dump the whole terminal: other TUI screens may contain secrets.
        raise AssertionError("Missing visible TUI text in real terminal: " + repr(text))

    def send(self, data):
        if self.win:
            self.win.write(data)
        else:
            os.write(self.posix_master, data.encode("utf-8"))

    def alive(self):
        return self.win.isalive() if self.win else self.child.poll() is None

    def close(self, expect_success=True):
        try:
            if expect_success:
                deadline = time.monotonic() + 7.0
                while self.alive() and time.monotonic() < deadline:
                    time.sleep(0.05)
                if self.alive():
                    raise AssertionError("TUI did not exit after q")
                # The guard must leave alt-screen, restore cursor and return.
                with self.lock:
                    output = self.raw
                assert "\x1b[?1049l" in output, "no alternate-screen restoration"
                assert "tui closed" in output, "compiled CLI did not exit normally"
                if self.win:
                    assert self.win.exitstatus == 0, "Windows TUI exit status not zero"
                else:
                    assert self.child.returncode == 0, "Linux TUI exit status not zero"
        finally:
            if self.alive():
                if self.win:
                    self.win.terminate(force=True)
                else:
                    self.child.kill()
                    self.child.wait(timeout=3)
            if self.posix_master is not None:
                os.close(self.posix_master)


def revision(binary, expected):
    process = subprocess.run(
        [binary, "server", "status"], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=7, check=False,
    )
    assert process.returncode == 0, "compiled CLI status request failed"
    assert "authorization revision=" + str(expected) in process.stdout, (
        "CAS revision unexpectedly changed; expected " + str(expected)
    )


def drive(binary, config, scenario, expected):
    if scenario == "readonly":
        command = [binary, "tui", "--role", "server"]
    else:
        command = [binary, "tui", "--role", "server", "--config", config]
    if scenario == "client":
        command = [binary, "tui", "--role", "client", "--config", config]
    tty = Terminal(command)
    try:
        if scenario == "readonly":
            tty.wait("Для сервера")
            since = tty.snapshot()
            tty.send("v")
            tty.wait("revision=" + str(expected), since=since)
            revision(binary, expected)
            tty.send("y")  # no saved digest: must never apply
            revision(binary, expected)
        else:
            tty.wait("Редактор TOML")
            if scenario == "dirty":
                since = tty.snapshot()
                tty.send("\r")
                tty.wait("Ввод:", since=since)
                tty.send("x\r")  # valid but unsaved changed TLS DNS
                tty.wait("Не сохранено")
                since = tty.snapshot()
                tty.send("\x12")  # Ctrl+R while dirty: must reject locally
                tty.wait("Сначала Ctrl+S", since=since)
                revision(binary, expected)
                tty.send("q")
                tty.wait("Не сохранено: подтвердите переход")
                tty.send("d")  # discard and exit, never save/apply
                tty.close()
                return
            if scenario == "client":
                tty.send("\x12")
                tty.send("y")
                revision(binary, expected)
            else:
                if scenario == "reject":
                    # A same-meaning TOML comment written *after* the editor
                    # loaded must still fail exact-content SHA-256 binding.
                    with open(config, "a", encoding="utf-8") as file:
                        file.write("\n# modified outside TUI after load\n")
                since = tty.snapshot()
                tty.send("\x12")
                tty.wait("revision=" + str(expected), since=since)
                revision(binary, expected)
                if scenario == "apply":
                    since = tty.snapshot()
                    tty.send("n")
                    tty.wait("Сервер работает", since=since)
                    revision(binary, expected)
                    since = tty.snapshot()
                    tty.send("a")
                    tty.wait("Подтвердить применение", since=since)
                    revision(binary, expected)
                since = tty.snapshot()
                tty.send("y")
                if scenario == "apply":
                    tty.wait("Применено: подтверждено сервером", since=since)
                    revision(binary, expected + 1)
                else:
                    tty.wait("Отказ: авторизация не применена", since=since)
                    revision(binary, expected)
        tty.send("\x1b")
        time.sleep(0.15)
        tty.send("q")
        tty.close()
    finally:
        if tty.alive():
            tty.close(expect_success=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--scenario", choices=("apply", "reject", "dirty", "readonly", "client"), required=True)
    parser.add_argument("--revision", type=int, required=True)
    args = parser.parse_args()
    drive(args.binary, args.config, args.scenario, args.revision)
    print("REAL_TUI_PTY_E2E_OK: " + args.scenario)


if __name__ == "__main__":
    main()
