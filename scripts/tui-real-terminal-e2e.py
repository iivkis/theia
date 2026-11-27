#!/usr/bin/env python3
"""M4.2f: drive the compiled Theia TUI in a real Linux PTY / Windows ConPTY.

Only a test tool: no fake ratatui events, injected IPC responses or snapshots.
The real compiled server and its native IPC are started by the Rust test.
"""
import argparse
import codecs
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

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
                # Process exit does not mean the ConPTY output pipe is drained.
                # Read the final restoration sequences and CLI result until EOF.
                while True:
                    chunk = self.win.read()
                    if chunk:
                        with self.lock:
                            text = chunk if isinstance(chunk, str) else self.decoder.decode(chunk)
                            self.raw += text
                            self.stream.feed(text)
                    elif not self.win.isalive():
                        break
                    else:
                        time.sleep(0.01)
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
                # The reader can still have buffered bytes after process exit.
                self.reader.join(timeout=7.0)
                assert not self.reader.is_alive(), "PTY output did not drain after exit"
                assert not self.error, "PTY output read failed after exit"
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
            # M4.2g: real PTY/ConPTY uppercase R opens a distinct read-only
            # restart readiness modal, not the authorization Apply modal.
            tty.send("\x1b")
            time.sleep(0.1)
            tty.send("R")
            tty.wait("Проверка готовности к перезапуску")
            tty.wait("auth-only CAS Apply")
            tty.send("y")  # never mutates even when the candidate is feasible
            revision(binary, expected)
        else:
            tty.wait("Режим подключения" if scenario == "client" else "Параметры · Enter")
            if scenario == "apply":
                # Both actual terminal creation paths must be reachable and
                # cancel without touching the exact TOML or server revision.
                with open(config, "rb") as file:
                    original = file.read()
                for choice, label in [("1", "Создать подключение (собственный TLS)"),
                                      ("2", "Мастер REALITY")]:
                    since = tty.snapshot()
                    tty.send("N")
                    tty.wait("SmartTheia REALITY", since=since)
                    since = tty.snapshot()
                    tty.send(choice)
                    tty.wait(label, since=since)
                    tty.send("\x1b")
                    time.sleep(0.15)
                    with open(config, "rb") as file:
                        assert file.read() == original
                    revision(binary, expected)
            if scenario == "dirty":
                since = tty.snapshot()
                tty.send("\r")
                tty.wait("Изменение параметра", since=since)
                tty.send("x\r")  # valid but unsaved changed TLS DNS
                tty.wait("Не сохранено")
                since = tty.snapshot()
                tty.send("\x12")  # Ctrl+R while dirty: must reject locally
                tty.wait("Сначала Ctrl+S", since=since)
                revision(binary, expected)
                tty.send("q")
                tty.wait("Сохранить изменения перед выходом?")
                tty.wait("Не сохранять и продолжить")
                revision(binary, expected)
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


def proxy_status(binary, expected):
    result = subprocess.run(
        [binary, "client", "proxy", "--status"], capture_output=True,
        text=True, timeout=7, check=False,
    )
    assert result.returncode == 0, "compiled WinINet status failed"
    assert expected in result.stdout, "unexpected journal state: " + expected


def read_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk, "unexpected tunnel EOF"
        data.extend(chunk)
    return bytes(data)


def test_tunnels(http_port, socks_port, echo_port):
    marker = b"theia-conpty-real-open-ok"
    with socket.create_connection(("127.0.0.1", http_port), timeout=5) as sock:
        sock.sendall(
            f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{echo_port}\r\n\r\n".encode("ascii")
        )
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            assert len(header) < 8192, "oversized CONNECT response"
            header.extend(read_exact(sock, 1))
        assert header.startswith(b"HTTP/1.1 200 "), "CONNECT did not reach OPEN_OK"
        sock.sendall(marker)
        assert read_exact(sock, len(marker)) == marker
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as sock:
        sock.sendall(b"\x05\x01\x00")
        assert read_exact(sock, 2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", echo_port))
        prefix = read_exact(sock, 4)
        assert prefix[:3] == b"\x05\x00\x00", "SOCKS did not reach OPEN_OK"
        if prefix[3] == 1:
            read_exact(sock, 6)
        elif prefix[3] == 4:
            read_exact(sock, 18)
        elif prefix[3] == 3:
            read_exact(sock, read_exact(sock, 1)[0] + 2)
        else:
            raise AssertionError("invalid SOCKS address")
        sock.sendall(marker)
        assert read_exact(sock, len(marker)) == marker


def drive_client_proxy(binary, config, http_port, socks_port, echo_port):
    assert os.name == "nt", "native Windows ConPTY required"
    assert os.environ.get("THEIA_WINDOWS_PROXY_E2E_ALLOWED") == "yes"
    command = [binary, "tui", "--role", "client", "--config", config]

    def open_panel():
        tty = Terminal(command)
        try:
            tty.wait("Режим подключения")
            tty.send("p")
            tty.wait("Состояние прочитано")
            return tty
        except BaseException:
            tty.close(expect_success=False)
            raise

    def review(tty, key, message):
        tty.send(key)
        tty.wait(message)
        tty.wait("Подтвердить")

    def confirm(tty, message):
        tty.send("y")
        tty.wait(message)

    def apply(tty):
        review(tty, "e", "Запустить локальный прокси при необходимости")
        proxy_status(binary, "NoJournal")
        confirm(tty, "Системный прокси включён")
        proxy_status(binary, "PendingOwned")

    proxy_status(binary, "NoJournal")
    tty = open_panel()
    try:
        tty.send("y")
        proxy_status(binary, "NoJournal")
        review(tty, "e", "Запустить локальный прокси при необходимости")
        tty.send("n")
        tty.wait("Отменено")
        proxy_status(binary, "NoJournal")
        for port in (http_port, socks_port):
            with socket.socket() as sock:
                sock.settimeout(2)
                assert sock.connect_ex(("127.0.0.1", port)) != 0, "listener started without consent"
        review(tty, "e", "Запустить локальный прокси при необходимости")
        proxy_status(binary, "NoJournal")
        confirm(tty, "Системный прокси включён")
        proxy_status(binary, "PendingOwned")
        test_tunnels(http_port, socks_port, echo_port)
        # Navigation must not tear down the owned runtime.
        tty.send("\x1b")
        tty.wait("Режим подключения")
        proxy_status(binary, "PendingOwned")
        test_tunnels(http_port, socks_port, echo_port)
        tty.send("p")
        tty.wait("Системный прокси включён")
        review(tty, "x", "Отключиться?")
        confirm(tty, "Локальный клиент остановлен")
        proxy_status(binary, "NoJournal")
        for port in (http_port, socks_port):
            with socket.socket() as sock:
                sock.settimeout(2)
                assert sock.connect_ex(("127.0.0.1", port)) != 0, "listener leaked after stop"
        tty.send("\x1b")
        tty.wait("Режим подключения")
        tty.send("q")
        tty.close()
    finally:
        if tty.alive():
            tty.close(expect_success=False)

    # A killed compiled TUI (not a unit-test surrogate) leaves the journal.
    tty = open_panel()
    try:
        apply(tty)
        test_tunnels(http_port, socks_port, echo_port)
        # Explicit process termination, never a graceful Ctrl+C/close request.
        killed = subprocess.run(
            ["taskkill", "/PID", str(tty.win.pid), "/F"],
            capture_output=True, timeout=10, check=False,
        )
        assert killed.returncode == 0, "could not hard-kill compiled TUI"
        deadline = time.monotonic() + 7
        while tty.alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not tty.alive(), "compiled TUI survived hard kill"
    finally:
        if tty.alive():
            tty.close(expect_success=False)
    proxy_status(binary, "PendingOwned")

    tty = open_panel()
    try:
        review(tty, "c", "Восстановить проверенный журнал")
        proxy_status(binary, "PendingOwned")
        tty.send("n")
        tty.wait("Отменено")
        proxy_status(binary, "PendingOwned")
        review(tty, "c", "Восстановить проверенный журнал")
        confirm(tty, "Восстановление журнала: Restored")
        proxy_status(binary, "NoJournal")
        tty.send("\x1b")
        tty.wait("Режим подключения")
        tty.send("q")
        tty.close()
    finally:
        if tty.alive():
            tty.close(expect_success=False)


def drive_dual_product(binary, server, client, cert, admission, fingerprint,
                       http_port, socks_port, echo_port):
    # Rust starts this process only after real server IPC readiness. The
    # monotonic barrier therefore cannot expire before startup + 121s.
    scenario_started = time.monotonic()
    replay_deadline = scenario_started + 121.0
    assert Path(cert).is_file()  # The server fixture must have its certificate.
    # Full compiled-binary paths, not an injected TUI/IPC response. The
    # reference inventory is a local, pre-provisioned fixture; no internet.
    server = Path(server)
    client = Path(client)
    base = server.parent

    def read_config(path):
        return tomllib.loads(path.read_text(encoding="utf-8"))

    def active_profile_label(profile_id):
        for index, profile in enumerate(read_config(client)["client"]["profiles"], 1):
            if profile["id"] == profile_id:
                return f"Активный профиль: №{index} · {profile['server']}"
        raise AssertionError("Expected saved profile is missing: " + profile_id)

    def finish(tty):
        tty.send("\x1b")
        time.sleep(0.15)
        tty.send("q")
        tty.close()

    def issue(tty, name):
        before = set(base.glob(".theia-export-*/invitation.theia"))
        tty.send("u")
        tty.wait("Имя пользователя")
        tty.send(name + "\r")
        tty.wait("Подтверждение нового пользователя")
        tty.send("y")
        tty.wait("Одноразовая выдача конфиденциальной ссылки")
        tty.send("f")
        tty.wait("Подтверждение конфиденциального экспорта")
        tty.send("y")
        tty.wait("Конфиденциальный файл создан")
        created = set(base.glob(".theia-export-*/invitation.theia")) - before
        assert len(created) == 1
        path = created.pop()
        with tty.lock:
            # The actual confidential URI must not be in the terminal stream.
            assert path.read_text(encoding="utf-8") not in tty.raw
        revision(binary, 1)
        # Do not concatenate ESC and the next navigation key: real terminals
        # may interpret the resulting sequence as an Alt-modified key.
        tty.send("\x1b")
        tty.wait("Параметры · Enter" if name == "own-user" else
                 "Защищённое подключение · только просмотр")
        return path

    server_cmd = [binary, "tui", "--role", "server", "--config", str(server)]
    tty = Terminal(server_cmd)
    try:
        tty.wait("Параметры · Enter")
        own_link = issue(tty, "own-user")
        tty.send("j")
        tty.wait("Защищённое подключение · только просмотр")
        reality_link = issue(tty, "reality-user")
        saved = read_config(server)["server"]
        assert "own-user" in saved["inbounds"][0]["allowed_user_ids"]
        assert "reality-user" in saved["inbounds"][1]["allowed_user_ids"]
        assert "own-user" not in saved["inbounds"][1]["allowed_user_ids"]
        tty.send("\x12")
        tty.wait("Подтвердить применение авторизации")
        revision(binary, 1)
        tty.send("y")
        tty.wait("Применено: подтверждено сервером")
        revision(binary, 2)
        finish(tty)
    finally:
        if tty.alive():
            tty.close(expect_success=False)

    # Headless Own-TLS client is a real native executable using protected IPC.
    if os.name == "nt":
        os.environ["THEIA_CLIENT_CONTROL_PIPE"] = f"tui-dual-{os.getpid()}"
    else:
        control = base / "client-ipc"
        control.mkdir(mode=0o700)
        os.environ["THEIA_CLIENT_CONTROL_DIR"] = str(control)

    def client_revision(expected):
        out = subprocess.run([binary, "client", "status"], capture_output=True,
                             text=True, timeout=3)
        return out.returncode == 0 and f"revision={expected};" in out.stdout

    headless = subprocess.Popen([binary, "client", "run", "--config", str(client)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    tty = None
    try:
        deadline = time.monotonic() + 6
        while not client_revision(1):
            assert headless.poll() is None and time.monotonic() < deadline
            time.sleep(0.05)
        client_cmd = [binary, "tui", "--role", "client", "--config", str(client)]
        tty = Terminal(client_cmd)
        tty.wait("Режим подключения")
        original = client.read_bytes()
        tty.send("i")
        tty.wait("Вставьте ключ (скрыто)")
        tty.send(str(own_link) + "\r")
        tty.wait("Проверка ключа · собственный TLS")
        # Issued Own-TLS keys carry their verified certificate anchor.
        tty.wait("Закреплён в ключе, соединение ещё НЕ проверено")
        assert client.read_bytes() == original
        tty.send("y")
        tty.wait("Профиль сохранён")
        assert read_config(client)["client"]["active_profile"] == "home"
        assert client_revision(1)
        tty.send("\x1b")
        tty.wait("Режим подключения")
        tty.send("A")
        tty.wait("Активный профиль в TOML:")
        tty.send("y")
        tty.wait(active_profile_label("public"))
        assert read_config(client)["client"]["active_profile"] == "public"
        assert client_revision(1)
        tty.send("V")
        tty.wait("Фоновый клиент: работает (версия 1)")
        tty.send("h")
        tty.wait("Применение настроек фонового клиента (версия 1)")
        assert client_revision(1)
        tty.send("n")
        tty.wait("Фоновый клиент: работает (версия 1)")
        assert client_revision(1)
        tty.send("h")
        tty.wait("Применение настроек фонового клиента (версия 1)")
        tty.send("y")
        tty.wait("Настройки фонового клиента применены (версия 2)")
        assert client_revision(2)
        test_tunnels(http_port, socks_port, echo_port)
        tty.send("\x1b")
        tty.wait("Режим подключения")
        headless.terminate()
        headless.wait(timeout=3)

        # All preceding operations use Own-TLS or local server management.
        # Do not enroll or connect REALITY before the real replay window ends.
        replay_wait_started = time.monotonic()
        remaining = max(0.0, replay_deadline - replay_wait_started)
        time.sleep(remaining)
        assert time.monotonic() >= replay_deadline
        replay_wait = time.monotonic() - replay_wait_started
        revision(binary, 2)

        def enroll():
            tty.send("i")
            tty.wait("Вставьте ключ (скрыто)")
            tty.send(str(reality_link) + "\r")
            tty.wait("ПРЕДПРОСМОТР: самодостаточный ключ REALITY")
            tty.send("y")
            # Successful managed enrollment opens registration automatically.
            tty.wait("Материалы подготовлены")

        # First complete local enrollment, cancel before TOML registration.
        before = set(base.glob(".theia-enroll-*"))
        saved = client.read_bytes()
        enroll()
        assert client.read_bytes() == saved
        assert len(set(base.glob(".theia-enroll-*")) - before) == 1
        tty.send("\x1b")
        tty.wait("Вставьте ключ (скрыто)")
        assert set(base.glob(".theia-enroll-*")) == before
        assert client.read_bytes() == saved

        # Re-run and actually register: still no implicit activation.
        enroll()
        tty.send("\x15reality-profile\r")
        tty.wait("Register REALITY profile")
        assert client.read_bytes() == saved
        tty.send("y")
        tty.wait("Профиль сохранён")
        assert read_config(client)["client"]["active_profile"] == "public"
        tty.send("\x1b")
        tty.wait("Режим подключения")
        tty.send("A")
        tty.wait("Активный профиль в TOML:")
        tty.send("y")
        tty.wait(active_profile_label("reality-profile"))
        assert read_config(client)["client"]["active_profile"] == "reality-profile"
        tty.send("V")
        tty.wait("Запустить локальный прокси")
        tty.send("s")
        tty.wait("Запустить локальный прокси для выбранного сервера?")
        tty.send("y")
        tty.wait("Локальный прокси работает. Это не подтверждает связь с сервером.")
        test_tunnels(http_port, socks_port, echo_port)
        tty.wait("последнее подтверждённое соединение: H")
        tty.send("x")
        tty.wait("Остановить локальный прокси?")
        tty.send("y")
        tty.wait("Локальный прокси остановлен")
        finish(tty)
        tty = None
    finally:
        if tty is not None and tty.alive():
            tty.close(expect_success=False)
        if headless.poll() is None:
            headless.kill()
            headless.wait(timeout=3)

    # Rollback is a separate, confirmed native server action. Refuse the
    # first review and verify both revisions and exact saved bytes.
    before = server.read_bytes()
    tty = Terminal(server_cmd)
    try:
        tty.wait("Параметры · Enter")
        tty.send("v")
        tty.wait("revision=2")
        tty.send("b")
        tty.wait("Откат авторизации, revision=2")
        tty.send("n")
        tty.wait("Параметры · Enter")
        revision(binary, 2)
        tty.send("v")
        tty.wait("revision=2")
        tty.send("b")
        tty.wait("Откат авторизации, revision=2")
        tty.send("y")
        tty.wait("Авторизация восстановлена, новая revision=3")
        revision(binary, 3)
        assert server.read_bytes() == before
        finish(tty)
    finally:
        if tty.alive():
            tty.close(expect_success=False)

    # Preserve the previous active driver budget; only real barrier waiting
    # is excluded. The Rust harness independently enforces the total budget.
    assert time.monotonic() - scenario_started - replay_wait <= 50.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--scenario", choices=("apply", "reject", "dirty", "readonly", "client", "client-proxy", "dual-product"), required=True)
    parser.add_argument("--revision", type=int, required=True)
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--socks-port", type=int)
    parser.add_argument("--echo-port", type=int)
    parser.add_argument("--client")
    parser.add_argument("--cert")
    parser.add_argument("--admission")
    parser.add_argument("--fingerprint")
    args = parser.parse_args()
    if args.scenario == "dual-product":
        drive_dual_product(args.binary, args.config, args.client, args.cert,
                           args.admission, args.fingerprint, args.http_port,
                           args.socks_port, args.echo_port)
    elif args.scenario == "client-proxy":
        assert all(port and 0 < port < 65536 for port in
                   (args.http_port, args.socks_port, args.echo_port))
        drive_client_proxy(args.binary, args.config, args.http_port,
                           args.socks_port, args.echo_port)
    else:
        drive(args.binary, args.config, args.scenario, args.revision)
    print("REAL_TUI_PTY_E2E_OK: " + args.scenario)


if __name__ == "__main__":
    main()
