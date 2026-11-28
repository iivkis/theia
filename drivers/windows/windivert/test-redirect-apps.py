#!/usr/bin/env python3
"""Independent external socket fixture; does not launch or configure Theia."""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import secrets
import socket
import threading
import time

TIMEOUT = 8
FLOWS = 4
MESSAGES = 4


def endpoint(value):
    host, sep, port = value.rpartition(':')
    if not sep or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError('expected literal IP:PORT')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('expected literal address') from exc
    if ip.is_unspecified or ip.is_multicast or getattr(ip, 'scope_id', None):
        raise argparse.ArgumentTypeError('unicast address required')
    return str(ip), int(port)


def family(address):
    return socket.AF_INET6 if ':' in address[0] else socket.AF_INET


def digest(label, payload):
    return label + hashlib.sha256(label + payload).digest()


def exact(sock, length):
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise RuntimeError('unexpected TCP EOF')
        result.extend(chunk)
    return bytes(result)


def tcp_peer(sock):
    with sock:
        sock.settimeout(TIMEOUT)
        transcript = bytearray()
        for _ in range(MESSAGES):
            size = int.from_bytes(exact(sock, 2), 'big')
            if not 1 <= size <= 128:
                raise RuntimeError('bad frame length')
            data = exact(sock, size)
            transcript.extend(data)
            sock.sendall(digest(b'T', data))
        if sock.recv(1) != b'':
            raise RuntimeError('missing TCP half-close')
        sock.sendall(digest(b'F', transcript))
        sock.shutdown(socket.SHUT_WR)


def tcp_client(address, barrier):
    with socket.socket(family(address), socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        barrier.wait(TIMEOUT)
        sock.connect(address)
        transcript = bytearray()
        for size in (1, 17, 64, 128):
            data = secrets.token_bytes(size)
            transcript.extend(data)
            frame = len(data).to_bytes(2, 'big') + data
            # Distinct writes, stream framing independent of packet boundaries.
            sock.sendall(frame[:1])
            sock.sendall(frame[1:])
            if exact(sock, 33) != digest(b'T', data):
                raise RuntimeError('wrong TCP response')
        sock.shutdown(socket.SHUT_WR)
        if exact(sock, 33) != digest(b'F', transcript) or sock.recv(1) != b'':
            raise RuntimeError('TCP half-close or final response failed')


def udp_client(address, barrier):
    with socket.socket(family(address), socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        barrier.wait(TIMEOUT)
        sock.connect(address)
        expected = set()
        for size in (0, 17, 64, 128):
            data = secrets.token_bytes(size)
            if sock.send(data) != len(data):
                raise RuntimeError('short UDP send')
            expected.update((digest(b'A', data), digest(b'B', data)))
        for _ in range(MESSAGES * 2):
            response = sock.recv(1024)
            if response not in expected:
                raise RuntimeError('unexpected or duplicate UDP response')
            expected.remove(response)
        if expected:
            raise RuntimeError('missing UDP responses')


def serve(address, peers, stop, ready):
    allowed = {ipaddress.ip_address(peer) for peer in peers}
    with socket.socket(family(address), socket.SOCK_STREAM) as tcp, socket.socket(family(address), socket.SOCK_DGRAM) as udp:
        if family(address) == socket.AF_INET6:
            for sock in (tcp, udp):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        tcp.bind(address)
        udp.bind(tcp.getsockname())
        tcp.listen(FLOWS * 2)
        tcp.settimeout(.1)
        udp.settimeout(.1)
        ready.append(tcp.getsockname()[:2])
        with concurrent.futures.ThreadPoolExecutor(max_workers=FLOWS * 2) as pool:
            tasks = set()
            while not stop.is_set():
                for task in tuple(tasks):
                    if task.done():
                        task.result()
                        tasks.remove(task)
                try:
                    conn, peer = tcp.accept()
                except socket.timeout:
                    pass
                else:
                    if ipaddress.ip_address(peer[0]) not in allowed or len(tasks) >= FLOWS * 2:
                        conn.close()
                        raise RuntimeError('unexpected TCP peer or capacity')
                    tasks.add(pool.submit(tcp_peer, conn))
                try:
                    data, peer = udp.recvfrom(1024)
                except socket.timeout:
                    continue
                if ipaddress.ip_address(peer[0]) not in allowed or len(data) > 128:
                    raise RuntimeError('unexpected UDP peer or datagram')
                for label in (b'B', b'A'):
                    response = digest(label, data)
                    if udp.sendto(response, peer) != len(response):
                        raise RuntimeError('short UDP reply')
            for task in tasks:
                task.result()


def run_clients(address):
    barrier = threading.Barrier(FLOWS * 2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=FLOWS * 2) as pool:
        tasks = [pool.submit(client, address, barrier)
                 for client in (tcp_client, udp_client) for _ in range(FLOWS)]
        for task in tasks:
            task.result()


def self_test():
    # Tests the independent application fixture, NOT WinDivert or XHTTP.
    for ip in ('127.0.0.1', '::1'):
        stop, ready = threading.Event(), []
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            server = pool.submit(serve, (ip, 0), [ip], stop, ready)
            try:
                deadline = time.monotonic() + TIMEOUT
                while not ready:
                    if server.done():
                        server.result()
                        raise RuntimeError('server exited before ready')
                    if time.monotonic() >= deadline:
                        raise RuntimeError('server did not start')
                    time.sleep(.01)
                run_clients(ready[0])
            finally:
                stop.set()
                server.result()
    print('external application fixture self-test passed (loopback only)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    modes.add_parser('self-test')
    client = modes.add_parser('client')
    client.add_argument('--target', type=endpoint, action='append', required=True)
    server = modes.add_parser('server')
    server.add_argument('--listen', type=endpoint, required=True)
    server.add_argument('--expected-peer', type=ipaddress.ip_address, action='append', required=True)
    server.add_argument('--seconds', type=int, default=120, choices=range(5, 301))
    args = parser.parse_args()
    if args.mode == 'self-test':
        self_test()
    elif args.mode == 'client':
        if len(args.target) > 8 or len(set(args.target)) != len(args.target):
            parser.error('1–8 distinct targets required')
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(args.target)) as pool:
            for future in [pool.submit(run_clients, target) for target in args.target]:
                future.result()
        print(f'external TCP/UDP application exchanges passed: {len(args.target)} target(s)')
    else:
        stop, ready = threading.Event(), []
        timer = threading.Timer(args.seconds, stop.set)
        timer.start()
        try:
            serve(args.listen, args.expected_peer, stop, ready)
        finally:
            timer.cancel()
        print('server fixture finished; peer checks passed for received requests')


if __name__ == '__main__':
    main()
