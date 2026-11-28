"""Independent aioquic verification of actual Rust Modify output.

This validates packet boundaries and authenticated Initial plaintext only.
The opaque Handshake tail is a structural fixture, not a live connection.
"""
import sys

from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import QuicPacketType, pull_quic_header


def field(stream):
    size = int.from_bytes(stream.read(4), "big")
    if not 0 < size <= 65535:
        raise ValueError("invalid fixture length")
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated fixture")
    return data


def header(data):
    buf = Buffer(data=data)
    result = pull_quic_header(buf, host_cid_length=0)
    return result, buf.tell()


def verify(version, original, initial, tail, hello):
    assert original == initial + tail
    assert len(initial) >= 1200
    before, before_offset = header(original)
    after, after_offset = header(initial)
    following, _ = header(tail)
    assert before.packet_type == after.packet_type == QuicPacketType.INITIAL
    assert following.packet_type == QuicPacketType.HANDSHAKE
    assert before.version == after.version == following.version == version
    assert before.destination_cid == after.destination_cid == following.destination_cid
    assert before.source_cid == after.source_cid == following.source_cid
    assert before.packet_length == after.packet_length == len(initial)
    assert following.packet_length == len(tail)
    assert before_offset == after_offset

    def decrypt(packet, offset):
        crypto = CryptoPair()
        crypto.setup_initial(cid=after.destination_cid, is_client=False, version=version)
        return crypto.decrypt_packet(packet, offset, expected_packet_number=0)

    original_plain = decrypt(original[:before.packet_length], before_offset)
    split_plain = decrypt(initial, after_offset)
    assert original_plain == split_plain
    _, payload, packet_number = split_plain
    assert packet_number == 0
    frames = Buffer(data=payload)
    assert frames.pull_uint_var() == 6  # CRYPTO
    assert frames.pull_uint_var() == 0  # offset
    size = frames.pull_uint_var()
    assert frames.pull_bytes(size) == hello
    assert not any(frames.pull_bytes(len(payload) - frames.tell()))


def verify_fresh(version, original, rewritten, hello):
    before, before_offset = header(original)
    after, after_offset = header(rewritten)
    assert original != rewritten
    assert len(original) == len(rewritten)
    assert before.packet_type == after.packet_type == QuicPacketType.INITIAL
    assert before.version == after.version == version
    assert before.destination_cid == after.destination_cid
    assert before.source_cid == after.source_cid
    assert before_offset == after_offset

    def decrypt(packet, offset):
        crypto = CryptoPair()
        crypto.setup_initial(cid=before.destination_cid, is_client=False, version=version)
        return crypto.decrypt_packet(packet, offset, expected_packet_number=0)

    old_aad, _, old_number = decrypt(original, before_offset)
    aad, payload, number = decrypt(rewritten, after_offset)
    assert aad == old_aad and number == old_number == 0
    frames = Buffer(data=payload)
    assert frames.pull_uint_var() == 6
    assert frames.pull_uint_var() == 0
    first = frames.pull_bytes(frames.pull_uint_var())
    assert frames.pull_uint_var() == 6
    assert frames.pull_uint_var() == len(first)
    second = frames.pull_bytes(frames.pull_uint_var())
    assert first and second and first + second == hello
    assert not any(frames.pull_bytes(len(payload) - frames.tell()))


if __name__ == "__main__":
    stream = sys.stdin.buffer
    values = [field(stream) for _ in range(5)]
    assert not stream.read(1)
    verify(int(sys.argv[1]), *values[:4])
    verify_fresh(int(sys.argv[1]), values[1], values[4], values[3])
    print("Independent Initial authentication and exact datagram boundaries verified")
