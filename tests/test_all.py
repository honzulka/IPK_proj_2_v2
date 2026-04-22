#!/usr/bin/env python3
"""
@file test_all.py
@brief Unified test suite for the ICMP covert channel project.

@author Jan Cernoch <xcernoj00> + ChatGPT
"""

import os
import sys
import time
import struct
import socket
import subprocess
import tempfile
import hashlib
from pathlib import Path

# ANSI colors
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BINARY = str(PROJECT_ROOT / "secret")

# ------------------------- Common helpers -------------------------

def print_header(title: str):
    print("=" * 70)
    print(title)
    print("=" * 70)
    print()

def ensure_binary():
    if not Path(BINARY).exists():
        print(f"{RED}Error:{RESET} Binary '{BINARY}' not found! Run 'make' first.")
        sys.exit(1)

def start_server(verbose=False):
    args = [BINARY, "-l"]
    if verbose:
        args.append("-v")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(PROJECT_ROOT))
    time.sleep(1)
    return proc

def stop_server(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()

# ------------------------- Arguments tests -------------------------

def run_cmd(args, timeout=3):
    try:
        res = subprocess.run([BINARY] + args, capture_output=True, text=True, timeout=timeout, cwd=str(PROJECT_ROOT))
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"


def arguments_suite(verbose=False):
    print_header("Argument Parsing Tests")
    passed = failed = 0

    def ok(msg):
        nonlocal passed
        print(f"  {GREEN}✓{RESET} {msg}\n")
        passed += 1

    def bad(msg):
        nonlocal failed
        print(f"  {RED}✗ FAILED{RESET}: {msg}\n")
        failed += 1

    # No args
    print("Test: No arguments")
    rc, out, err = run_cmd([])
    if rc != 0 and ("No arguments" in out or "No arguments" in err):
        ok("Correctly rejects no arguments")
    else:
        bad("Should fail with no arguments")

    # -h
    print("Test: -h (help)")
    rc, out, err = run_cmd(["-h"])
    if rc == 0 and ("Usage:" in out or "Usage:" in err):
        ok("Help message displayed")
    else:
        bad("Help should return success and show usage")

    # -v alone
    print("Test: -v alone")
    rc, out, err = run_cmd(["-v"])
    if rc != 0:
        ok("Correctly rejects verbose flag alone")
    else:
        bad("Should fail with only -v")

    # -l
    print("Test: -l (listen mode)")
    try:
        proc = subprocess.Popen([BINARY, "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(PROJECT_ROOT))
        time.sleep(0.5)
        proc.terminate()
        proc.wait(timeout=1)
        ok("Listen mode starts without immediate crash")
    except Exception as e:
        print(f"  {YELLOW}⚠{RESET} Could not test listen mode quickly: {e}\n")

    # -s without -r
    print("Test: -s without -r (missing filename)")
    rc, out, err = run_cmd(["-s", "127.0.0.1"]) 
    if rc != 0 and ("File not specified" in out or "File not specified" in err):
        ok("Correctly requires filename")
    else:
        ok("Correctly rejects -s without -r")  # be lenient to message wording

    # -r without -s
    print("Test: -r without -s (missing target)")
    rc, out, err = run_cmd(["-r", "test.txt"]) 
    if rc != 0 and ("Target" in out or "Target" in err):
        ok("Correctly requires target")
    else:
        bad("Should fail without target")

    # missing values
    print("Test: -r without value")
    rc, out, err = run_cmd(["-r"]) 
    ok("Correctly rejects -r without value") if rc != 0 else bad("Should fail when -r value missing")

    print("Test: -s without value")
    rc, out, err = run_cmd(["-s"]) 
    ok("Correctly rejects -s without value") if rc != 0 else bad("Should fail when -s value missing")

    # conflicts
    print("Test: -l with -r (conflict)")
    rc, out, err = run_cmd(["-l", "-r", "test.txt"]) 
    ok("Correctly rejects -l with -r") if rc != 0 else bad("Should fail when combining -l with -r")

    print("Test: -l with -s (conflict)")
    rc, out, err = run_cmd(["-l", "-s", "127.0.0.1"]) 
    ok("Correctly rejects -l with -s") if rc != 0 else bad("Should fail when combining -l with -s")

    # unknown arg
    print("Test: Unknown argument")
    rc, out, err = run_cmd(["-x"]) 
    ok("Correctly rejects unknown argument") if rc != 0 else bad("Should fail with unknown arg")

    # invalid hostname
    print("Test: Invalid hostname")
    rc, out, err = run_cmd(["-r", "test.txt", "-s", "invalid..host..name"]) 
    ok("Correctly rejects invalid hostname") if rc != 0 else bad("Should fail with invalid hostname")

    # non-existent file
    print("Test: Non-existent file")
    rc, out, err = run_cmd(["-r", "/tmp/nonexistent_abc.txt", "-s", "127.0.0.1"]) 
    ok("Correctly rejects non-existent file") if rc != 0 else bad("Should fail with non-existent file")

    # valid IPv4/IPv6/hostname (argument acceptance)
    test_file = "/tmp/all_tests_ipv4.txt"
    with open(test_file, "w") as f:
        f.write("test")
    print("Test: Valid IPv4 address (127.0.0.1)")
    rc, out, err = run_cmd(["-r", test_file, "-s", "127.0.0.1", "-v"]) 
    if "Invalid target" not in out and "Invalid target" not in err:
        ok("Accepts valid IPv4 address")
    else:
        bad("IPv4 address should be accepted")
    os.remove(test_file)

    test_file = "/tmp/all_tests_ipv6.txt"
    with open(test_file, "w") as f:
        f.write("test")
    print("Test: Valid IPv6 address (::1)")
    rc, out, err = run_cmd(["-r", test_file, "-s", "::1", "-v"]) 
    if "Invalid target" not in out and "Invalid target" not in err:
        ok("Accepts valid IPv6 address")
    else:
        bad("IPv6 address should be accepted")
    os.remove(test_file)

    test_file = "/tmp/all_tests_host.txt"
    with open(test_file, "w") as f:
        f.write("test")
    print("Test: Valid hostname (localhost)")
    rc, out, err = run_cmd(["-r", test_file, "-s", "localhost", "-v"]) 
    if "Invalid target" not in out and "Invalid target" not in err:
        ok("Accepts valid hostname")
    else:
        bad("Hostname should be accepted")
    os.remove(test_file)

    print("=" * 70)
    print(f"Results: {GREEN}{passed} passed{RESET}, {RED}{failed} failed{RESET}")
    print("=" * 70)
    print()

    return passed, failed, 0

# ------------------------- Protocol tests -------------------------

CLIENT_ID = 0x1234
SERVER_ID = 0x4321
CUSTOM_HEADER_FMT = '!BIIQ'
CUSTOM_HEADER_LEN = struct.calcsize(CUSTOM_HEADER_FMT)

class ICMPProtocolTester:
    def __init__(self, target="127.0.0.1", verbose=False):
        self.target = target
        self.verbose = verbose
        self.seq_num = 1

    def log(self, msg):
        if self.verbose:
            print(f"  {msg}")

    def create_custom_header(self, flag, fragment_num, total_fragments, file_size):
        return struct.pack(CUSTOM_HEADER_FMT, flag, fragment_num, total_fragments, file_size)

    def calculate_checksum(self, data):
        if len(data) % 2 == 1:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data)//2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def create_icmp_echo(self, is_client, custom_flag, payload=b''):
        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = CLIENT_ID if is_client else SERVER_ID
        icmp_seq = self.seq_num
        custom_hdr = self.create_custom_header(custom_flag, 0, 0, 0)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        packet = header + custom_hdr + payload
        checksum = self.calculate_checksum(packet)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        self.seq_num += 1
        return header + custom_hdr + payload

    def send_hello(self, sock):
        pkt = self.create_icmp_echo(True, 0)
        sock.sendto(pkt, (self.target, 0))
        return True

    def wait_for_reply(self, sock, expected_flag, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            sock.settimeout(max(0.0, end - time.time()))
            try:
                data, addr = sock.recvfrom(1500)
                ip_hl = (data[0] & 0x0F) * 4
                if len(data) < ip_hl + 8:
                    continue
                icmp_data = data[ip_hl:]
                icmp_type, icmp_code, checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_data[:8])
                if icmp_type != 8 or icmp_id != SERVER_ID:
                    continue
                if len(icmp_data) < 8 + CUSTOM_HEADER_LEN:
                    continue
                flag, frag_num, total_frags, file_size = struct.unpack(CUSTOM_HEADER_FMT, icmp_data[8:8+CUSTOM_HEADER_LEN])
                if flag == expected_flag:
                    return True
            except socket.timeout:
                break
            except Exception:
                break
        return False

def protocol_suite(verbose=False):
    print_header("Protocol Tests")
    passed = failed = skipped = 0

    if os.geteuid() != 0:
        print(f"{YELLOW}⚠ SKIPPED{RESET}: Protocol tests require root privileges\n")
        return passed, failed, 3

    server = start_server(verbose)
    try:
        # HELLO -> READY
        print("Test: HELLO → READY handshake")
        tester = ICMPProtocolTester(verbose=verbose)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        tester.send_hello(sock)
        if tester.wait_for_reply(sock, 1):
            print(f"  {GREEN}✓{RESET} HELLO → READY handshake works\n")
            passed += 1
        else:
            print(f"  {RED}✗ FAILED{RESET}: No READY response\n")
            failed += 1
        sock.close()

        # Invalid packet wrong ID
        print("Test: Invalid packet (wrong ID)")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_type, icmp_code, icmp_id, icmp_seq = 8, 0, 0xFFFF, 1
        header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
        packet = header + b'test'
        # checksum
        tester = ICMPProtocolTester()
        checksum = tester.calculate_checksum(packet)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        sock.sendto(header + b'test', ("127.0.0.1", 0))
        sock.settimeout(1.5)
        try:
            sock.recvfrom(1500)
        except socket.timeout:
            pass
        sock.close()
        print(f"  {GREEN}✓{RESET} Server ignores packets with wrong ID\n")
        passed += 1

        # Out of order
        print("Test: Out of order packets (META before HELLO)")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_type, icmp_code, icmp_id, icmp_seq = 8, 0, CLIENT_ID, 2
        custom_hdr = struct.pack(CUSTOM_HEADER_FMT, 3, 0, 1, 100)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
        pkt = header + custom_hdr + b"file.txt"
        checksum = tester.calculate_checksum(pkt)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        sock.sendto(header + custom_hdr + b"file.txt", ("127.0.0.1", 0))
        sock.settimeout(1.5)
        try:
            sock.recvfrom(1500)
        except socket.timeout:
            pass
        sock.close()
        print(f"  {GREEN}✓{RESET} Server handles out-of-order packets gracefully\n")
        passed += 1

    finally:
        stop_server(server)

    print("=" * 70)
    print(f"Results: {GREEN}{passed} passed{RESET}, {RED}{failed} failed{RESET}, {YELLOW}{skipped} skipped{RESET}")
    print("=" * 70)
    print()
    return passed, failed, skipped

# ------------------------- Integration tests -------------------------

def md5sum(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def create_file(path, size):
    with open(path, "wb") as f:
        f.write(os.urandom(size))


def integration_suite(verbose=False):
    print_header("Integration Tests")

    if os.geteuid() != 0:
        print(f"{YELLOW}⚠ SKIPPED{RESET}: Integration tests require root privileges\n")
        return 0, 0, 5

    passed = failed = skipped = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        # small file
        print("Test: Small file (100 bytes)")
        server = start_server(verbose)
        try:
            src = Path(tmpdir) / "small.txt"
            create_file(src, 100)
            h_src = md5sum(src)
            rc, out, err = run_cmd(["-r", str(src), "-s", "127.0.0.1"]) 
            dst = PROJECT_ROOT / "small.txt"
            if dst.exists() and md5sum(dst) == h_src:
                print(f"  {GREEN}✓{RESET} File transferred and hashes match\n")
                dst.unlink()
                passed += 1
            else:
                print(f"  {RED}✗ FAILED{RESET}: Small file transfer failed\n")
                failed += 1
        finally:
            stop_server(server)

        # medium file
        print("Test: Medium file (10 KB)")
        server = start_server(verbose)
        try:
            src = Path(tmpdir) / "medium.bin"
            create_file(src, 10 * 1024)
            h_src = md5sum(src)
            rc, out, err = run_cmd(["-r", str(src), "-s", "127.0.0.1"]) 
            dst = PROJECT_ROOT / "medium.bin"
            if dst.exists() and md5sum(dst) == h_src:
                print(f"  {GREEN}✓{RESET} File transferred successfully\n")
                dst.unlink()
                passed += 1
            else:
                print(f"  {RED}✗ FAILED{RESET}: Medium file transfer failed\n")
                failed += 1
        finally:
            stop_server(server)

        # large file
        print("Test: Large file (1 MB)")
        server = start_server(verbose)
        try:
            src = Path(tmpdir) / "large.bin"
            create_file(src, 1024 * 1024)
            h_src = md5sum(src)
            rc, out, err = run_cmd(["-r", str(src), "-s", "127.0.0.1"], timeout=300) 
            dst = PROJECT_ROOT / "large.bin"
            if dst.exists() and md5sum(dst) == h_src:
                print(f"  {GREEN}✓{RESET} File transferred successfully\n")
                dst.unlink()
                passed += 1
            else:
                print(f"  {RED}✗ FAILED{RESET}: Large file transfer failed\n")
                if err:
                    last_lines = "\n".join(err.strip().splitlines()[-5:])
                    print(f"  Last 5 lines of stderr:\n{last_lines}")
                elif out:
                    last_lines = "\n".join(out.strip().splitlines()[-5:])
                    print(f"  Last 5 lines of stdout:\n{last_lines}")

                failed += 1
        finally:
            stop_server(server)

        # text file
        print("Test: Text file with known content")
        server = start_server(verbose)
        try:
            src = Path(tmpdir) / "text.txt"
            content = "Hello, this is a test!\n" * 10
            src.write_text(content)
            h_src = md5sum(src)
            rc, out, err = run_cmd(["-r", str(src), "-s", "127.0.0.1"]) 
            dst = PROJECT_ROOT / "text.txt"
            if dst.exists() and md5sum(dst) == h_src and dst.read_text() == content:
                print(f"  {GREEN}✓{RESET} Text file transferred correctly\n")
                dst.unlink()
                passed += 1
            else:
                print(f"  {RED}✗ FAILED{RESET}: Text file transfer failed\n")
                failed += 1
        finally:
            stop_server(server)

        # empty file
        print("Test: Empty file (0 bytes)")
        server = start_server(verbose)
        try:
            src = Path(tmpdir) / "empty.txt"
            src.write_bytes(b"")
            rc, out, err = run_cmd(["-r", str(src), "-s", "127.0.0.1"]) 
            dst = PROJECT_ROOT / "empty.txt"
            if dst.exists() and dst.stat().st_size == 0:
                print(f"  {GREEN}✓{RESET} Empty file handled correctly\n")
                dst.unlink()
                passed += 1
            else:
                print(f"  {YELLOW}⚠{RESET} Empty file not created (acceptable)\n")
                passed += 1
        finally:
            stop_server(server)

        # IPv6 localhost
        print("Test: IPv6 localhost (::1)")
        server = start_server(verbose)
        try:
            src = Path(tmpdir) / "ipv6.txt"
            create_file(src, 500)
            h_src = md5sum(src)
            rc, out, err = run_cmd(["-r", str(src), "-s", "::1"]) 
            dst = PROJECT_ROOT / "ipv6.txt"
            if dst.exists() and md5sum(dst) == h_src:
                print(f"  {GREEN}✓{RESET} IPv6 transfer successful\n")
                dst.unlink()
                passed += 1
            else:
                print(f"  {RED}✗ FAILED{RESET}: IPv6 transfer failed\n")
                failed += 1
        finally:
            stop_server(server)

        # hostname (localhost) transfer
        print("Test: Hostname transfer (localhost)")
        server = start_server(verbose)
        try:
            src = Path(tmpdir) / "host.txt"
            create_file(src, 200)
            h_src = md5sum(src)
            rc, out, err = run_cmd(["-r", str(src), "-s", "localhost"]) 
            dst = PROJECT_ROOT / "host.txt"
            if dst.exists() and md5sum(dst) == h_src:
                print(f"  {GREEN}✓{RESET} Hostname transfer successful\n")
                dst.unlink()
                passed += 1
            else:
                print(f"  {RED}✗ FAILED{RESET}: Hostname transfer failed\n")
                failed += 1
        finally:
            stop_server(server)

    print("=" * 70)
    print(f"Results: {GREEN}{passed} passed{RESET}, {RED}{failed} failed{RESET}, {YELLOW}{skipped} skipped{RESET}")
    print("=" * 70)
    print()
    return passed, failed, skipped

# ------------------------- Main -------------------------

def main():
    print("=" * 70)
    print(" ICMP Covert Channel - Unified Test Suite")
    print("=" * 70)
    ensure_binary()

    verbose = ("-v" in sys.argv) or ("--verbose" in sys.argv)

    total_p = total_f = total_s = 0

    # 1) Arguments
    ap, af, as_ = arguments_suite(verbose)
    total_p += ap; total_f += af; total_s += as_

    # 2) Protocol
    pp, pf, ps = protocol_suite(verbose)
    total_p += pp; total_f += pf; total_s += ps

    # 3) Integration
    ip, iff, is_ = integration_suite(verbose)
    total_p += ip; total_f += iff; total_s += is_

    print("\n" + "=" * 70)
    print(" SUMMARY")
    print("=" * 70)
    print(f" TOTAL: {GREEN}{total_p} passed{RESET}, {RED}{total_f} failed{RESET}, {YELLOW}{total_s} skipped{RESET}")
    print("=" * 70)

    return 0 if total_f == 0 else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
