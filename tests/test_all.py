#!/usr/bin/env python3
"""
Unified automated tests for IPK Project 2 (ipk-rdt).
"""

import hashlib
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BINARY = PROJECT_ROOT / "ipk-rdt"
PROTOCOL_H = PROJECT_ROOT / "src" / "protocol.h"

FLAG_SYN = 0x01
FLAG_ACK = 0x02
FLAG_FIN = 0x04
FLAG_DATA = 0x08
FLAG_META = 0x10

RDT_HDR_FMT = "!IIIHBH"
RDT_HDR_SIZE = struct.calcsize(RDT_HDR_FMT)


def md5_bytes(data: bytes) -> str:
    h = hashlib.md5()
    h.update(data)
    return h.hexdigest()


def random_bytes(size: int) -> bytes:
    return os.urandom(size)


def print_header(title: str) -> None:
    print("=" * 72)
    print(title)
    print("=" * 72)


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}✗ FAILED{RESET}: {msg}")


def skip(msg: str) -> None:
    print(f"  {YELLOW}⚠ SKIPPED{RESET}: {msg}")


def ensure_binary() -> None:
    if not BINARY.exists():
        print(f"{RED}Error:{RESET} Binary '{BINARY}' not found. Run 'make' first.")
        sys.exit(1)


def run_cmd(args, timeout=5):
    return subprocess.run(
        [str(BINARY)] + args,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def free_port(family: int) -> int:
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        if family == socket.AF_INET6:
            s.bind(("::1", 0))
        else:
            s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def non_loopback_ipv4():
    try:
        out = subprocess.check_output(
            ["sh", "-c", "ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return None
    for line in out.splitlines():
        ip = line.strip()
        if ip and not ip.startswith("127."):
            return ip
    return None


def netns_supported() -> bool:
    return os.geteuid() == 0 and shutil.which("ip") is not None


def tc_supported() -> bool:
    return shutil.which("tc") is not None


def run_netns_transfer_case(
    *,
    payload: bytes,
    timeout_s: int = 1,
    client_netem: str | None = None,
    server_netem: str | None = None,
    malformed_noise: bool = False,
):
    tag = f"{os.getpid()}{random.randint(1000,9999)}"
    ns1 = f"ipk_c_{tag}"
    ns2 = f"ipk_s_{tag}"
    v1 = f"v1{tag}"[:15]
    v2 = f"v2{tag}"[:15]
    ip1 = "10.251.13.1"
    ip2 = "10.251.13.2"
    port = random.randint(25000, 35000)

    def ipcmd(*args):
        subprocess.run(["ip", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def tccmd(ns, *args):
        subprocess.run(["ip", "netns", "exec", ns, "tc", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with tempfile.TemporaryDirectory(prefix="ipk-rdt-netns-") as td:
        td = Path(td)
        in_file = td / "in.bin"
        out_file = td / "out.bin"
        in_file.write_bytes(payload)

        server = None
        noise = None
        try:
            ipcmd("netns", "add", ns1)
            ipcmd("netns", "add", ns2)
            ipcmd("link", "add", v1, "type", "veth", "peer", "name", v2)
            ipcmd("link", "set", v1, "netns", ns1)
            ipcmd("link", "set", v2, "netns", ns2)
            ipcmd("-n", ns1, "link", "set", "lo", "up")
            ipcmd("-n", ns2, "link", "set", "lo", "up")
            ipcmd("-n", ns1, "addr", "add", f"{ip1}/24", "dev", v1)
            ipcmd("-n", ns2, "addr", "add", f"{ip2}/24", "dev", v2)
            ipcmd("-n", ns1, "link", "set", v1, "up")
            ipcmd("-n", ns2, "link", "set", v2, "up")

            if client_netem:
                tccmd(ns1, "qdisc", "add", "dev", v1, "root", "netem", *client_netem.split())
            if server_netem:
                tccmd(ns2, "qdisc", "add", "dev", v2, "root", "netem", *server_netem.split())

            server = subprocess.Popen(
                ["ip", "netns", "exec", ns2, str(BINARY), "-s", "-a", ip2, "-p", str(port), "-o", str(out_file), "-w", str(timeout_s)],
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.2)

            if malformed_noise:
                noise_code = (
                    "import os,socket,sys,time,random; "
                    "h=sys.argv[1]; p=int(sys.argv[2]); "
                    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                    "end=time.time()+2.0; "
                    "while time.time()<end: "
                    " s.sendto(os.urandom(random.randint(1,80)),(h,p)); "
                    " time.sleep(0.005)"
                )
                noise = subprocess.Popen(
                    ["ip", "netns", "exec", ns1, "python3", "-c", noise_code, ip2, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            client = subprocess.run(
                ["ip", "netns", "exec", ns1, str(BINARY), "-c", "-a", ip2, "-p", str(port), "-i", str(in_file), "-w", str(timeout_s)],
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=45,
            )
            if noise:
                noise.wait(timeout=5)
            s_out, s_err = server.communicate(timeout=45)
            _ = s_out, s_err

            got = out_file.read_bytes() if out_file.exists() else b""
            ok_case = client.returncode == 0 and server.returncode == 0 and got == payload
            detail = f"client_rc={client.returncode},server_rc={server.returncode},len={len(got)}"
            return ok_case, detail
        finally:
            if noise and noise.poll() is None:
                noise.terminate()
            if server and server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    server.kill()
            subprocess.run(["ip", "netns", "del", ns1], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "netns", "del", ns2], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def checksum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_rdt_packet(conn_id: int, seq: int, ack: int, flags: int, payload: bytes = b"", len_override: int | None = None) -> bytes:
    payload_len = len(payload) if len_override is None else len_override
    hdr_wo_cks = struct.pack(RDT_HDR_FMT, conn_id, seq, ack, payload_len, flags, 0)
    cks = checksum16(hdr_wo_cks + payload)
    hdr = struct.pack(RDT_HDR_FMT, conn_id, seq, ack, payload_len, flags, cks)
    return hdr + payload


def parse_rdt_header(pkt: bytes):
    if len(pkt) < RDT_HDR_SIZE:
        return None
    conn_id, seq, ack, plen, flags, cks = struct.unpack(RDT_HDR_FMT, pkt[:RDT_HDR_SIZE])
    return {"conn_id": conn_id, "seq": seq, "ack": ack, "len": plen, "flags": flags, "checksum": cks}


def recv_packet(sock: socket.socket, timeout: float = 1.0):
    sock.settimeout(timeout)
    data, _ = sock.recvfrom(2048)
    return parse_rdt_header(data), data


def run_transfer(
    *,
    host: str,
    family: int,
    input_data: bytes,
    client_input_mode: str,
    server_output_mode: str,
    server_bind: str | None = None,
    timeout: int = 1,
    transfer_timeout: int = 20,
    inject_malformed: bool = False,
):
    port = free_port(family)

    with tempfile.TemporaryDirectory(prefix="ipk-rdt-test-") as td:
        td_path = Path(td)
        in_file = td_path / "input.bin"
        out_file = td_path / "output.bin"

        if client_input_mode == "file":
            in_file.write_bytes(input_data)
            client_stdin = None
            client_args = ["-c", "-a", host, "-p", str(port), "-i", str(in_file), "-w", str(timeout)]
        else:
            client_stdin = input_data
            client_args = ["-c", "-a", host, "-p", str(port), "-i", "-", "-w", str(timeout)]

        server_args = ["-s", "-p", str(port), "-w", str(timeout)]
        if server_bind is not None:
            server_args.extend(["-a", server_bind])
        if server_output_mode == "file":
            server_args.extend(["-o", str(out_file)])

        server = subprocess.Popen(
            [str(BINARY)] + server_args,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            time.sleep(0.2)

            if inject_malformed:
                send_malformed_packets(host, port, family, count=60)

            client = subprocess.Popen(
                [str(BINARY)] + client_args,
                cwd=str(PROJECT_ROOT),
                stdin=subprocess.PIPE if client_input_mode == "stdin" else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                c_out, c_err = client.communicate(input=client_stdin, timeout=transfer_timeout)
            except subprocess.TimeoutExpired:
                client.kill()
                c_out, c_err = client.communicate()
                raise RuntimeError(f"client timeout, stderr={c_err.decode(errors='replace')}")

            try:
                s_out, s_err = server.communicate(timeout=transfer_timeout)
            except subprocess.TimeoutExpired:
                server.kill()
                s_out, s_err = server.communicate()
                raise RuntimeError(f"server timeout, stderr={s_err.decode(errors='replace')}")

            if client.returncode != 0:
                raise RuntimeError(f"client rc={client.returncode}, stderr={c_err.decode(errors='replace')}")
            if server.returncode != 0:
                raise RuntimeError(f"server rc={server.returncode}, stderr={s_err.decode(errors='replace')}")

            if server_output_mode == "file":
                if not out_file.exists():
                    raise RuntimeError("server output file was not created")
                got = out_file.read_bytes()
            else:
                got = s_out

            return got, c_out, c_err, s_err
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    server.kill()


def send_malformed_packets(host: str, port: int, family: int, count: int) -> None:
    for _ in range(count):
        if family == socket.AF_INET6:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.sendto(os.urandom(random.randint(1, 64)), (host, port))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(os.urandom(random.randint(1, 64)), (host, port))


def read_define_int(path: Path, name: str):
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith(f"#define {name} "):
            return int(line.split()[-1])
    return None


def cli_suite():
    print_header("CLI / argument behavior")
    p = f = 0

    r = run_cmd(["-h"], timeout=3)
    if r.returncode == 0 and b"Usage:" in r.stdout:
        ok("-h returns 0 and prints usage")
        p += 1
    else:
        fail("-h behavior mismatch")
        f += 1

    r = run_cmd([], timeout=3)
    if r.returncode != 0:
        ok("no-arg invocation fails")
        p += 1
    else:
        fail("no-arg invocation should fail")
        f += 1

    r = run_cmd(["-c", "-p", "9000"], timeout=3)
    if r.returncode != 0 and b"-a HOST is required" in r.stderr:
        ok("client rejects missing -a")
        p += 1
    else:
        fail("client missing -a should fail with stderr error")
        f += 1

    r = run_cmd(["-c", "-s", "-a", "127.0.0.1", "-p", "9000"], timeout=3)
    if r.returncode != 0:
        ok("mutually exclusive -c/-s enforced")
        p += 1
    else:
        fail("simultaneous -c and -s should fail")
        f += 1

    return p, f, 0


def protocol_limits_suite():
    print_header("Protocol static limits")
    p = f = 0

    max_payload = read_define_int(PROTOCOL_H, "MAX_PAYLOAD_SIZE")
    header_size = read_define_int(PROTOCOL_H, "RDT_HEADER_SIZE")
    if max_payload is None or header_size is None:
        fail("cannot read protocol size defines")
        return 0, 1, 0

    if max_payload + header_size <= 1200:
        ok(f"MAX_PAYLOAD_SIZE + RDT_HEADER_SIZE <= 1200 ({max_payload + header_size})")
        p += 1
    else:
        fail(f"UDP payload exceeds 1200 ({max_payload + header_size})")
        f += 1

    return p, f, 0


def transfer_suite():
    print_header("Transfer scenarios (correctness)")
    p = f = s = 0

    cases = [
        ("IPv4 file->file small binary", dict(host="127.0.0.1", family=socket.AF_INET, input_data=random_bytes(1024), client_input_mode="file", server_output_mode="file", server_bind="127.0.0.1")),
        ("IPv6 file->file small binary", dict(host="::1", family=socket.AF_INET6, input_data=random_bytes(1024), client_input_mode="file", server_output_mode="file", server_bind="::1")),
        ("empty input file->file", dict(host="127.0.0.1", family=socket.AF_INET, input_data=b"", client_input_mode="file", server_output_mode="file", server_bind="127.0.0.1")),
        ("stdin->file", dict(host="127.0.0.1", family=socket.AF_INET, input_data=random_bytes(4096), client_input_mode="stdin", server_output_mode="file", server_bind="127.0.0.1")),
        ("file->stdout", dict(host="127.0.0.1", family=socket.AF_INET, input_data=random_bytes(4096), client_input_mode="file", server_output_mode="stdout", server_bind="127.0.0.1")),
        ("stdin->stdout", dict(host="127.0.0.1", family=socket.AF_INET, input_data=random_bytes(4096), client_input_mode="stdin", server_output_mode="stdout", server_bind="127.0.0.1")),
        ("default bind accepts IPv6 client", dict(host="::1", family=socket.AF_INET6, input_data=random_bytes(2048), client_input_mode="file", server_output_mode="file", server_bind=None)),
    ]

    non_local_v4 = non_loopback_ipv4()
    if non_local_v4:
        cases.append(
            ("IPv4 non-localhost interface", dict(host=non_local_v4, family=socket.AF_INET, input_data=random_bytes(4096), client_input_mode="file", server_output_mode="file", server_bind=non_local_v4))
        )
    else:
        skip("non-localhost IPv4 test skipped (no global IPv4 address)")
        s += 1

    for name, kwargs in cases:
        try:
            got, _, _, s_err = run_transfer(**kwargs, transfer_timeout=25)
            if got == kwargs["input_data"]:
                if kwargs["server_output_mode"] == "stdout" and b"META received" in got:
                    fail(f"{name}: payload polluted by log text")
                    f += 1
                else:
                    ok(name)
                    p += 1
            else:
                fail(f"{name}: payload mismatch (in={md5_bytes(kwargs['input_data'])}, out={md5_bytes(got)})")
                f += 1
                if s_err:
                    print("    server stderr:", s_err.decode(errors="replace").strip())
        except Exception as e:
            fail(f"{name}: {e}")
            f += 1

    return p, f, s


def malformed_noise_during_valid_transfer():
    data = random_bytes(64 * 1024)
    got, _, _, _ = run_transfer(
        host="127.0.0.1",
        family=socket.AF_INET,
        input_data=data,
        client_input_mode="file",
        server_output_mode="file",
        server_bind="127.0.0.1",
        inject_malformed=True,
        transfer_timeout=30,
    )
    return got == data


def malformed_duplicate_out_of_order_bad_meta():
    port = free_port(socket.AF_INET)
    with tempfile.TemporaryDirectory(prefix="ipk-rdt-malformed-") as td:
        out_path = Path(td) / "out.bin"
        server = subprocess.Popen(
            [str(BINARY), "-s", "-a", "127.0.0.1", "-p", str(port), "-o", str(out_path), "-w", "2"],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        conn_id = random.randint(1, 0xFFFFFFFE)
        target = ("127.0.0.1", port)
        try:
            time.sleep(0.1)

            sock.sendto(build_rdt_packet(conn_id, 0, 0, FLAG_SYN), target)
            synack = None
            deadline = time.time() + 2.5
            while time.time() < deadline:
                hdr, _ = recv_packet(sock, timeout=0.5)
                if hdr and hdr["conn_id"] == conn_id and (hdr["flags"] & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK):
                    synack = hdr
                    break
            if synack is None:
                return False

            sock.sendto(build_rdt_packet(conn_id, 0, 0, FLAG_SYN), target)  # duplicate SYN
            sock.sendto(build_rdt_packet(conn_id, 1, synack["seq"] + 1, FLAG_ACK), target)

            # malformed META (len says more than payload actually contains)
            bad_meta_payload = struct.pack("!QI", 2, 2)
            sock.sendto(build_rdt_packet(conn_id, 1, 1, FLAG_META, bad_meta_payload, len_override=len(bad_meta_payload) + 4), target)

            # valid META
            sock.sendto(build_rdt_packet(conn_id, 1, 1, FLAG_META, bad_meta_payload), target)

            # corrupted checksum DATA (must be ignored)
            bad_data = bytearray(build_rdt_packet(conn_id, 2, 0, FLAG_DATA, b"A"))
            bad_data[-1] ^= 0xFF
            sock.sendto(bytes(bad_data), target)

            # out-of-order DATA first
            sock.sendto(build_rdt_packet(conn_id, 3, 0, FLAG_DATA, b"B"), target)
            sock.sendto(build_rdt_packet(conn_id, 2, 0, FLAG_DATA, b"A"), target)
            sock.sendto(build_rdt_packet(conn_id, 2, 0, FLAG_DATA, b"A"), target)  # duplicate DATA
            sock.sendto(build_rdt_packet(conn_id, 3, 0, FLAG_DATA, b"B"), target)

            # FIN + wait for server FIN
            fin_seq = 4
            got_server_fin = False
            for _ in range(8):
                sock.sendto(build_rdt_packet(conn_id, fin_seq, 0, FLAG_FIN), target)
                try:
                    hdr, _ = recv_packet(sock, timeout=0.5)
                except socket.timeout:
                    continue
                if not hdr or hdr["conn_id"] != conn_id:
                    continue
                if hdr["flags"] & FLAG_FIN:
                    sock.sendto(build_rdt_packet(conn_id, fin_seq + 1, hdr["seq"] + 1, FLAG_ACK), target)
                    got_server_fin = True
                    break

            if not got_server_fin:
                return False

            s_out, s_err = server.communicate(timeout=5)
            if server.returncode != 0:
                _ = s_out, s_err
                return False
            return out_path.exists() and out_path.read_bytes() == b"AB"
        finally:
            sock.close()
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    server.kill()


def malformed_bad_meta_session_times_out():
    port = free_port(socket.AF_INET)
    server = subprocess.Popen(
        [str(BINARY), "-s", "-a", "127.0.0.1", "-p", str(port), "-o", "-", "-w", "1"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    conn_id = random.randint(1, 0xFFFFFFFE)
    target = ("127.0.0.1", port)
    try:
        time.sleep(0.1)
        sock.sendto(build_rdt_packet(conn_id, 0, 0, FLAG_SYN), target)
        synack = None
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                hdr, _ = recv_packet(sock, timeout=0.4)
            except socket.timeout:
                continue
            if hdr and hdr["conn_id"] == conn_id and (hdr["flags"] & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK):
                synack = hdr
                break
        if synack is None:
            return False

        sock.sendto(build_rdt_packet(conn_id, 1, synack["seq"] + 1, FLAG_ACK), target)

        # only malformed META + out-of-order DATA; no valid progress
        for _ in range(5):
            bad_meta = struct.pack("!QI", 123, 2)
            sock.sendto(build_rdt_packet(conn_id, 1, 1, FLAG_META, bad_meta, len_override=len(bad_meta) + 8), target)
            sock.sendto(build_rdt_packet(conn_id, 99, 0, FLAG_DATA, b"X"), target)
            time.sleep(0.05)

        try:
            server.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate()
            return False

        return server.returncode != 0
    finally:
        sock.close()
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=1)
            except subprocess.TimeoutExpired:
                server.kill()


def malformed_suite():
    print_header("Malformed / duplicate / out-of-order traffic")
    p = f = 0

    try:
        if malformed_noise_during_valid_transfer():
            ok("ignores malformed random UDP datagrams")
            p += 1
        else:
            fail("random malformed datagrams test failed")
            f += 1
    except Exception as e:
        fail(f"random malformed datagrams: {e}")
        f += 1

    try:
        if malformed_duplicate_out_of_order_bad_meta():
            ok("handles bad META + duplicate + out-of-order packets")
            p += 1
        else:
            fail("bad META / duplicate / out-of-order scenario failed")
            f += 1
    except Exception as e:
        fail(f"bad META / duplicate / out-of-order: {e}")
        f += 1

    try:
        if malformed_bad_meta_session_times_out():
            ok("terminates malformed session with non-zero exit")
            p += 1
        else:
            fail("malformed session timeout behavior failed")
            f += 1
    except Exception as e:
        fail(f"malformed session timeout: {e}")
        f += 1

    return p, f, 0


def netns_suite():
    print_header("Two-device namespace tests (non-localhost)")
    p = f = s = 0

    if not netns_supported():
        skip("namespace suite skipped (requires root + iproute2)")
        s += 1
        return p, f, s
    if not tc_supported():
        skip("namespace impairment tests skipped (tc/netem not available)")
        s += 1
        return p, f, s

    data = random_bytes(96 * 1024)
    cases = [
        ("netns clean", dict()),
        ("netns duplicate", dict(client_netem="duplicate 8%")),
        ("netns reorder", dict(client_netem="delay 20ms 8ms reorder 25% 50%")),
        ("netns corrupt", dict(client_netem="corrupt 4%")),
        ("netns mixed", dict(client_netem="loss 5% duplicate 2% delay 12ms 4ms reorder 12% 50% corrupt 1%", timeout_s=2)),
        ("netns malformed-noise", dict(malformed_noise=True)),
    ]

    for name, cfg in cases:
        try:
            case_cfg = dict(cfg)
            case_timeout = case_cfg.pop("timeout_s", 1)
            ok_case, detail = run_netns_transfer_case(payload=data, timeout_s=case_timeout, **case_cfg)
            if ok_case:
                ok(name)
                p += 1
            else:
                fail(f"{name}: {detail}")
                f += 1
        except Exception as e:
            if isinstance(e, subprocess.CalledProcessError) and ("client_netem" in cfg or "server_netem" in cfg):
                skip(f"{name}: netem setup not supported in this environment")
                s += 1
            else:
                fail(f"{name}: {e}")
                f += 1

    return p, f, s


def main():
    print_header("IPK-RDT Automated Test Suite")
    ensure_binary()

    total_p = total_f = total_s = 0
    suites = [cli_suite, protocol_limits_suite, transfer_suite, malformed_suite, netns_suite]

    for suite in suites:
        p, f, s = suite()
        total_p += p
        total_f += f
        total_s += s
        print()

    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"TOTAL: {GREEN}{total_p} passed{RESET}, {RED}{total_f} failed{RESET}, {YELLOW}{total_s} skipped{RESET}")
    print("=" * 72)

    return 0 if total_f == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)
