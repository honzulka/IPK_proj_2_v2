# CHANGELOG

## Implemented functionality

- Single executable `ipk-rdt` with both modes:
  - server mode `-s`
  - client mode `-c`
- Reliable UDP transfer of one continuous byte stream:
  - explicit 3-way handshake (`SYN`, `SYN+ACK`, `ACK`)
  - metadata packet (`META`) with file size and segment count
  - pipelined data transfer (windowed sending, `WINDOW_SIZE=32`)
  - cumulative ACK processing
  - retransmission after timeout + fast retransmit on duplicate ACK
  - explicit teardown with `FIN/ACK/FIN/ACK`
  - teardown fix: client now exits successfully if FIN was ACKed and peer FIN is lost/delayed
- Integrity and validation:
  - protocol checksum (header + payload)
  - packet length and flag validation
  - malformed/corrupted packets are ignored
  - `conn_id` protection against packet confusion between transfers
  - server-side reassembly buffer for out-of-order segments before final ordered write
- Input/output support:
  - input from file or `stdin` (`-i`, `-`)
  - output to file or `stdout` (`-o`, `-`)
  - transfer of binary and text data
  - empty input handling
- IPv4 and IPv6 support:
  - address resolution via `getaddrinfo`
  - server default bind supports IPv4 and IPv6 clients
- CLI and diagnostics:
  - help output (`-h`, `--help`)
  - understandable error messages on `stderr`
  - verbose debug mode (`-v`)
- Automated tests:
  - `make test` target
  - CLI tests, transfer-mode tests, protocol-size test
  - malformed/duplicate/out-of-order/bad-META robustness tests
  - non-loopback IPv4 transfer test
  - two-device simulation via Linux network namespaces (`ip netns` + `veth`)
  - namespace impairment scenarios (duplicate/reorder/corrupt/mixed/malformed-noise)

## Known limitations

- One transfer per server process run (intentional by assignment design).
- No transfer resume after process crash.
- No encryption or authentication.
- No multi-client parallel service.
