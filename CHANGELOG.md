# CHANGELOG

## Implemented functionality

- Single executable `ipk-rdt` with both modes:
  - server mode `-s`
  - client mode `-c`
- Reliable UDP transfer of one continuous byte stream:
  - explicit 3-way handshake (`SYN`, `SYN+ACK`, `ACK`)
  - metadata packet (`META`) with file size and segment count
  - pipelined Go-Back-N data transfer (windowed sending)
  - cumulative ACK processing
  - retransmission after timeout
  - explicit teardown with `FIN/ACK/FIN/ACK`
- Integrity and validation:
  - protocol checksum (header + payload)
  - packet length and flag validation
  - malformed/corrupted packets are ignored
  - `conn_id` protection against packet confusion between transfers
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

## Known limitations

- One transfer per server process run (intentional by assignment design).
- No transfer resume after process crash.
- No encryption or authentication.
- No multi-client parallel service.
