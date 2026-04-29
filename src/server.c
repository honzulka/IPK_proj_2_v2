/**
 * @file server.c
 * @brief UDP server implementation for reliable transfer.
 *
 * @author Jan Cernoch <xcernoj00>
 */

#define _DEFAULT_SOURCE

#include "server.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <endian.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define RECV_BUFFER 1500

/* ================= SOCKET ================= */

static int create_socket(const char *address, int port) {
  struct addrinfo hints = {0}, *res, *rp;
  char port_str[16];
  int sock = -1;

  snprintf(port_str, sizeof(port_str), "%d", port);

  hints.ai_family = AF_UNSPEC;   /* Support both IPv4 and IPv6 */
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(address, port_str, &hints, &res) != 0) {
    perror("getaddrinfo");
    return -1;
  }

  /* If -a is omitted, prefer IPv6 wildcard with dual-stack support first. */
  for (int pass = 0; pass < 2 && sock < 0; pass++) {
    for (rp = res; rp != NULL; rp = rp->ai_next) {
      if (address == NULL) {
        if (pass == 0 && rp->ai_family != AF_INET6)
          continue;
        if (pass == 1 && rp->ai_family == AF_INET6)
          continue;
      }

      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock < 0)
        continue;

      int reuse = 1;
      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

      if (address == NULL && rp->ai_family == AF_INET6) {
        int v6only = 0;
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
      }

      if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
        break;

      close(sock);
      sock = -1;
    }
  }

  freeaddrinfo(res);
  return sock;
}

/* ================= SEND HELPER ================= */

static void send_pkt(int sock, const rdt_header_t *hdr,
                     struct sockaddr *addr, socklen_t addrlen) {
  pkt_t pkt = build_packet(hdr, NULL);
  if (pkt.data) {
    sendto(sock, pkt.data, pkt.len, 0, addr, addrlen);
    free(pkt.data);
  }
}

/* ================= SERVER ================= */

void start_server(int port, const char *address, FILE *output, int timeout) {

  int sock = create_socket(address, port);
  if (sock < 0) {
    fprintf(stderr, "ERROR: Cannot bind socket\n");
    exit(EXIT_FAILURE);
  }

  uint8_t buffer[RECV_BUFFER];
  struct sockaddr_storage client_addr;
  socklen_t client_len = sizeof(client_addr);

  uint32_t conn_id = 0;

  /*
   * Server state machine:
   *   0 = INIT        – waiting for SYN
   *   1 = HANDSHAKE   – SYN+ACK sent, waiting for client's ACK
   *   2 = CONNECTED   – receiving META / DATA / FIN
   */
  int state = 0;

  int meta_received = 0;
  uint32_t expected_seq = 2; /* DATA packets start at seq = 2 */
  uint32_t total_segments = 0;

  /* Duplicate detection bitmap (one byte per segment, indexed by seq-2) */
  uint8_t *received = NULL;

  fd_set readfds;

  /* Longer initial timeout while waiting for first connection */
  int cur_timeout = 10;

  while (1) {

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval tv = { .tv_sec = cur_timeout, .tv_usec = 0 };

    int rv = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (rv <= 0) {
      fprintf(stderr, "ERROR: Timeout (state=%d)\n", state);
      free(received);
      close(sock);
      exit(EXIT_FAILURE);
    }

    ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&client_addr, &client_len);

    if (n < (ssize_t)RDT_HEADER_SIZE)
      continue;

    rdt_header_t hdr;
    uint8_t *payload = NULL;

    if (parse_packet(buffer, (size_t)n, &hdr, &payload) != 0)
      continue;

    /* ================= STATE 0: INIT – wait for SYN ================= */

    if (state == 0) {
      if (!(hdr.flags & FLAG_SYN))
        continue;

      conn_id = hdr.conn_id;
      cur_timeout = timeout;

      rdt_header_t synack = {
        .conn_id = conn_id,
        .seq     = 0,
        .ack     = hdr.seq + 1,
        .len     = 0,
        .flags   = FLAG_SYN | FLAG_ACK
      };
      send_pkt(sock, &synack, (struct sockaddr *)&client_addr, client_len);

      state = 1;
      continue;
    }

    /* All subsequent packets must carry the correct conn_id */
    if (hdr.conn_id != conn_id)
      continue;

    /* ================= STATE 1: HANDSHAKE – wait for client's ACK ================= */

    if (state == 1) {
      if (hdr.flags & FLAG_SYN) {
        /* Client re-sent SYN: our SYN+ACK was lost, resend it */
        rdt_header_t synack = {
          .conn_id = conn_id,
          .seq     = 0,
          .ack     = hdr.seq + 1,
          .len     = 0,
          .flags   = FLAG_SYN | FLAG_ACK
        };
        send_pkt(sock, &synack, (struct sockaddr *)&client_addr, client_len);
        continue;
      }

      if (hdr.flags & FLAG_ACK) {
        /* 3-way handshake complete */
        state = 2;
        continue;
      }

      /* Client sent META before we got its ACK (ACK was lost) – treat as
       * implicit handshake completion and fall through to META handling. */
      if (hdr.flags & FLAG_META) {
        state = 2;
        /* fall through to META handling below */
      } else {
        continue;
      }
    }

    /* ================= META (valid in state 2; also as implicit ACK from state 1) ================= */

    if (hdr.flags & FLAG_META) {

      if (!meta_received) {
        /* First META packet: parse and store metadata */
        if (hdr.len != sizeof(meta_payload_t)) {
          /* Malformed META: ignore */
          continue;
        }

        meta_payload_t meta;
        memcpy(&meta, payload, sizeof(meta));

        /* Correct byte-order conversion for all fields */
        uint64_t file_size    = be64toh(meta.file_size);
        total_segments        = ntohl(meta.total_segments);

        fprintf(stderr, "META received: file_size=%llu, segments=%u\n",
                (unsigned long long)file_size, total_segments);

        /* Allocate duplicate detection bitmap */
        free(received);
        if (total_segments > 0) {
          received = calloc(total_segments, sizeof(uint8_t));
          if (!received) {
            fprintf(stderr, "ERROR: calloc failed\n");
            close(sock);
            exit(EXIT_FAILURE);
          }
        } else {
          received = NULL;
        }

        meta_received = 1;
        expected_seq  = 2; /* DATA packets start at seq = 2 */
      }

      /* ACK the META packet: ack = META_seq + 1 = 1 + 1 = 2 */
      rdt_header_t ack = {
        .conn_id = conn_id,
        .seq     = 0,
        .ack     = 2,
        .len     = 0,
        .flags   = FLAG_ACK
      };
      send_pkt(sock, &ack, (struct sockaddr *)&client_addr, client_len);
      continue;
    }

    /* Ignore anything before META is received */
    if (!meta_received)
      continue;

    /* ================= DATA ================= */

    if (hdr.flags & FLAG_DATA) {

      /* Validate sequence number is within expected range */
      if (hdr.seq < 2 || hdr.seq >= 2 + total_segments) {
        /* Out of valid range: resend last cumulative ACK */
        rdt_header_t ack = {
          .conn_id = conn_id,
          .seq     = 0,
          .ack     = expected_seq,
          .len     = 0,
          .flags   = FLAG_ACK
        };
        send_pkt(sock, &ack, (struct sockaddr *)&client_addr, client_len);
        continue;
      }

      uint32_t idx = hdr.seq - 2; /* map seq → 0-based index */

      if (hdr.seq == expected_seq) {
        /* In-order packet: write and advance */
        if (!received[idx]) {
          fwrite(payload, 1, hdr.len, output);
          received[idx] = 1;
        }
        expected_seq++;
      }
      /* Out-of-order or duplicate (hdr.seq != expected_seq):
       * discard silently – Go-Back-N will cause retransmission. */

      /* Send cumulative ACK */
      rdt_header_t ack = {
        .conn_id = conn_id,
        .seq     = 0,
        .ack     = expected_seq,
        .len     = 0,
        .flags   = FLAG_ACK
      };
      send_pkt(sock, &ack, (struct sockaddr *)&client_addr, client_len);
      continue;
    }

    /* ================= FIN ================= */

    if (hdr.flags & FLAG_FIN) {

      /* Send ACK for client's FIN */
      rdt_header_t ack = {
        .conn_id = conn_id,
        .seq     = 0,
        .ack     = hdr.seq + 1,
        .len     = 0,
        .flags   = FLAG_ACK
      };
      send_pkt(sock, &ack, (struct sockaddr *)&client_addr, client_len);

      /* Send our own FIN */
      rdt_header_t fin = {
        .conn_id = conn_id,
        .seq     = 1,
        .ack     = expected_seq,
        .len     = 0,
        .flags   = FLAG_FIN
      };
      send_pkt(sock, &fin, (struct sockaddr *)&client_addr, client_len);

      /* Wait for client's final ACK (a few retries, then close anyway) */
      int retries = 4;
      while (retries-- > 0) {
        uint8_t buf2[RECV_BUFFER];
        struct sockaddr_storage from2;
        socklen_t from2_len = sizeof(from2);

        fd_set fds2;
        FD_ZERO(&fds2);
        FD_SET(sock, &fds2);
        struct timeval tv2 = { .tv_sec = timeout, .tv_usec = 0 };
        if (select(sock + 1, &fds2, NULL, NULL, &tv2) <= 0)
          break; /* timeout: assume client received our ACK+FIN */

        ssize_t n2 = recvfrom(sock, buf2, sizeof(buf2), 0,
                              (struct sockaddr *)&from2, &from2_len);
        if (n2 < (ssize_t)RDT_HEADER_SIZE)
          continue;

        rdt_header_t hdr2;
        if (parse_packet(buf2, (size_t)n2, &hdr2, NULL) != 0)
          continue;
        if (hdr2.conn_id != conn_id)
          continue;

        if (hdr2.flags & FLAG_ACK)
          break; /* client ACKed our FIN – done */

        if (hdr2.flags & FLAG_FIN) {
          /* Client re-sent FIN (our ACK was lost): resend ACK + FIN */
          send_pkt(sock, &ack, (struct sockaddr *)&client_addr, client_len);
          send_pkt(sock, &fin, (struct sockaddr *)&client_addr, client_len);
        }
      }

      /* Cleanup */
      fflush(output);
      if (output != stdout)
        fclose(output);

      free(received);
      close(sock);
      return;
    }
  }
}
