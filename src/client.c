/**
 * @file client.c
 * @brief UDP client implementing reliable data transfer (Go-Back-N).
 *
 * @author Jan Cernoch <xcernoj00>
 */

#define _DEFAULT_SOURCE

#include "client.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <endian.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_PAYLOAD 1100
#define WINDOW_SIZE 32
#define BUFFER_SIZE 1500

/* ================= SEND ================= */

static void send_packet(int sock, struct sockaddr *addr, socklen_t addrlen, const rdt_header_t *hdr, const uint8_t *payload) {
  pkt_t pkt = build_packet(hdr, payload);
  if (pkt.data) {
    sendto(sock, pkt.data, pkt.len, 0, addr, addrlen);
    free(pkt.data);
  }
}

/* ================= RECV WITH TIMEOUT ================= */

static ssize_t recv_timeout(int sock, uint8_t *buf, size_t len, struct sockaddr *from, socklen_t *from_len, int timeout_ms) {
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);

  if (timeout_ms <= 0)
    timeout_ms = 1;
  struct timeval tv = {
    .tv_sec = timeout_ms / 1000,
    .tv_usec = (timeout_ms % 1000) * 1000
  };

  int rv = select(sock + 1, &fds, NULL, NULL, &tv);
  if (rv <= 0)
    return -1;

  return recvfrom(sock, buf, len, 0, from, from_len);
}

static long long now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

static int retransmit_timeout_ms(int timeout_s) {
  int ms = timeout_s * 200;
  if (ms < 60)
    ms = 60;
  if (ms > 250)
    ms = 250;
  return ms;
}

static int progress_timed_out(long long last_progress_ms, int timeout_s) {
  return now_ms() - last_progress_ms >= (long long)timeout_s * 1000LL;
}

/* ================= CLIENT ================= */

void start_client(int port, const char *address, FILE *input, int timeout, int verbose) {
  if (verbose)
    fprintf(stderr, "Starting client...\n");

  /* Seed random number generator */
  srand((unsigned)time(NULL) ^ (unsigned)getpid());

  /* Resolve server address (supports IPv4, IPv6, hostnames) */
  struct addrinfo hints = {0}, *res;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  if (getaddrinfo(address, port_str, &hints, &res) != 0) {
    fprintf(stderr, "ERROR: resolve failed for '%s'\n", address);
    exit(EXIT_FAILURE);
  }

  /* Create socket matching the resolved address family */
  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    perror("socket");
    freeaddrinfo(res);
    exit(EXIT_FAILURE);
  }

  struct sockaddr_storage srv;
  socklen_t srv_len = res->ai_addrlen;
  memcpy(&srv, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);

  uint8_t buffer[BUFFER_SIZE];
  struct sockaddr_storage from;
  socklen_t from_len = sizeof(from);

  rdt_header_t rh;
  ssize_t n;
  int rtx_ms = retransmit_timeout_ms(timeout);
  long long last_progress_ms = now_ms();

  uint32_t conn_id = (uint32_t)rand();
  if (conn_id == 0) conn_id = 1; /* avoid zero conn_id */

  /* ================= HANDSHAKE ================= */

  if (verbose)
    fprintf(stderr, "Starting handshake...\n");

  while (1) {
    rdt_header_t syn = {
      .conn_id = conn_id,
      .seq = 0,
      .ack = 0,
      .len = 0,
      .flags = FLAG_SYN
    };

    send_packet(sock, (struct sockaddr *)&srv, srv_len, &syn, NULL);

    from_len = sizeof(from);
    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, rtx_ms);

    if (n <= 0) {
      if (progress_timed_out(last_progress_ms, timeout)) {
        fprintf(stderr, "ERROR: Timeout without progress during handshake\n");
        close(sock);
        exit(EXIT_FAILURE);
      }
      continue;
    }

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    /* Verify this reply belongs to our connection */
    if (rh.conn_id != conn_id)
      continue;

    if ((rh.flags & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK)) {
      last_progress_ms = now_ms();
      break;
    }
  }

  /* Final ACK completing 3-way handshake */
  rdt_header_t ack = {
    .conn_id = conn_id,
    .seq = 1,
    .ack = rh.seq + 1,
    .len = 0,
    .flags = FLAG_ACK
  };

  send_packet(sock, (struct sockaddr *)&srv, srv_len, &ack, NULL);

  /* ================= LOAD INPUT DATA (stream-safe, supports stdin) ================= */

  uint8_t *file = NULL;
  size_t file_size = 0;
  {
    uint8_t tmp_buf[4096];
    size_t cap = 0;
    size_t nr;
    while ((nr = fread(tmp_buf, 1, sizeof(tmp_buf), input)) > 0) {
      if (file_size + nr > cap) {
        size_t new_cap = (cap == 0) ? 65536 : cap * 2;
        while (new_cap < file_size + nr) new_cap *= 2;
        uint8_t *newbuf = realloc(file, new_cap);
        if (!newbuf) {
          perror("realloc");
          free(file);
          close(sock);
          exit(EXIT_FAILURE);
        }
        file = newbuf;
        cap = new_cap;
      }
      memcpy(file + file_size, tmp_buf, nr);
      file_size += nr;
    }
    if (ferror(input)) {
      perror("fread");
      free(file);
      close(sock);
      exit(EXIT_FAILURE);
    }
  }

  uint32_t total = (uint32_t)((file_size + MAX_PAYLOAD - 1) / MAX_PAYLOAD);

  /* ================= META ================= */

  /* Use htobe64 for the 64-bit file_size field */
  meta_payload_t meta = {
    .file_size       = htobe64((uint64_t)file_size),
    .total_segments  = htonl(total)
  };

  if (verbose)
    fprintf(stderr, "Sending META (file_size=%zu, segments=%u)...\n", file_size, total);

  while (1) {
    rdt_header_t mh = {
      .conn_id = conn_id,
      .seq = 1,
      .ack = 1,
      .len = sizeof(meta),
      .flags = FLAG_META
    };

    send_packet(sock, (struct sockaddr *)&srv, srv_len, &mh, (uint8_t *)&meta);

    from_len = sizeof(from);
    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, rtx_ms);

    if (n <= 0) {
      if (progress_timed_out(last_progress_ms, timeout)) {
        fprintf(stderr, "ERROR: Timeout without progress during metadata transfer\n");
        free(file);
        close(sock);
        exit(EXIT_FAILURE);
      }
      continue;
    }

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    if (rh.conn_id != conn_id)
      continue;

    /* Server ACKs META with ack = META_seq + 1 = 1 + 1 = 2 */
    if ((rh.flags & FLAG_ACK) && rh.ack == 2) {
      last_progress_ms = now_ms();
      break;
    }
  }

  /* ================= GO-BACK-N DATA TRANSFER ================= */

  uint32_t base = 2;
  uint32_t next = 2;
  uint32_t last_ack = 0;
  int dup_ack_count = 0;

  if (verbose)
    fprintf(stderr, "Sending data (%u segment(s))...\n", total);

  while (base < total + 2) {

    /* Fill the sliding window with new packets */
    while (next < base + WINDOW_SIZE && next < total + 2) {

      uint32_t idx = next - 2;

      size_t off = (size_t)idx * MAX_PAYLOAD;
      size_t seg_len = (file_size - off > MAX_PAYLOAD) ? MAX_PAYLOAD : (file_size - off);

      rdt_header_t h = {
        .conn_id = conn_id,
        .seq = next,
        .ack = 0,
        .len = (uint16_t)seg_len,
        .flags = FLAG_DATA
      };

      send_packet(sock, (struct sockaddr *)&srv, srv_len, &h, file + off);

      next++;
    }

    from_len = sizeof(from);
    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, rtx_ms);

    if (n <= 0) {
      if (progress_timed_out(last_progress_ms, timeout)) {
        fprintf(stderr, "ERROR: Timeout without progress during data transfer\n");
        free(file);
        close(sock);
        exit(EXIT_FAILURE);
      }
      /* Timeout: Go-Back-N retransmit from base */
      next = base;
      continue;
    }

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    if (rh.conn_id != conn_id)
      continue;

    if (rh.flags & FLAG_ACK) {
      if (rh.ack > total + 2) {
        /* ignore invalid cumulative ACK */
      } else if (rh.ack > base) {
        base = rh.ack;
        last_progress_ms = now_ms();
        last_ack = rh.ack;
        dup_ack_count = 0;
      } else if (rh.ack == base && base < total + 2) {
        if (rh.ack == last_ack) {
          dup_ack_count++;
        } else {
          last_ack = rh.ack;
          dup_ack_count = 1;
        }
        if (dup_ack_count >= 3) {
          next = base; /* fast retransmit */
          dup_ack_count = 0;
        }
      }
    }
  }

  free(file);

  /* ================= FIN (4-way teardown) ================= */

  if (verbose)
    fprintf(stderr, "Sending FIN...\n");

  int fin_acked = 0;

  while (1) {
    rdt_header_t fin = {
      .conn_id = conn_id,
      .seq = total + 2,
      .ack = 0,
      .len = 0,
      .flags = FLAG_FIN
    };
    send_packet(sock, (struct sockaddr *)&srv, srv_len, &fin, NULL);

    from_len = sizeof(from);
    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, rtx_ms);

    if (n <= 0) {
      if (fin_acked) {
        /* We already got ACK for our FIN; peer may have closed after its FIN. */
        break;
      }
      if (progress_timed_out(last_progress_ms, timeout)) {
        fprintf(stderr, "ERROR: Timeout without progress during session termination\n");
        close(sock);
        exit(EXIT_FAILURE);
      }
      continue;
    }

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    if (rh.conn_id != conn_id)
      continue;

    if (rh.flags & FLAG_ACK) {
      if (!fin_acked)
        fin_acked = 1;
      last_progress_ms = now_ms();
    }

    if (rh.flags & FLAG_FIN) {
      /* Server's FIN: send final ACK and close */
      rdt_header_t final_ack = {
        .conn_id = conn_id,
        .seq = total + 3,
        .ack = rh.seq + 1,
        .len = 0,
        .flags = FLAG_ACK
      };
      send_packet(sock, (struct sockaddr *)&srv, srv_len, &final_ack, NULL);
      last_progress_ms = now_ms();
      break;
    }
  }

  if (verbose)
    fprintf(stderr, "Transfer complete.\n");
  close(sock);
}
