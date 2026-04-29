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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_PAYLOAD 1100
#define WINDOW_SIZE 5
#define BUFFER_SIZE 1500

/* ================= SEND ================= */

static void send_packet(int sock, struct sockaddr *addr, socklen_t addrlen, const rdt_header_t *hdr, const uint8_t *payload) {

  pkt_t pkt = build_packet(hdr, payload);
  sendto(sock, pkt.data, pkt.len, 0, addr, addrlen);
  free(pkt.data);
}

/* ================= RECV WITH TIMEOUT ================= */

static ssize_t recv_timeout(int sock, uint8_t *buf, size_t len, struct sockaddr *from, socklen_t *from_len, int timeout) {

  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);

  struct timeval tv = { .tv_sec = timeout, .tv_usec = 0 };

  int rv = select(sock + 1, &fds, NULL, NULL, &tv);
  if (rv <= 0)
    return -1;

  return recvfrom(sock, buf, len, 0, from, from_len);
}

/* ================= CLIENT ================= */

void start_client(int port, const char *address, FILE *input, int timeout) {
  printf("Starting client...\n");

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  /* resolve server */
  struct addrinfo hints = {0}, *res;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  if (getaddrinfo(address, port_str, &hints, &res) != 0) {
    fprintf(stderr, "resolve failed\n");
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

  uint32_t conn_id = (uint32_t)rand();

  /* ================= HANDSHAKE ================= */

  printf("Starting handshake...\n");

  while (1) {
    rdt_header_t syn = {
      .conn_id = conn_id,
      .seq = 0,
      .ack = 0,
      .len = 0,
      .flags = FLAG_SYN
    };

    send_packet(sock, (struct sockaddr *)&srv, srv_len, &syn, NULL);

    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, timeout);

    if (n <= 0)
      continue;

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    if ((rh.flags & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK))
      break;
  }

  /* final ACK */
  rdt_header_t ack = {
    .conn_id = conn_id,
    .seq = 1,
    .ack = rh.seq + 1,
    .len = 0,
    .flags = FLAG_ACK
  };

  send_packet(sock, (struct sockaddr *)&srv, srv_len, &ack, NULL);

  /* ================= LOAD FILE ================= */

  fseek(input, 0, SEEK_END);
  size_t file_size = ftell(input);
  fseek(input, 0, SEEK_SET);

  uint8_t *file = malloc(file_size);
  if (!file) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  fread(file, 1, file_size, input);

  uint32_t total = (file_size + MAX_PAYLOAD - 1) / MAX_PAYLOAD;

  /* ================= META ================= */

  meta_payload_t meta = {
    .file_size = htonl(file_size),
    .total_segments = htonl(total)
  };

  printf("Sending META...\n");

  while (1) {
    rdt_header_t mh = {
      .conn_id = conn_id,
      .seq = 1,
      .ack = 1,
      .len = sizeof(meta),
      .flags = FLAG_META
    };

    send_packet(sock, (struct sockaddr *)&srv, srv_len, &mh, (uint8_t *)&meta);

    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, timeout);

    if (n <= 0)
      continue;

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    if ((rh.flags & FLAG_ACK) && rh.ack == 2)
      break;
  }

  /* ================= GO-BACK-N ================= */

  uint32_t base = 2;
  uint32_t next = 2;

  printf("Sending data...\n");

  while (base < total + 2) {

    while (next < base + WINDOW_SIZE && next < total + 2) {

      uint32_t idx = next - 2;

      size_t off = idx * MAX_PAYLOAD;
      size_t len = (file_size - off > MAX_PAYLOAD) ? MAX_PAYLOAD : (file_size - off);

      rdt_header_t h = {
        .conn_id = conn_id,
        .seq = next,
        .ack = 0,
        .len = len,
        .flags = FLAG_DATA
      };

      send_packet(sock, (struct sockaddr *)&srv, srv_len, &h, file + off);

      next++;
    }

    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, timeout);

    if (n <= 0) {
      next = base;
      continue;
    }

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    if (rh.flags & FLAG_ACK) {
      if (rh.ack > base)
        base = rh.ack;
    }
  }

  free(file);

  /* ================= FIN ================= */

  printf("Sending FIN...\n");

  while (1) {
    rdt_header_t fin = {
      .conn_id = conn_id,
      .seq = total + 2,
      .ack = 0,
      .len = 0,
      .flags = FLAG_FIN
    };

    send_packet(sock, (struct sockaddr *)&srv, srv_len, &fin, NULL);

    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, timeout);

    if (n <= 0)
      continue;

    if (parse_packet(buffer, (size_t)n, &rh, NULL) != 0)
      continue;

    if (rh.flags & FLAG_ACK)
      break;
  }

  close(sock);
}
