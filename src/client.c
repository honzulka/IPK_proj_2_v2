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

  rdt_header_t syn = {
    .conn_id = conn_id,
    .seq = 0,
    .ack = 0,
    .len = 0,
    .flags = FLAG_SYN
  };
  printf("Starting handshake...\n");

  send_packet(sock, (struct sockaddr *)&srv, srv_len, &syn, NULL);
  n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, timeout);
  if (n <= 0) {
    fprintf(stderr, "Handshake timeout\n");
    exit(EXIT_FAILURE);
  }

  int i = 0;
  if ((i = parse_packet(buffer, (size_t)n, &rh, NULL)) != 0) {
    printf("error: %d\n", i);
    exit(EXIT_FAILURE);
  }
    
  if (!(rh.flags & FLAG_SYN) || !(rh.flags & FLAG_ACK))
    exit(EXIT_FAILURE);

  /* final ACK */
  rdt_header_t ack = {
    .conn_id = conn_id,
    .seq = 1,
    .ack = rh.seq + 1,
    .len = 0,
    .flags = FLAG_ACK
  };
  printf("Sending final ack for handshake...\n");

  send_packet(sock, (struct sockaddr *)&srv, srv_len, &ack, NULL);

  /* ================= LOAD INPUT ================= */

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

  /* ================= GO-BACK-N ================= */

  uint32_t base = 0;
  uint32_t next = 0;
  printf("Sending data...\n");
  while (base < total) {

    /* send window */
    while (next < base + WINDOW_SIZE && next < total) {

      size_t off = next * MAX_PAYLOAD;
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

    /* wait ACK */
    n = recv_timeout(sock, buffer, sizeof(buffer), (struct sockaddr *)&from, &from_len, timeout);
    printf("Received ack (ok)...\n");

    if (n <= 0) {
      /* timeout → resend window */
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

  rdt_header_t fin = {
    .conn_id = conn_id,
    .seq = total,
    .ack = 0,
    .len = 0,
    .flags = FLAG_FIN
  };
  printf("Send FIN...\n");

  send_packet(sock, (struct sockaddr *)&srv, srv_len, &fin, NULL);

  close(sock);
}
