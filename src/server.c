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

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(address, port_str, &hints, &res) != 0) {
    perror("getaddrinfo");
    return -1;
  }

  for (rp = res; rp != NULL; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock < 0)
      continue;

    if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    close(sock);
    sock = -1;
  }

  freeaddrinfo(res);
  return sock;
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
  int connected = 0;
  int meta_received = 0;

  uint32_t expected_seq = 0;
  uint32_t total_segments = 0;

  /* duplicate detection */
  uint8_t *received = NULL;

  fd_set readfds;

  int init_timeout = 10;

  while (1) {

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval tv = { .tv_sec = init_timeout, .tv_usec = 0 };

    int rv = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (rv <= 0) {
      fprintf(stderr, "ERROR: Timeout\n");
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

    /* ================= HANDSHAKE ================= */

    if (!connected) {
      if (!(hdr.flags & FLAG_SYN))
        continue;

      conn_id = hdr.conn_id;
      expected_seq = 0;

      init_timeout = timeout;

      rdt_header_t synack = {
        .conn_id = conn_id,
        .seq = 0,
        .ack = 0,
        .len = 0,
        .flags = FLAG_SYN | FLAG_ACK
      };

      pkt_t pkt = build_packet(&synack, NULL);

      sendto(sock, pkt.data, pkt.len, 0,
             (struct sockaddr *)&client_addr, client_len);

      free(pkt.data);

      connected = 1;
      continue;
    }

    
    /* ================= META ================= */

    if (hdr.flags & FLAG_META) {

      if (hdr.len != sizeof(meta_payload_t))
        continue;

      meta_payload_t meta;
      memcpy(&meta, payload, sizeof(meta));

      /* convert from network byte order */
      meta.file_size = ntohl(meta.file_size);
      meta.total_segments = ntohl(meta.total_segments);

      total_segments = meta.total_segments;

      /* allocate duplicate detection buffer */
      received = calloc(total_segments, sizeof(uint8_t));
      if (!received) {
        fprintf(stderr, "ERROR: malloc failed\n");
        exit(EXIT_FAILURE);
      }

      meta_received = 1;

      /* ACK META */
      rdt_header_t ack = {
        .conn_id = conn_id,
        .seq = 0,
        .ack = 0,
        .len = 0,
        .flags = FLAG_ACK
      };

      pkt_t pkt = build_packet(&ack, NULL);
      sendto(sock, pkt.data, pkt.len, 0,
             (struct sockaddr *)&client_addr, client_len);
      free(pkt.data);

      continue;
    }

    /* ignore everything before META */
    if (!meta_received)
      continue;
    
    if (hdr.conn_id != conn_id)
      continue;


    /* ================= DATA ================= */

    if (hdr.flags & FLAG_DATA) {

      /* duplicate packet */
      if (hdr.seq < total_segments && received[hdr.seq]) {

        /* resend last ACK */
        rdt_header_t ack = {
          .conn_id = conn_id,
          .seq = 0,
          .ack = expected_seq,
          .len = 0,
          .flags = FLAG_ACK
        };

        pkt_t pkt = build_packet(&ack, NULL);
        sendto(sock, pkt.data, pkt.len, 0,
               (struct sockaddr *)&client_addr, client_len);
        free(pkt.data);

        continue;
      }

      /* correct in-order packet */
      if (hdr.seq == expected_seq) {

        fwrite(payload, 1, hdr.len, output);
        received[hdr.seq] = 1;
        expected_seq++;

        /* move window forward (in case duplicates already arrived) */
        while (expected_seq < total_segments && received[expected_seq])
          expected_seq++;
      }

      /* cumulative ACK */
      rdt_header_t ack = {
        .conn_id = conn_id,
        .seq = 0,
        .ack = expected_seq,
        .len = 0,
        .flags = FLAG_ACK
      };

      pkt_t pkt = build_packet(&ack, NULL);

      sendto(sock, pkt.data, pkt.len, 0,
             (struct sockaddr *)&client_addr, client_len);

      free(pkt.data);
      continue;
    }

    /* ================= FIN ================= */

    if (hdr.flags & FLAG_FIN) {

      rdt_header_t ack = {
        .conn_id = conn_id,
        .seq = 0,
        .ack = hdr.seq + 1,
        .len = 0,
        .flags = FLAG_ACK
      };

      pkt_t pkt = build_packet(&ack, NULL);
      sendto(sock, pkt.data, pkt.len, 0,
             (struct sockaddr *)&client_addr, client_len);
      free(pkt.data);

      rdt_header_t fin = {
        .conn_id = conn_id,
        .seq = 0,
        .ack = expected_seq,
        .len = 0,
        .flags = FLAG_FIN
      };

      pkt = build_packet(&fin, NULL);
      sendto(sock, pkt.data, pkt.len, 0,
             (struct sockaddr *)&client_addr, client_len);
      free(pkt.data);

      if (output != stdout)
        fclose(output);

      free(received);
      close(sock);
      return;
    }
  }
}
