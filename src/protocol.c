/**
 * @file protocol.c
 * @brief UDP Reliable Data Transfer protocol implementation.
 *
 * @author Jan Cernoch <xcernoj00>
 */

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ================= CHECKSUM ================= */

uint16_t compute_checksum(const void *data, size_t len) {
  const uint8_t *buf = (const uint8_t *)data;
  uint32_t sum = 0;

  /* Process 2 bytes at a time (RFC 1071) */
  while (len > 1) {
    sum += ((uint16_t)buf[0] << 8) | buf[1];
    buf += 2;
    len -= 2;
  }

  /* Odd trailing byte: pad with zero on the right */
  if (len == 1) {
    sum += (uint16_t)buf[0] << 8;
  }

  /* Fold 32-bit sum into 16 bits */
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return (uint16_t)(~sum);
}

/* ================= BUILD ================= */

pkt_t build_packet(const rdt_header_t *hdr, const uint8_t *payload) {
  pkt_t pkt = {0};

  if (!hdr)
    return pkt;

  if (hdr->len > MAX_PAYLOAD_SIZE)
    return pkt;

  size_t total_len = RDT_HEADER_SIZE + hdr->len;

  uint8_t *buf = malloc(total_len);
  if (!buf)
    return pkt;

  rdt_header_t tmp = *hdr;

  /* convert to network byte order */
  tmp.conn_id = htonl(tmp.conn_id);
  tmp.seq     = htonl(tmp.seq);
  tmp.ack     = htonl(tmp.ack);
  tmp.len     = htons(tmp.len);
  tmp.checksum = 0;

  memcpy(buf, &tmp, RDT_HEADER_SIZE);

  if (payload && hdr->len > 0) {
    memcpy(buf + RDT_HEADER_SIZE, payload, hdr->len);
  }

  /* compute checksum */
  uint16_t cks = compute_checksum(buf, total_len);

  /* store checksum in network byte order */
  ((rdt_header_t *)buf)->checksum = htons(cks);

  pkt.data = buf;
  pkt.len = total_len;
  return pkt;
}

/* ================= PARSE ================= */

int parse_packet(const uint8_t *buffer, size_t len, rdt_header_t *hdr_out, uint8_t **payload_out) {
  if (!buffer || !hdr_out)
    return -11;

  if (len < RDT_HEADER_SIZE)
    return -21;

  /* checksum (raw) */
  uint16_t recv_cks = ((const rdt_header_t *)buffer)->checksum;
  recv_cks = ntohs(recv_cks);

  /* copy header first */
  memcpy(hdr_out, buffer, RDT_HEADER_SIZE);

  /* convert immediately */
  hdr_out->conn_id = ntohl(hdr_out->conn_id);
  hdr_out->seq     = ntohl(hdr_out->seq);
  hdr_out->ack     = ntohl(hdr_out->ack);
  hdr_out->len     = ntohs(hdr_out->len);

  /* now validate length BEFORE touching payload */
  size_t pkt_len = RDT_HEADER_SIZE + hdr_out->len;

  if (pkt_len != len)
    return -41;

  if (hdr_out->len > MAX_PAYLOAD_SIZE)
    return -51;

  /* checksum validation over exact packet */
  uint8_t tmp[pkt_len];
  memcpy(tmp, buffer, pkt_len);
  memset(tmp + offsetof(rdt_header_t, checksum), 0, sizeof(uint16_t));

  uint16_t calc_cks = compute_checksum(tmp, pkt_len);

  if (recv_cks != calc_cks)
    return -31;

  /* flags check – all defined flags are valid */
  uint8_t allowed = FLAG_SYN | FLAG_ACK | FLAG_FIN | FLAG_DATA | FLAG_META;
  if (hdr_out->flags & ~allowed)
    return -61;

  if (payload_out)
    *payload_out = (uint8_t *)(buffer + RDT_HEADER_SIZE);

  return 0;
}

/* ================= VALIDATION ================= */

int header_valid(const rdt_header_t *hdr, const uint8_t *buffer, size_t len) {
  (void)buffer; /* unused */

  if (!hdr)
    return 0;

  if (len < RDT_HEADER_SIZE)
    return 0;

  if (hdr->len > MAX_PAYLOAD_SIZE)
    return 0;

  if ((size_t)RDT_HEADER_SIZE + hdr->len != len)
    return 0;

  return 1;
}
