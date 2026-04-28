/**
 * @file protocol.c
 * @brief UDP Reliable Data Transfer protocol implementation
 *
 * @author Jan Cernoch <xcernoj00> and ChatGPT (checksum functions)
 */

#include "protocol.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Compute RFC1071 checksum
 */
uint16_t compute_checksum(const uint8_t *data, size_t len) {
  uint32_t sum = 0;

  while (len > 1) {
    sum += ((uint16_t)data[0] << 8) | data[1];
    data += 2;
    len -= 2;
  }

  if (len == 1) {
    sum += ((uint16_t)data[0] << 8);
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)(~sum);
}

void header_hton(rdt_header_t *h) {
  h->conn_id = htonl(h->conn_id);
  h->seq     = htonl(h->seq);
  h->ack     = htonl(h->ack);
  h->len     = htons(h->len);
  h->checksum = htons(h->checksum);
}

void header_ntoh(rdt_header_t *h) {
  h->conn_id = ntohl(h->conn_id);
  h->seq     = ntohl(h->seq);
  h->ack     = ntohl(h->ack);
  h->len     = ntohs(h->len);
  h->checksum = ntohs(h->checksum);
}

pkt_t build_packet(const rdt_header_t *hdr, const uint8_t *payload) {
  pkt_t pkt = {0};

  if (!hdr) return pkt;

  size_t total_len = RDT_HEADER_SIZE + hdr->len;

  if (hdr->len > MAX_DATA_SIZE || total_len > MAX_UDP_PAYLOAD) {
    return pkt;
  }

  pkt.data = malloc(total_len);
  if (!pkt.data) {
    return pkt;
  }

  /* prepare header copy */
  rdt_header_t net_hdr = *hdr;
  net_hdr.checksum = 0;

  header_hton(&net_hdr);

  memcpy(pkt.data, &net_hdr, RDT_HEADER_SIZE);

  if (hdr->len > 0 && payload) {
    memcpy(pkt.data + RDT_HEADER_SIZE, payload, hdr->len);
  }

  /* compute checksum over whole packet */
  uint16_t cksum = compute_checksum(pkt.data, total_len);

  /* write checksum (network order!) */
  ((rdt_header_t *)pkt.data)->checksum = htons(cksum);

  pkt.len = total_len;
  return pkt;
}

int parse_packet(uint8_t *buffer, size_t len,
                 rdt_header_t *hdr_out,
                 uint8_t **payload_out) {

  if (!buffer || len < RDT_HEADER_SIZE) {
    return -1;
  }

  rdt_header_t *hdr = (rdt_header_t *)buffer;

  /* save and zero checksum for verification */
  uint16_t recv_cksum = hdr->checksum;
  hdr->checksum = 0;

  uint16_t calc_cksum = compute_checksum(buffer, len);

  /* restore checksum */
  hdr->checksum = recv_cksum;

  if (recv_cksum != htons(calc_cksum)) {
    return -1;
  }

  /* copy + convert header */
  memcpy(hdr_out, buffer, RDT_HEADER_SIZE);
  header_ntoh(hdr_out);

  /* validate length */
  if (RDT_HEADER_SIZE + hdr_out->len != len) {
    return -1;
  }

  if (payload_out) {
    *payload_out = buffer + RDT_HEADER_SIZE;
  }

  return 0;
}

void free_packet(pkt_t *pkt) {
  if (pkt && pkt->data) {
    free(pkt->data);
    pkt->data = NULL;
    pkt->len = 0;
  }
}
