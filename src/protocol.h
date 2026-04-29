/**
 * @file protocol.h
 * @brief UDP Reliable Data Transfer protocol (RDT) - header definitions.
 *
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* Maximum payload size (fits into UDP safely) */
#define MAX_PAYLOAD_SIZE 1100

/* Header size (packed) */
#define RDT_HEADER_SIZE 17

/* Flags */
#define FLAG_SYN  0x01
#define FLAG_ACK  0x02
#define FLAG_FIN  0x04
#define FLAG_DATA 0x08
#define FLAG_META 0x10

/* Packet structure */
typedef struct {
  uint8_t *data;
  size_t len;
} pkt_t;

/* RDT header (packed!) */
typedef struct __attribute__((packed)) {
  uint32_t conn_id;
  uint32_t seq;
  uint32_t ack;
  uint16_t len;
  uint8_t flags;
  uint16_t checksum;
} rdt_header_t;

/* Metadata payload */
typedef struct __attribute__((packed)) {
  uint64_t file_size;
  uint32_t total_segments;
} meta_payload_t;

/* Compute checksum (RFC1071 style) */
uint16_t compute_checksum(const void *data, size_t len);

/* Build packet (allocates buffer) */
pkt_t build_packet(const rdt_header_t *hdr, const uint8_t *payload);

/* Parse packet (validates checksum) */
int parse_packet(const uint8_t *buffer, size_t len, rdt_header_t *hdr_out, uint8_t **payload_out);

/* Validate header + payload */
int header_valid(const rdt_header_t *hdr, const uint8_t *buffer, size_t len);

#endif
