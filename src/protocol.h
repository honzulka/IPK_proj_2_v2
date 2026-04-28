/**
 * @file protocol.h
 * @brief UDP Reliable Data Transfer protocol (RDT) - header definitions
 *
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* Assignment constraint */
#define MAX_UDP_PAYLOAD 1200

/* Header size (packed) = 4+4+4+2+1+2 = 17 B */
#define RDT_HEADER_SIZE 17

/* Max payload so that header + payload <= 1200 */
#define MAX_DATA_SIZE (MAX_UDP_PAYLOAD - RDT_HEADER_SIZE)

/* Flags */
#define FLAG_SYN  0x01
#define FLAG_ACK  0x02
#define FLAG_FIN  0x04
#define FLAG_DATA 0x08

/**
 * @brief On-wire header (packed)
 */
typedef struct {
  uint32_t conn_id;   /* connection identifier */
  uint32_t seq;       /* sequence number (segment index) */
  uint32_t ack;       /* cumulative ACK */
  uint16_t len;       /* payload length */
  uint8_t  flags;     /* FLAG_* */
  uint16_t checksum;  /* header + payload checksum */
} __attribute__((packed)) rdt_header_t;

/**
 * @brief Packet container
 */
typedef struct {
  uint8_t *data;
  size_t len;
} pkt_t;

/* --- API --- */

/**
 * @brief Convert header fields to network byte order
 */
void header_hton(rdt_header_t *h);

/**
 * @brief Convert header fields to host byte order
 */
void header_ntoh(rdt_header_t *h);

/**
 * @brief Compute checksum (RFC1071)
 */
uint16_t compute_checksum(const uint8_t *data, size_t len);

/**
 * @brief Build packet (allocates buffer)
 *
 * @param hdr Header in host byte order
 * @param payload Pointer to payload (can be NULL if len=0)
 * @return pkt_t (caller must free with free_packet)
 */
pkt_t build_packet(const rdt_header_t *hdr, const uint8_t *payload);

/**
 * @brief Parse packet (validates checksum and length)
 *
 * @param buffer Raw received buffer
 * @param len Length of buffer
 * @param hdr_out Output header (host order)
 * @param payload_out Pointer inside buffer
 * @return 0 on success, -1 on error
 */
int parse_packet(uint8_t *buffer, size_t len, rdt_header_t *hdr_out, uint8_t **payload_out);

/**
 * @brief Free packet buffer
 */
void free_packet(pkt_t *pkt);

#endif /* PROTOCOL_H */
