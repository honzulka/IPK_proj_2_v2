/**
 * @file protocol.h
 * @brief Public protocol definitions and helpers for ICMP/ICMPv6 packet creation
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <netinet/in.h> /* htonl, htons, ntohl, ntohs, struct in6_addr */
#include <stddef.h> /* size_t */
#include <stdint.h>
#include <sys/socket.h> /* struct sockaddr, socklen_t */

/**
 * Default symmetric key used for AES operations in tests/examples.
 */
#define SECRET_KEY "xcernoj00"

/** Maximum payload bytes in a single fragment (ICMP data segment). */
#define MAX_FRAGMENT_SIZE 1200

/** General receive buffer size used by tests and helpers. */
#define BUFFER_SIZE 1500

/** Identifier placed into ICMP id field for client-originated packets. */
#define CLIENT_ID 0x1234

/** Identifier placed into ICMP id field for server-originated packets. */
#define SERVER_ID 0x4321

/** Protocol packet flags used in the custom header (1 byte). */
typedef enum {
    FLAG_HELLO = 0, /**< initial packet (SYN) */
    FLAG_READY = 1, /**< server reply (SYN-ACK) */
    FLAG_ACK = 2, /**< acknowledgement */
    FLAG_META = 3, /**< metadata packet */
    FLAG_DATA = 4, /**< data packet */
    FLAG_FIN = 5, /**< client terminates transfer */
    FLAG_OK = 6, /**< server: all OK */
    FLAG_FAIL = 7 /**< server: failure / missing fragments */
} flag_t;

/**
 * @brief Simple buffer/length pair used to return prepared packets.
 */
typedef struct {
    uint8_t *data; /**< pointer to allocated packet bytes; caller must free */
    size_t len; /**< length of the allocated buffer in bytes */
} pkt_data;

/**
 * @brief On-wire custom header appended to ICMP echo payloads.
 *
 * The struct is packed to avoid padding so its byte layout is stable across
 * platforms. Multi-byte fields must be converted to network byte order using
 * header_hton() before transmission and header_ntoh() after reception.
 */
typedef struct {
    uint8_t flag; /**< one of flag_t values */
    uint32_t fragment_num; /**< fragment sequence number (network order when sent) */
    uint32_t total_fragments; /**< total number of fragments (network order when sent) */
    uint64_t file_size; /**< original file size in bytes (network order when sent) */
} __attribute__((packed)) custom_header;

/**
 * @brief Convert custom_header fields from host to network byte order.
 *
 * This mutates the provided header so it is safe to memcpy into a packet
 * buffer for transmission.
 *
 * @param h Pointer to the header to convert (must be non-NULL).
 */
void header_hton(custom_header *h);

/**
 * @brief Convert custom_header fields from network to host byte order.
 *
 * Inverse operation of header_hton(). Use after receiving a packet and
 * extracting the custom header bytes.
 *
 * @param h Pointer to header to convert (must be non-NULL).
 */
void header_ntoh(custom_header *h);

/**
 * @brief Build an ICMP or ICMPv6 packet containing the custom header + payload.
 *
 * This function allocates a new buffer (returned in pkt_data.data) which the
 * caller must free when no longer needed. For IPv6, the returned ICMPv6
 * checksum field is left zero — the sender helper computes the pseudo-header
 * checksum prior to sending.
 *
 * @param af Address family: AF_INET or AF_INET6.
 * @param is_client Non-zero when the packet is client-originated (affects id).
 * @param custom_flag One of the FLAG_* constants to set in the custom header.
 * @param icmp_seq_num Sequence number to place in the ICMP header.
 * @param payload Pointer to payload bytes to append after the custom header
 *                (may be NULL if payload_length == 0).
 * @param payload_length Length of payload in bytes.
 * @param file_size File size to encode into the custom header (host order).
 * @param total_fragments Total number of fragments (host order).
 * @param fragment_num Fragment index for this packet (host order).
 * @return pkt_data with allocated buffer and length; on error, data==NULL and len==0.
 */
pkt_data prepare_packet(int af, int is_client, int custom_flag, uint16_t icmp_seq_num,
    uint8_t *payload, size_t payload_length, uint64_t file_size,
    int total_fragments, int fragment_num);

/**
 * @brief Send a prepared packet using sendto().
 *
 * This is a convenience wrapper around sendto(). If dest_addr->sa_family is
 * AF_INET6 the implementation may call an IPv6-specific helper that computes
 * the ICMPv6 pseudo-header checksum prior to transmission.
 *
 * @param sockfd Open socket file descriptor for sending (raw socket).
 * @param dest_addr Pointer to destination sockaddr (AF_INET or AF_INET6).
 * @param addrlen Length of destination address structure.
 * @param data Pointer to packet bytes to send.
 * @param data_len Length of the packet in bytes.
 * @return 0 on success, -1 on failure (errno set).
 */
int send_packet(int sockfd, struct sockaddr *dest_addr, socklen_t addrlen,
    uint8_t *data, size_t data_len);

/**
 * @brief Compute the ICMPv6 checksum for a packet using the IPv6 pseudo-header.
 *
 * The function sums the pseudo-header (src/dst/length/zeros/next-header) and
 * the ICMPv6 packet payload using 16-bit one's-complement arithmetic and
 * returns the checksum in network byte order.
 *
 * @param src Pointer to the source IPv6 address.
 * @param dst Pointer to the destination IPv6 address.
 * @param icmpv6_packet Pointer to the ICMPv6 packet bytes (header + payload).
 * @param icmpv6_len Length of the ICMPv6 packet in bytes.
 * @return 16-bit checksum in network byte order (htons-style).
 */
uint16_t icmpv6_checksum(struct in6_addr *src, struct in6_addr *dst,
    uint8_t *icmpv6_packet, size_t icmpv6_len);

/**
 * @note For IPv6 the ICMPv6 checksum requires an IPv6 pseudo-header (source +
 * destination addresses + length + next-header). To keep a single source of
 * truth we compute and insert the ICMPv6 checksum inside the IPv6 send helper
 * which is used internally by send_packet() for AF_INET6 destinations.
 *
 * Callers of prepare_packet() should leave the ICMPv6 checksum field zero;
 * send_packet() will ensure the correct pseudo-header checksum is computed
 * before the packet is sent.
 */

/**
 * @brief IPv6-specific send helper that computes the pseudo-header checksum.
 *
 * This helper computes the ICMPv6 checksum and performs the send. It is
 * intended for internal use by send_packet() and accepts a generic
 * destination address pointer.
 *
 * @param sockfd Open socket file descriptor.
 * @param dest_addr Pointer to struct sockaddr containing the IPv6 address.
 * @param addrlen Length of dest_addr (sizeof(struct sockaddr_in6)).
 * @param data Packet bytes to send (icmp6 header + payload).
 * @param data_len Length of data in bytes.
 * @return 0 on success, -1 on failure.
 */
int send_packet_ipv6(int sockfd, struct sockaddr *dest_addr, socklen_t addrlen,
    uint8_t *data, size_t data_len);

#endif /* PROTOCOL_H */