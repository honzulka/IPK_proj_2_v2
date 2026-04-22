/**
 * @file protocol.c
 * @brief Public protocol definitions and helpers for ICMP/ICMPv6 packet creation
 * 
 * @author Jan Cernoch <xcernoj00> and ChatGPT (checksum functions)
 */

#include "protocol.h"
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline uint64_t htonll(uint64_t value) {
    static const int num = 42;
    if (*(const char *)&num == 42) {
        uint32_t high = htonl((uint32_t)(value >> 32));
        uint32_t low = htonl((uint32_t)(value & 0xFFFFFFFFULL));
        return (((uint64_t)low) << 32) | high;
    } else {
        return value;
    }
}

static inline uint64_t ntohll(uint64_t value) {
    return htonll(value);
}

void header_hton(custom_header *h) {
    h->fragment_num = htonl(h->fragment_num);
    h->total_fragments = htonl(h->total_fragments);
    h->file_size = htonll(h->file_size);
}

void header_ntoh(custom_header *h) {
    h->fragment_num = ntohl(h->fragment_num);
    h->total_fragments = ntohl(h->total_fragments);
    h->file_size = ntohll(h->file_size);
}

/* Compute standard RFC 1071 checksum over memory (returns checksum in host order) */
static uint16_t checksum(void *b, int len) {
    uint16_t *buf = (uint16_t *)b;
    unsigned int sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

pkt_data prepare_packet(int af, int is_client, int custom_flag, uint16_t icmp_seq_num, uint8_t *payload, size_t payload_length, uint64_t file_size, int total_fragments, int fragment_num) {
    pkt_data pkt;
    if (af == AF_INET6) {
        size_t packet_len = sizeof(struct icmp6_hdr) + sizeof(custom_header) + payload_length;
        pkt.data = malloc(packet_len);
        if (!pkt.data) {
            perror("malloc");
            pkt.len = 0;
            return pkt;
        }
        memset(pkt.data, 0, packet_len);
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)pkt.data;
        custom_header *hdr = (custom_header *)(pkt.data + sizeof(struct icmp6_hdr));

        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_seq = htons(icmp_seq_num);
        icmp6->icmp6_id = is_client ? htons(CLIENT_ID) : htons(SERVER_ID);

        hdr->flag = custom_flag;
        hdr->fragment_num = (uint32_t)fragment_num;
        hdr->total_fragments = (uint32_t)total_fragments;
        hdr->file_size = (uint64_t)file_size;
        header_hton(hdr);

        if (payload_length > 0 && payload) {
            memcpy(pkt.data + sizeof(struct icmp6_hdr) + sizeof(custom_header), payload, payload_length);
        }
        icmp6->icmp6_cksum = 0; // computed by sender helper
        pkt.len = packet_len;
        return pkt;
    } else {
        size_t packet_len = sizeof(struct icmphdr) + sizeof(custom_header) + payload_length;
        pkt.data = malloc(packet_len);
        if (!pkt.data) {
            perror("malloc");
            pkt.len = 0;
            return pkt;
        }
        memset(pkt.data, 0, packet_len);
        struct icmphdr *icmp = (struct icmphdr *)pkt.data;
        custom_header *hdr = (custom_header *)(pkt.data + sizeof(struct icmphdr));

        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.sequence = htons(icmp_seq_num);
        icmp->un.echo.id = is_client ? htons(CLIENT_ID) : htons(SERVER_ID);

        hdr->flag = custom_flag;
        hdr->fragment_num = (uint32_t)fragment_num;
        hdr->total_fragments = (uint32_t)total_fragments;
        hdr->file_size = (uint64_t)file_size;
        header_hton(hdr);

        if (payload_length > 0 && payload) {
            memcpy(pkt.data + sizeof(struct icmphdr) + sizeof(custom_header), payload, payload_length);
        }

        icmp->checksum = checksum(pkt.data, (int)packet_len);
        pkt.len = packet_len;
        return pkt;
    }
}

int send_packet(int sockfd, struct sockaddr *dest_addr, socklen_t addrlen, uint8_t *data, size_t data_len) {
    ssize_t bytes_sent = sendto(sockfd, data, data_len, 0, dest_addr, addrlen);
    if (bytes_sent < 0) {
        perror("sendto");
        return -1;
    }
    if ((size_t)bytes_sent != data_len) {
        fprintf(stderr, "Error: Sent %zd bytes, expected %zu\n", bytes_sent, data_len);
        return -1;
    }
    return 0;
}

int send_packet_ipv6(int sockfd, struct sockaddr *dest_addr, socklen_t addrlen, uint8_t *data, size_t data_len) {
    (void)connect(sockfd, dest_addr, addrlen);

    struct sockaddr_storage local;
    socklen_t llen = sizeof(local);
    struct in6_addr src6 = {0}, dst6 = {0};
    if (getsockname(sockfd, (struct sockaddr *)&local, &llen) == 0 && local.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&local;
        src6 = sin6->sin6_addr;
    }
    if (dest_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)dest_addr;
        dst6 = d6->sin6_addr;
    }

    if (memcmp(&src6, &(struct in6_addr){0}, sizeof(src6)) != 0 && memcmp(&dst6, &(struct in6_addr){0}, sizeof(dst6)) != 0) {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)data;
        icmp6->icmp6_cksum = 0;

        struct {
            struct in6_addr src;
            struct in6_addr dst;
            uint32_t length;
            uint8_t zeros[3];
            uint8_t next_header;
        } __attribute__((packed)) pseudo;

        memcpy(&pseudo.src, &src6, sizeof(src6));
        memcpy(&pseudo.dst, &dst6, sizeof(dst6));
        pseudo.length = htonl((uint32_t)data_len);
        memset(pseudo.zeros, 0, sizeof(pseudo.zeros));
        pseudo.next_header = IPPROTO_ICMPV6;

        size_t total_len = sizeof(pseudo) + data_len;
        uint8_t *buf = malloc(total_len);
        if (buf) {
            memcpy(buf, &pseudo, sizeof(pseudo));
            memcpy(buf + sizeof(pseudo), data, data_len);
            uint16_t cks = checksum(buf, (int)total_len);
            free(buf);
            icmp6->icmp6_cksum = cks;
        }
    }

    ssize_t bytes_sent = sendto(sockfd, data, data_len, 0, dest_addr, addrlen);
    if (bytes_sent < 0) {
        perror("sendto");
        return -1;
    }
    if ((size_t)bytes_sent != data_len) {
        fprintf(stderr, "Error: Sent %zd bytes, expected %zu\n", bytes_sent, data_len);
        return -1;
    }
    return 0;
}

uint16_t icmpv6_checksum(struct in6_addr *src, struct in6_addr *dst, uint8_t *icmpv6_packet, size_t icmpv6_len) {
    // Build pseudo-header and sum bytes in network (big-endian) order
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t length;
        uint8_t zeros[3];
        uint8_t next_header;
    } __attribute__((packed)) pseudo;

    memcpy(&pseudo.src, src, sizeof(*src));
    memcpy(&pseudo.dst, dst, sizeof(*dst));
    pseudo.length = htonl((uint32_t)icmpv6_len);
    memset(pseudo.zeros, 0, sizeof(pseudo.zeros));
    pseudo.next_header = IPPROTO_ICMPV6;

    uint32_t sum = 0;
    const uint8_t *p = (const uint8_t *)&pseudo;
    size_t i;

    for (i = 0; i + 1 < sizeof(pseudo); i += 2) {
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    }
    if (i < sizeof(pseudo)) {
        sum += ((uint16_t)p[i] << 8);
    }

    p = (const uint8_t *)icmpv6_packet;
    for (i = 0; i + 1 < icmpv6_len; i += 2) {
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    }
    if (i < icmpv6_len) {
        sum += ((uint16_t)p[i] << 8);
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t folded = (uint16_t)sum;
    uint16_t chksum = (uint16_t)~folded;
    (void)0; /* debug prints removed */
    // Return checksum in network byte order
    return htons(chksum);
}
