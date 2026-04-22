/**
 * @file client.c
 * @brief Client API for initiating file transfers.
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#define _DEFAULT_SOURCE

#include "client.h"
#include "crypto.h"
#include "protocol.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *get_filename(const char *path) {
    const char *filename = strrchr(path, '/'); // find last '/'
    if (filename) {
        return filename + 1; // skip '/'
    } else {
        return path; // no '/' → it's just a name
    }
}

static int validate_hostname(const char *hostname) {
    struct addrinfo hints, *res;
    int result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;

    result = getaddrinfo(hostname, NULL, &hints, &res);
    if (result != 0) {
        return -1; // Invalid domain
    }

    freeaddrinfo(res);
    return 0;
}

static void start_sending(const char *target, const char *filepath, int verbose) {

    // Open the file to be sent
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("\nfopen");
        exit(EXIT_FAILURE);
    }

    const char *filename = get_filename(filepath);

    // Resolve target hostname to IP address (prefer IPv6, fallback to IPv4)
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6
    hints.ai_socktype = SOCK_RAW;

    if (getaddrinfo(target, NULL, &hints, &res) != 0) {
        perror("\ngetaddrinfo");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // Find first IPv4 or IPv6 address
    int af = AF_UNSPEC;
    struct sockaddr_storage dest_addr;
    socklen_t dest_addrlen = 0;
    char addr_str[INET6_ADDRSTRLEN];

    for (rp = res; rp != NULL; rp = rp->ai_next) {

        if (rp->ai_family == AF_INET && af == AF_UNSPEC) {
            af = AF_INET;
            memcpy(&dest_addr, rp->ai_addr, sizeof(struct sockaddr_in));
            dest_addrlen = sizeof(struct sockaddr_in);
            inet_ntop(AF_INET, &((struct sockaddr_in *)&dest_addr)->sin_addr, addr_str, sizeof(addr_str));
            break; // Prefer IPv4
        } else if (rp->ai_family == AF_INET6) {
            af = AF_INET6;
            memcpy(&dest_addr, rp->ai_addr, sizeof(struct sockaddr_in6));
            dest_addrlen = sizeof(struct sockaddr_in6);
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&dest_addr)->sin6_addr, addr_str, sizeof(addr_str));
            break;
        }
    }
    freeaddrinfo(res);

    if (af == AF_UNSPEC) {
        fprintf(stderr, "\nError: Could not resolve target address\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if (verbose) {
        printf("Target: %s (%s)\n", addr_str, af == AF_INET6 ? "IPv6" : "IPv4");
        printf("Filename: %s\n\n", filename);
    }

    // Create raw ICMP/ICMPv6 socket (requires superuser privileges)
    int sockfd;
    if (af == AF_INET6) {
        sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    } else {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (sockfd < 0) {
        perror("\nsocket");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    int icmp_s = 1; // ICMP sequence number (for sending packets)
    int old_icmp_s = 0; // Old ICMP sequence number

    // Send initial FLAG_HELLO packet
    pkt_data pkt = prepare_packet(af, 1, FLAG_HELLO, icmp_s++, NULL, 0, 0, 0, 0);
    if (af == AF_INET6) {
        if (send_packet_ipv6(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
            free(pkt.data);
            close(sockfd);
            fclose(file);
            exit(EXIT_FAILURE);
        }
    } else {
        if (send_packet(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
            free(pkt.data);
            close(sockfd);
            fclose(file);
            exit(EXIT_FAILURE);
        }
    }
    free(pkt.data);

    if (verbose)
        printf("Sent FLAG_HELLO packet\n");

    // Wait for FLAG_READY response
    uint8_t buffer[BUFFER_SIZE];
    while (1) {
        struct sockaddr_storage src_addr;
        socklen_t addrlen = sizeof(src_addr);
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addrlen);
        if (n < 0) {
            perror("\nrecvfrom");
            close(sockfd);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        uint16_t echo_id = 0;
        uint16_t echo_seq = 0;
        custom_header *hdr = NULL;

        if (af == AF_INET) {
            // Parse IPv4 + ICMP
            struct iphdr *ip = (struct iphdr *)buffer;
            int ip_header_len = ip->ihl * 4;
            struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_header_len);
            hdr = (custom_header *)(buffer + ip_header_len + sizeof(struct icmphdr));
            echo_id = ntohs(icmp->un.echo.id);
            echo_seq = ntohs(icmp->un.echo.sequence);
        } else {
            // Parse ICMPv6 (no IP header in received data for raw ICMPv6)
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
            hdr = (custom_header *)(buffer + sizeof(struct icmp6_hdr));
            echo_id = ntohs(icmp6->icmp6_id);
            echo_seq = ntohs(icmp6->icmp6_seq);
        }

        if (echo_id != SERVER_ID) {
            continue; // Not from server, ignore
        }

        if (echo_seq == old_icmp_s) {
            continue; // Duplicate packet, ignore
        }
        old_icmp_s = echo_seq;

        // Check for FLAG_READY
        if (hdr->flag == FLAG_READY) {
            if (verbose)
                printf("Received FLAG_READY packet\n");
            break;
        } else {
            if (verbose)
                printf("Unexpected flag received. Ignoring...\n");
        }
    }

    // Read entire file into plaintext buffer
    fseek(file, 0, SEEK_END);
    size_t plaintext_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t *plain_file = malloc(plaintext_len);
    if (!plain_file) {
        fprintf(stderr, "\nError: Unable to allocate memory for file.\n");
        close(sockfd);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    if (fread(plain_file, 1, plaintext_len, file) != plaintext_len) {
        perror("\nfread");
        free(plain_file);
        close(sockfd);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fclose(file);

    // Encrypt: IMPORTANT - do NOT pre-allocate encrypted_file; aes_encrypt allocates it.
    uint8_t *encrypted_file = NULL;
    size_t encrypted_file_len = 0;
    if (!aes_encrypt(plain_file, plaintext_len, &encrypted_file, &encrypted_file_len, SECRET_KEY)) {
        fprintf(stderr, "\nError: AES encryption failed.\n");
        free(plain_file);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // We don't need plaintext anymore
    free(plain_file);

    // Compute fragments based on ciphertext length
    int total_fragments = (encrypted_file_len + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;

    // Send metadata packet: send ciphertext length (encrypted_file_len) instead of plaintext length
    pkt = prepare_packet(af, 1, FLAG_META, icmp_s++, (uint8_t *)filename, strlen(filename), (uint64_t)encrypted_file_len, total_fragments, 0);
    if (af == AF_INET6) {
        if (send_packet_ipv6(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
            free(pkt.data);
            close(sockfd);
            free(encrypted_file);
            exit(EXIT_FAILURE);
        }
    } else {
        if (send_packet(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
            free(pkt.data);
            close(sockfd);
            free(encrypted_file);
            exit(EXIT_FAILURE);
        }
    }
    free(pkt.data);

    if (verbose)
        printf("Sent FLAG_META packet\n");

    // Wait for FLAG_ACK response
    while (1) {
        struct sockaddr_storage src_addr;
        socklen_t addrlen = sizeof(src_addr);
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
            (struct sockaddr *)&src_addr, &addrlen);
        if (n < 0) {
            perror("\nrecvfrom");
            close(sockfd);
            free(encrypted_file);
            exit(EXIT_FAILURE);
        }

        uint16_t echo_id = 0;
        uint16_t echo_seq = 0;
        custom_header *hdr = NULL;

        if (af == AF_INET) {
            struct iphdr *ip = (struct iphdr *)buffer;
            int ip_header_len = ip->ihl * 4;
            struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_header_len);
            hdr = (custom_header *)(buffer + ip_header_len + sizeof(struct icmphdr));
            echo_id = ntohs(icmp->un.echo.id);
            echo_seq = ntohs(icmp->un.echo.sequence);
        } else {
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
            hdr = (custom_header *)(buffer + sizeof(struct icmp6_hdr));
            echo_id = ntohs(icmp6->icmp6_id);
            echo_seq = ntohs(icmp6->icmp6_seq);
        }

        if (echo_id != SERVER_ID) {
            // Not from server, ignore
            continue;
        }

        if (echo_seq == old_icmp_s) {
            continue; // duplicate packet, ignore
        }
        old_icmp_s = echo_seq;

        if (hdr->flag == FLAG_ACK) {
            if (verbose)
                printf("Received FLAG_ACK packet\n");
            break;
        } else {
            if (verbose)
                printf("Unexpected flag received. Ignoring...\n");
        }
    }

    // Send encrypted file data in fragments (read from encrypted_file)
    for (int fragment_num = 0; fragment_num < total_fragments; fragment_num++) {
        size_t offset = (size_t)fragment_num * MAX_FRAGMENT_SIZE;
        size_t remaining = encrypted_file_len - offset;
        size_t chunk_size = remaining < MAX_FRAGMENT_SIZE ? remaining : MAX_FRAGMENT_SIZE;

        pkt = prepare_packet(af, 1, FLAG_DATA, icmp_s++, encrypted_file + offset, chunk_size,
            (uint64_t)encrypted_file_len, total_fragments, fragment_num);

        if (af == AF_INET6) {
            if (send_packet_ipv6(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
                free(pkt.data);
                close(sockfd);
                free(encrypted_file);
                exit(EXIT_FAILURE);
            }
        } else {
            if (send_packet(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
                free(pkt.data);
                close(sockfd);
                free(encrypted_file);
                exit(EXIT_FAILURE);
            }
        }
        free(pkt.data);

        if (verbose)
            printf("Sent FLAG_DATA packet, fragment: %d (%zu bytes)\n", fragment_num, chunk_size);
    }

    // Free encrypted buffer after sending
    free(encrypted_file);

    // Send FIN packet
    pkt = prepare_packet(af, 1, FLAG_FIN, icmp_s++, NULL, 0, 1, 1, 0);
    if (af == AF_INET6) {
        if (send_packet_ipv6(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
            free(pkt.data);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    } else {
        if (send_packet(sockfd, (struct sockaddr *)&dest_addr, dest_addrlen, pkt.data, pkt.len) < 0) {
            free(pkt.data);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }
    free(pkt.data);

    if (verbose)
        printf("Sent FLAG_FIN packet\n");

    // Wait for FLAG_OK or FLAG_FAIL response
    while (1) {
        struct sockaddr_storage src_addr;
        socklen_t addrlen = sizeof(src_addr);
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
            (struct sockaddr *)&src_addr, &addrlen);
        if (n < 0) {
            perror("\nrecvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        uint16_t echo_id = 0;
        uint16_t echo_seq = 0;
        custom_header *hdr = NULL;

        if (af == AF_INET) {
            struct iphdr *ip = (struct iphdr *)buffer;
            int ip_header_len = ip->ihl * 4;
            struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_header_len);
            hdr = (custom_header *)(buffer + ip_header_len + sizeof(struct icmphdr));
            echo_id = ntohs(icmp->un.echo.id);
            echo_seq = ntohs(icmp->un.echo.sequence);
        } else {
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
            hdr = (custom_header *)(buffer + sizeof(struct icmp6_hdr));
            echo_id = ntohs(icmp6->icmp6_id);
            echo_seq = ntohs(icmp6->icmp6_seq);
        }

        if (echo_id != SERVER_ID) {
            // Not from server, ignore
            continue;
        }

        if (echo_seq == old_icmp_s) {
            continue; // duplicate packet, ignore
        }
        old_icmp_s = echo_seq;

        if (hdr->flag == FLAG_OK) {
            if (verbose)
                printf("Received FLAG_OK packet\n");
            printf("\nTransmission complete successfully, sent file %s\n", filename);
            break;
        } else if (hdr->flag == FLAG_FAIL) {
            if (verbose)
                printf("Received FLAG_FAIL packet\n");
            printf("\nTransmission failed: Some fragments are missing!\n");
            break;
        } else {
            if (verbose)
                printf("Unexpected flag received. Ignoring...\n");
        }
    }

    close(sockfd);
}

void start_client(const char *target, const char *filename, int verbose) {
    if (verbose)
        printf("\nStarting client...\n");

    // Validate target hostname/IP
    if (validate_hostname(target) < 0) {
        fprintf(stderr, "\nError: Invalid target hostname or IP address: %s\n", target);
        exit(EXIT_FAILURE);
    }

    start_sending(target, filename, verbose);
}
