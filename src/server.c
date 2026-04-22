/**
 * @file server.c
 * @brief Server public API for listening/receiving file transfers.
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#define _DEFAULT_SOURCE

#include "server.h"
#include "crypto.h"
#include "protocol.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

/* Print first active IPv4 and IPv6 addresses of the machine. */
static void print_addresses() {

    struct ifaddrs *ifaddr, *ifa;
    char addrbuf[INET6_ADDRSTRLEN];
    int found_active = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("\ngetifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        int family = ifa->ifa_addr->sa_family;
        if (!(ifa->ifa_flags & IFF_UP))
            continue; // skip inactive interfaces

        if (family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            if (inet_ntop(AF_INET, &sa->sin_addr, addrbuf, sizeof(addrbuf))) {
                printf("Listening on IPv4 address (%s): %s\n", ifa->ifa_name, addrbuf);
            }
            found_active = 1;
        } else if (family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            if (inet_ntop(AF_INET6, &sa6->sin6_addr, addrbuf, sizeof(addrbuf))) {
                printf("Listening on IPv6 address (%s): %s\n", ifa->ifa_name, addrbuf);
            }
            found_active = 1;
        }
    }

    freeifaddrs(ifaddr);

    if (!found_active) {
        fprintf(stderr, "\nError: No active network interfaces found.\n");
        exit(EXIT_FAILURE);
    }
}

void start_listening(int verbose) {

    // Create raw ICMP sockets for both IPv4 and IPv6
    int sockfd4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sockfd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (sockfd4 < 0 && sockfd6 < 0) {
        perror("\nsocket: Cannot create any socket");
        exit(EXIT_FAILURE);
    }

    if (sockfd4 < 0) {
        if (verbose)
            printf("Warning: IPv4 socket creation failed, IPv4 disabled\n");
    }
    if (sockfd6 < 0) {
        if (verbose)
            printf("Warning: IPv6 socket creation failed, IPv6 disabled\n");
    }

    uint8_t buffer[BUFFER_SIZE]; // buffer for receiving packets
    uint8_t *data; // pointer to payload data within received packet

    int icmp_s = 1; // ICMP sequence number (for sending packets)
    int old_icmp_s = 0; // Old ICMP sequence number

    char *filename = NULL;
    FILE *file = NULL;
    uint64_t file_size = 0;
    uint32_t total_fragments = 0;
    uint8_t **fragments = NULL; // Array of pointers to store fragments
    int *fragment_received = NULL; // Array to track received fragments
    size_t *fragment_sizes = NULL; // Array to track each fragment's length
    pkt_data pkt;
    int ok = 0; // Flag to indicate successful transfer

    while (1) {

        if (ok) {
            printf("\nTransmission complete successfully, received file %s\n", filename);

            // Cleanup per-transfer state
            if (fragments) {
                for (uint32_t i = 0; i < total_fragments; i++) {
                    free(fragments[i]);
                }
                free(fragments);
                fragments = NULL;
            }
            free(fragment_received);
            fragment_received = NULL;
            free(fragment_sizes);
            fragment_sizes = NULL;
            total_fragments = 0;
            file_size = 0;
            free(filename);
            filename = NULL;
            break; // exit after successful transfer
        }

        // Use select() to wait for packets on either socket
        fd_set readfds;
        FD_ZERO(&readfds);
        int maxfd = -1;

        if (sockfd4 >= 0) {
            FD_SET(sockfd4, &readfds);
            maxfd = sockfd4;
        }
        if (sockfd6 >= 0) {
            FD_SET(sockfd6, &readfds);
            if (sockfd6 > maxfd)
                maxfd = sockfd6;
        }

        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("\nselect");
            continue;
        }

        // Determine which socket has data and which address family
        int sockfd;
        int af;

        if (sockfd4 >= 0 && FD_ISSET(sockfd4, &readfds)) {
            sockfd = sockfd4;
            af = AF_INET;
        } else if (sockfd6 >= 0 && FD_ISSET(sockfd6, &readfds)) {
            sockfd = sockfd6;
            af = AF_INET6;
        } else {
            continue;
        }

        struct sockaddr_storage src_addr;
        socklen_t addrlen = sizeof(src_addr);
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addrlen);
        if (n < 0) {
            perror("\nrecvfrom");
            continue;
        }

        // Parse headers based on address family
        uint16_t echo_id = 0;
        uint16_t echo_seq = 0;
        custom_header *hdr = NULL;
        struct in6_addr src6_addr;
        struct in6_addr dst6_addr;
        memset(&src6_addr, 0, sizeof(src6_addr));
        memset(&dst6_addr, 0, sizeof(dst6_addr));

        if (af == AF_INET) {
            // Parse IPv4 + ICMP
            struct iphdr *ip = (struct iphdr *)buffer;
            int ip_header_len = ip->ihl * 4;
            struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_header_len);
            hdr = (custom_header *)(buffer + ip_header_len + sizeof(struct icmphdr));
            data = (uint8_t *)(buffer + ip_header_len + sizeof(struct icmphdr) + sizeof(custom_header));
            echo_id = ntohs(icmp->un.echo.id);
            echo_seq = ntohs(icmp->un.echo.sequence);
        } else {
            // Parse ICMPv6 (no IP header in received data for raw ICMPv6)
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
            hdr = (custom_header *)(buffer + sizeof(struct icmp6_hdr));
            data = (uint8_t *)(buffer + sizeof(struct icmp6_hdr) + sizeof(custom_header));
            echo_id = ntohs(icmp6->icmp6_id);
            echo_seq = ntohs(icmp6->icmp6_seq);
            if (src_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_addr;
                dst6_addr = sin6->sin6_addr; // destination for replies is the client address
            }
        }

        // Convert header fields to host order for easier processing
        header_ntoh(hdr);

        /* determine server's local IPv6 address for replies (if AF_INET6) */
        if (af == AF_INET6) {
            struct sockaddr_in6 local6;
            socklen_t llen = sizeof(local6);
            if (getsockname(sockfd, (struct sockaddr *)&local6, &llen) == 0) {
                src6_addr = local6.sin6_addr;
            }
        }

        if (echo_id != CLIENT_ID) {
            continue; // Not from client, ignore
        }

        if (echo_seq == old_icmp_s) {
            continue; // Duplicate packet, ignore
        }
        old_icmp_s = echo_seq;

        // Handle packet based on flag
        switch (hdr->flag) {
        case FLAG_HELLO:
            if (verbose)
                printf("\nReceived FLAG_HELLO packet\n");
            pkt = prepare_packet(af, 0, FLAG_READY, icmp_s++, NULL, 0, 0, 0, 0);
            if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0) {
                free(pkt.data);
                continue;
            }
            if (verbose)
                printf("Sent FLAG_READY packet\n");
            free(pkt.data);
            break;

        case FLAG_META:
            if (verbose)
                printf("Received FLAG_META packet\n");
            // Persist filename (data points into recv buffer which will be reused)
            if (filename) {
                free(filename);
                filename = NULL;
            }
            filename = strdup((char *)data);
            // header_ntoh() already converted hdr fields to host byte order
            file_size = hdr->file_size;
            total_fragments = hdr->total_fragments;
            if (verbose)
                printf("\nFilename: %s, File size: %llu, Total fragments: %u\n\n", filename ? filename : "(null)", (unsigned long long)file_size, total_fragments);

            /* Allocate tracking arrays for fragments */
            if (total_fragments > 0) {
                // we use calloc to zero-initialize
                fragments = calloc(total_fragments, sizeof(uint8_t *));
                fragment_received = calloc(total_fragments, sizeof(int));
                fragment_sizes = calloc(total_fragments, sizeof(size_t));
                if (!fragments || !fragment_received || !fragment_sizes) {
                    perror("\ncalloc");
                    exit(EXIT_FAILURE);
                }
            }

            // Send ACK to client
            pkt = prepare_packet(af, 0, FLAG_ACK, icmp_s++, NULL, 0, 0, 0, 0);
            if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0) {
                free(pkt.data);
                continue;
            }
            if (verbose)
                printf("Sent FLAG_ACK packet\n");
            free(pkt.data);
            break;

        case FLAG_DATA: // Data fragment
            uint32_t seq = hdr->fragment_num;
            if (verbose)
                printf("Received FLAG_DATA packet, fragment_num: %u\n", seq);

            if (total_fragments == 0 || fragments == NULL || fragment_received == NULL) {
                fprintf(stderr, "\nError: Received data but no META was processed. Ignoring fragment %u\n", seq);
                break;
            }

            if (seq >= total_fragments) {
                fprintf(stderr, "\nError: Received out-of-range fragment %u (total %u)\n", seq, total_fragments);
                break;
            }

            // Calculate payload length of this fragment based on address family
            size_t data_len;
            if (af == AF_INET) {
                struct iphdr *ip = (struct iphdr *)buffer;
                int ip_header_len = ip->ihl * 4;
                data_len = n - ip_header_len - sizeof(struct icmphdr) - sizeof(custom_header);
            } else {
                data_len = n - sizeof(struct icmp6_hdr) - sizeof(custom_header);
            }

            if (data_len == 0) {
                fprintf(stderr, "\nError: Received empty fragment %u\n", seq);
                break;
            }

            // If we already have this fragment, ignore duplicate
            if (fragment_received[seq]) {
                break;
            }

            fragments[seq] = malloc(data_len);
            if (!fragments[seq]) {
                perror("\nmalloc");
                if (sockfd4 >= 0)
                    close(sockfd4);
                if (sockfd6 >= 0)
                    close(sockfd6);
                free(filename);
                if (fragments) {
                    for (uint32_t i = 0; i < total_fragments; i++) {
                        free(fragments[i]);
                    }
                    free(fragments);
                }
                free(fragment_received);
                free(fragment_sizes);
                exit(EXIT_FAILURE);
            }
            memcpy(fragments[seq], data, data_len);
            fragment_sizes[seq] = data_len;
            fragment_received[seq] = 1;

            break;

        case FLAG_FIN:
            if (verbose)
                printf("Received FLAG_FIN packet\n\n");

            if (total_fragments == 0 || fragments == NULL || fragment_received == NULL) {
                fprintf(stderr, "\nError: FIN received but no transfer in progress. Sending FLAG_FAIL\n");
                pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0) {
                    free(pkt.data);
                }
                free(pkt.data);
                break;
            }

            // Check completeness
            int missing = 0;
            for (uint32_t i = 0; i < total_fragments; i++) {
                if (!fragment_received[i]) {
                    missing = 1;
                    fprintf(stderr, "\nMissing fragment %u\n", i);
                }
            }

            if (missing) {
                if (verbose) {
                    printf("File incomplete, sending FLAG_FAIL\n");
                }
                pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0) {
                    free(pkt.data);
                }
                free(pkt.data);
            } else {
                // All fragments present -> assemble ciphertext buffer
                if (verbose)
                    printf("All fragments present, assembling ciphertext for '%s'\n", filename ? filename : "(null)");

                // file_size is expected to be the ciphertext length (sent in META)
                if (file_size == 0) {
                    fprintf(stderr, "Error: Expected ciphertext length is 0\n");
                    pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                    if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0) {
                        free(pkt.data);
                    }
                    break;
                }

                // Check total size consistency
                uint64_t sum_sizes = 0;
                for (uint32_t i = 0; i < total_fragments; i++) {
                    sum_sizes += (uint64_t)fragment_sizes[i];
                }
                if (sum_sizes != file_size) {
                    fprintf(stderr, "Error: Sum of fragment sizes (%llu) != expected ciphertext size (%llu)\n",
                        (unsigned long long)sum_sizes, (unsigned long long)file_size);
                    pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                    if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0) {
                        free(pkt.data);
                    }
                    break;
                }

                // Allocate contiguous buffer for ciphertext
                size_t ciphertext_len = (size_t)file_size;
                uint8_t *ciphertext = malloc(ciphertext_len);
                if (!ciphertext) {
                    perror("\nmalloc");
                    pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                    if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0) {
                        free(pkt.data);
                    }
                    break;
                }

                // Copy fragments in order
                size_t offset = 0;
                for (uint32_t i = 0; i < total_fragments; i++) {
                    if (fragment_sizes[i] > 0 && fragments[i] != NULL) {
                        memcpy(ciphertext + offset, fragments[i], fragment_sizes[i]);
                        offset += fragment_sizes[i];
                    }
                }

                // Decrypt
                uint8_t *plaintext = NULL;
                size_t plaintext_len = 0;
                if (!aes_decrypt(ciphertext, ciphertext_len, &plaintext, &plaintext_len, SECRET_KEY)) {
                    fprintf(stderr, "AES decryption failed\n");
                    free(ciphertext);
                    pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                    if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0)
                        free(pkt.data);
                    free(pkt.data);
                } else {
                    // Write plaintext to file
                    file = fopen(filename ? filename : "received_file", "wb");
                    if (!file) {
                        perror("\nfopen");
                        free(plaintext);
                        free(ciphertext);
                        pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                        if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0)
                            free(pkt.data);
                        free(pkt.data);
                    } else {
                        size_t written = fwrite(plaintext, 1, plaintext_len, file);
                        fclose(file);
                        if (written != plaintext_len) {
                            fprintf(stderr, "Error: Written %zu bytes but expected %zu\n", written, plaintext_len);
                            free(plaintext);
                            free(ciphertext);
                            pkt = prepare_packet(af, 0, FLAG_FAIL, icmp_s++, NULL, 0, 0, 0, 0);
                            if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0)
                                free(pkt.data);
                            free(pkt.data);
                        } else {
                            if (verbose)
                                printf("File '%s' written successfully (%zu bytes)\nSending FLAG_OK packet\n",
                                    filename ? filename : "(null)", plaintext_len);
                            pkt = prepare_packet(af, 0, FLAG_OK, icmp_s++, NULL, 0, 0, 0, 0);
                            if (send_packet(sockfd, (struct sockaddr *)&src_addr, addrlen, pkt.data, pkt.len) < 0)
                                free(pkt.data);
                            free(pkt.data);
                            free(plaintext);
                            free(ciphertext);
                            ok = 1;
                        }
                    }
                }

                // Free fragments memory now (we either succeeded or already returned failure)
                for (uint32_t i = 0; i < total_fragments; i++) {
                    free(fragments[i]);
                    fragments[i] = NULL;
                }
                free(fragments);
                fragments = NULL;
                free(fragment_received);
                fragment_received = NULL;
                free(fragment_sizes);
                fragment_sizes = NULL;
            }

            break;

        default:
            if (verbose)
                printf("Unexpected flag received. Ignoring...\n");
        }
    }
    if (sockfd4 >= 0)
        close(sockfd4);
    if (sockfd6 >= 0)
        close(sockfd6);
}

void start_server(int verbose) {
    printf("\n");
    if (verbose)
        printf("Starting server...\n");

    print_addresses();

    start_listening(verbose);
}
