/**
 * @file main.c
 * @brief Main program for ICMP/ICMPv6 file transfer utility.
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage(const char *prog_name) {
    printf("\nUsage: %s -r <file> -s <ip|hostname> [-l]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -r <file>         Specify file to transfer (can include path, e.g. ../test.file)\n");
    printf("  -s <ip|hostname>  Destination IP address or hostname\n");
    printf("  -l                Listen mode (server): receive ICMP messages and save file\n");
    printf("  -v                Enable verbose output\n");
    printf("\nDescription:\n");
    printf("  This program transfers a file through a covert channel inside ICMP/ICMPv6\n");
    printf("  Echo-Request/Response messages. The file is encrypted using AES before transmission.\n");
}

int main(int argc, char **argv) {

    const char *filename = NULL;
    const char *target = NULL;
    int flag_listen = 0;
    int verbose = 0;

    if (argc < 2) {
        fprintf(stderr, "\nError: No arguments were specified.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Process args
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-r") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "\nError: Missing filename after -r.\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            filename = argv[i];
        } else if (strcmp(argv[i], "-s") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "\nError: Missing number after -s.\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            target = argv[i];
        } else if (strcmp(argv[i], "-l") == 0) {
            flag_listen = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else {
            fprintf(stderr, "\nError: Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!filename && !flag_listen) {
        fprintf(stderr, "\nError: File not specified.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!target && !flag_listen) {
        fprintf(stderr, "\nError: Target IP/hostname not specified.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (flag_listen && (filename || target)) {
        fprintf(stderr, "\nError: -l option cannot be used with -f or -s.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (flag_listen) {
        start_server(verbose);
    } else {
        start_client(target, filename, verbose);
    }

    return EXIT_SUCCESS;
}
