/**
 * @file main.c
 * @brief Main program for UDP file transfer utility.
 *
 * @author Jan Cernoch <xcernoj00>
 */

#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_TIMEOUT 1 // 1 second

void print_usage(const char *prog) {
  printf(
    "Usage:\n"
    "  %s -s -p PORT [-a ADDRESS] [-o OUTPUT] [-w TIMEOUT]\n"
    "  %s -c -a HOST -p PORT [-i INPUT] [-w TIMEOUT]\n"
    "\n"
    "Options:\n"
    "  -s            server mode\n"
    "  -c            client mode\n"
    "  -a ADDRESS    address / host\n"
    "  -p PORT       UDP port\n"
    "  -i INPUT      input file or - for stdin\n"
    "  -o OUTPUT     output file or - for stdout\n"
    "  -w TIMEOUT    timeout in seconds (default 1)\n"
    "  -h            show help\n",
    prog, prog
  );
}

int main(int argc, char **argv) {

  char *address = NULL;
  int port = -1;
  FILE *input = stdin;
  FILE *output = stdout;
  int flag_client = 0;
  int flag_server = 0;
  int timeout = DEFAULT_TIMEOUT;

  if (argc < 2) {
      fprintf(stderr, "\nError: No arguments were specified.\n");
      print_usage(argv[0]);
      exit(EXIT_FAILURE);
  }

  // Process args
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-s") == 0) {
      flag_server = 1;
    } else if (strcmp(argv[i], "-p") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "\nError: Missing port number after -p.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
      }
      port = atoi(argv[i]);
      if (port <= 0 || port > 65535) {
        fprintf(stderr, "\nError: Invalid port number.\n");
        exit(EXIT_FAILURE);
      }
    } else if (strcmp(argv[i], "-a") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "\nError: Missing address after -a.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
      }
      address = argv[i];
    } else if (strcmp(argv[i], "-o") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "\nError: Missing output after -o.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
      }
      if (strcmp(argv[i], "-") == 0) {
        output = stdout;
      } else {
        output = fopen(argv[i], "wb");
        if (!output) {
          perror("fopen");
          exit(EXIT_FAILURE);
        }
      }
    } else if (strcmp(argv[i], "-w") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "\nError: Missing timeout after -w.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
      }
      timeout = atoi(argv[i]);
      if (timeout < 0) {
        fprintf(stderr, "\nError: Invalid timeout.\n");
        exit(EXIT_FAILURE);
      }
    } else if (strcmp(argv[i], "-c") == 0) {
      flag_client = 1;
    } else if (strcmp(argv[i], "-i") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "\nError: Missing input after -i.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
      }
      if (strcmp(argv[i], "-") == 0) {
        input = stdin;
      } else {
        input = fopen(argv[i], "rb");
        if (!input) {
          perror("fopen");
          exit(EXIT_FAILURE);
        }
      }
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_usage(argv[0]);
      exit(EXIT_SUCCESS);
    } else {
      fprintf(stderr, "\nError: Unknown argument: %s\n", argv[i]);
      print_usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (flag_client == flag_server) {
    fprintf(stderr, "ERROR: Exactly one of -c or -s must be specified\n");
    exit(EXIT_FAILURE);
  }

  if (port < 0) {
    fprintf(stderr, "ERROR: -p PORT is required\n");
    exit(1);
  }

  if (flag_client) {
    if (!address) {
      fprintf(stderr, "ERROR: -a HOST is required in client mode\n");
      exit(1);
    }
  }

  if (flag_client && output != stdout) {
    fprintf(stderr, "Error: -o is not valid in client mode\n");
    exit(EXIT_FAILURE);
  }

  if (flag_server && input != stdin) {
    fprintf(stderr, "Error: -i is not valid in server mode\n");
    exit(EXIT_FAILURE);
  }

  if (flag_server) {
      start_server(port, address, output, timeout);
  } else {
      start_client(port, address, input, timeout);
  }

  if (input != stdin) fclose(input);
  if (output != stdout) fclose(output);

  return EXIT_SUCCESS;
}
