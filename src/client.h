/**
 * @file client.h
 * @brief UDP client for reliable data transfer (Go-Back-N).
 *
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>

/**
 * @brief Start UDP client.
 *
 * @param port UDP port
 * @param address Target address
 * @param input Input FILE*
 * @param timeout Timeout in seconds
 * @param verbose Enable debug output
 */
void start_client(int port, const char *address, FILE *input, int timeout, int verbose);

#endif /* CLIENT_H */
