/**
 * @file server.h
 * @brief UDP server for reliable data transfer.
 *
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>

/**
 * @brief Start UDP server.
 *
 * @param port UDP port
 * @param address Bind address (NULL = all)
 * @param output Output FILE*
 * @param timeout Timeout in seconds
 */
void start_server(int port, const char *address, FILE *output, int timeout);

#endif /* SERVER_H */
