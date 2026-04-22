/**
 * @file client.h
 * @brief Client API for initiating file transfers.
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef CLIENT_H
#define CLIENT_H

#include <stddef.h>

/**
 * @brief Start the client and send a file to the given target.
 *
 * This function implements the high-level client behavior. It resolves the
 * target address, opens the file, fragments and encrypts it, and sends the
 * protocol packets. On fatal errors the function will exit the process.
 *
 * @param target Hostname or IP address string (IPv4 or IPv6).
 * @param filename Path to the file to send.
 * @param verbose Non-zero to enable verbose logging.
 */
void start_client(const char *target, const char *filename, int verbose);

#endif /* CLIENT_H */