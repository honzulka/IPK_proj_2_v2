/**
 * @file server.h
 * @brief Server public API for listening/receiving file transfers.
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef SERVER_H
#define SERVER_H

/**
 * @brief Start the server in listen mode.
 *
 * This function runs the server's main loop and blocks until the server
 * terminates. The server requires root privileges to open raw sockets.
 *
 * @param verbose Non-zero to enable verbose logging.
 */
void start_server(int verbose);

#endif /* SERVER_H */