#ifndef ARGPARSING_H
#define ARGPARSING_H

#include <string>
#include <cstdint>

struct ProgramArgs {
    std::string transport_protocol;  // Required: "tcp" or "udp"
    std::string server_address;      // Required: IP or hostname
    uint16_t server_port;            // Default: 4567
    uint16_t udp_timeout;            // Default: 250ms
    uint8_t udp_retransmissions;     // Default: 3
};

/**
 * Prints help message to stderr
 * @param programName The name of the program executable 
 */
void printHelp(const char* programName);

/**
 * Parses command line arguments into a ProgramArgs structure
 * @param argc Argument count from main
 * @param argv Argument vector from main
 * @return A ProgramArgs struct with parsed arguments
 * @throws std::runtime_error if required arguments are missing or invalid
 */
ProgramArgs parseArgs(int argc, char* argv[]);

#endif // ARGPARSING_H