/**
 * @file main.cpp
 * @brief Main entry point for the IPK25-CHAT client application
 *
 * This application implements a client for the IPK25-CHAT protocol,
 * supporting both TCP and UDP transport protocols.
 *
 * @author xsevcim00
 */

#include <iostream>
#include <stdexcept>
#include <getopt.h>
#include <signal.h>
#include <memory>
#include "tcp_client.h"
#include "udp_client.h"

/**
 * @brief Global flag indicating that a graceful shutdown has been requested
 *
 * Set to 1 by the signal handler when SIGINT (Ctrl+C) is raised.
 */
volatile sig_atomic_t terminationRequested = 0;

/**
 * @brief Signal handler to request graceful shutdown
 *
 * Sets the global terminationRequested flag when SIGINT is received.
 *
 * @param signum The signal number that was raised
 */
void signalHandler(int signum) {
    (void)signum; ///< Unused parameter
    terminationRequested = 1;
}

/**
 * @struct ProgramArgs
 * @brief Parsed command-line arguments for the client application
 */
struct ProgramArgs {
    std::string transport_protocol;  // "tcp" or "udp"
    std::string server_address;      // server hostname or IP address
    uint16_t    server_port = 4567;  // server port number (default: 4567)
    uint16_t    udp_timeout = 250;   // UDP confirmation timeout in ms
    uint8_t     udp_retransmissions = 3; // max UDP retransmissions
};

/**
 * @brief Prints usage information for the application
 *
 * @param programName Name of the executable (usually argv[0])
 */
void printHelp(const char* programName) {
    std::cerr << "Usage: " << programName
            << " -t PROTOCOL -s SERVER [-p PORT] [-d TIMEOUT] [-r RETRANSMIT] [-h]" << std::endl;
    std::cerr << "\nIPK25-CHAT client application\n" << std::endl;
    std::cerr << "Required arguments:" << std::endl;
    std::cerr << "  -t PROTOCOL       Transport protocol, either 'tcp' or 'udp'" << std::endl;
    std::cerr << "  -s SERVER         Server IP address or hostname" << std::endl;
    std::cerr << "\nOptional arguments:" << std::endl;
    std::cerr << "  -p PORT           Server port (default: 4567)" << std::endl;
    std::cerr << "  -d TIMEOUT        UDP confirmation timeout in milliseconds (default: 250)" << std::endl;
    std::cerr << "  -r RETRANSMIT     Maximum number of UDP retransmissions (default: 3)" << std::endl;
    std::cerr << "  -h                Display this help message and exit" << std::endl;
}

/**
 * @brief Parses a numeric command-line argument with range validation
 *
 * Converts a string to an integer of type T and checks its bounds.
 *
 * @tparam T Numeric type (e.g., uint8_t, uint16_t)
 * @param arg  String to convert
 * @param name Friendly name for error reporting
 * @param min  Minimum allowed value
 * @param max  Maximum allowed value
 * @return Parsed value of type T
 * @throws std::runtime_error if conversion fails or value out of range
 */
template<typename T>
T parseNumericArg(const char* arg, const char* name, T min, T max) {
    try {
        int value = std::stoi(arg);
        if (value < static_cast<int>(min) || value > static_cast<int>(max)) {
            throw std::range_error(std::string(name) + " must be between " + std::to_string(min) + " and " + std::to_string(max));
        }
        return static_cast<T>(value);
    } catch (const std::exception&) {
        throw std::runtime_error(std::string("Error: Invalid ") + name);
    }
}

/**
 * @brief Parses and validates command-line arguments
 *
 * Extracts options -t, -s, -p, -d, -r, and -h, and checks required values.
 *
 * @param argc Number of command-line arguments
 * @param argv Array of argument strings
 * @return Filled ProgramArgs structure
 * @throws std::runtime_error if required arguments are missing or invalid
 */
ProgramArgs parseArgs(int argc, char* argv[]) {
    ProgramArgs args;
    int opt;

    while ((opt = getopt(argc, argv, "t:s:p:d:r:h")) != -1) {
        switch (opt) {
            case 't':
                args.transport_protocol = optarg;
                break;
            case 's':
                args.server_address = optarg;
                break;
            case 'p':
                args.server_port = parseNumericArg<uint16_t>(optarg, "port", 1, 65535);
                break;
            case 'd':
                args.udp_timeout = parseNumericArg<uint16_t>(optarg, "timeout", 1, 65535);
                break;
            case 'r':
                args.udp_retransmissions = parseNumericArg<uint8_t>(optarg, "retransmission count", 0, 255);
                break;
            case 'h':
                printHelp(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                printHelp(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // ensure mandatory arguments are provided
    if (args.transport_protocol.empty()) {
        throw std::runtime_error("Error: Transport protocol (-t) must be specified");
    }
    if (args.server_address.empty()) {
        throw std::runtime_error("Error: Server address (-s) must be specified");
    }
    if (args.transport_protocol != "tcp" && args.transport_protocol != "udp") {
        throw std::runtime_error("Error: Transport protocol (-t) must be either 'tcp' or 'udp'");
    }

    return args;
}

/**
 * @brief Factory function to instantiate the correct Client subclass
 *
 * Creates a TcpClient or UdpClient based on parsed arguments.
 *
 * @param args Configuration parameters
 * @return Unique pointer to the created Client
 */
std::unique_ptr<Client> createClient(const ProgramArgs& args) {
    if (args.transport_protocol == "udp") {
        return std::make_unique<UdpClient>(
            args.server_address,
            args.server_port,
            args.udp_timeout,
            args.udp_retransmissions
        );
    } else {
        return std::make_unique<TcpClient>(
            args.server_address,
            args.server_port
        );
    }
}

/**
 * @brief Application entry point
 *
 * Initializes signal handler, parses arguments, creates the client,
 * and starts the client run loop.
 *
 * @param argc Number of command-line arguments
 * @param argv Argument vector
 * @return EXIT_SUCCESS on normal termination, EXIT_FAILURE on error
 */
int main(int argc, char* argv[]) {
    // handle SIGINT for graceful shutdown
    signal(SIGINT, signalHandler);

    try {
    // load and validate command-line arguments
    ProgramArgs args = parseArgs(argc, argv);

        // log startup configuration to stderr
        std::cerr << "Transport protocol: " << args.transport_protocol << std::endl;
        std::cerr << "Server address: "   << args.server_address << std::endl;
        std::cerr << "Server port: "      << args.server_port << std::endl;
        if (args.transport_protocol == "udp") {
            std::cerr << "UDP timeout: "               << args.udp_timeout << " ms" << std::endl;
            std::cerr << "UDP retransmissions: "      << static_cast<int>(args.udp_retransmissions) << std::endl;
        }

        // construct client instance
        std::unique_ptr<Client> client = createClient(args);

        // prompt user for authentication
        std::cerr << "\nPlease authenticate using: /auth <username> <secret> <displayName>" << std::endl;

        // nter client run loop
        return client->run();

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
