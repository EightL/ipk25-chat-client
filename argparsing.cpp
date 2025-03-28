#include <iostream>
#include <string>
#include <getopt.h>
#include <cstdlib>
#include <stdexcept>
#include <cstdint>

struct ProgramArgs {
    std::string transport_protocol;  // Required: "tcp" or "udp"
    std::string server_address;      // Required: IP or hostname
    uint16_t server_port = 4567;     // Default: 4567
    uint16_t udp_timeout = 250;      // Default: 250ms
    uint8_t udp_retransmissions = 3; // Default: 3
};

void printHelp(const char* programName) {
    std::cerr << "Usage: " << programName << " -t PROTOCOL -s SERVER [-p PORT] [-d TIMEOUT] [-r RETRANSMIT] [-h]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "IPK25-CHAT client application" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Required arguments:" << std::endl;
    std::cerr << "  -t PROTOCOL       Transport protocol, either 'tcp' or 'udp'" << std::endl;
    std::cerr << "  -s SERVER         Server IP address or hostname" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Optional arguments:" << std::endl;
    std::cerr << "  -p PORT           Server port (default: 4567)" << std::endl;
    std::cerr << "  -d TIMEOUT        UDP confirmation timeout in milliseconds (default: 250)" << std::endl;
    std::cerr << "  -r RETRANSMIT     Maximum number of UDP retransmissions (default: 3)" << std::endl;
    std::cerr << "  -h                Display this help message and exit" << std::endl;
}

ProgramArgs parseArgs(int argc, char* argv[]) {
    ProgramArgs args;
    bool t_provided = false;
    bool s_provided = false;
    int opt;
    
    // Parse command-line options
    while ((opt = getopt(argc, argv, "t:s:p:d:r:h")) != -1) {
        switch (opt) {
            case 't':
                args.transport_protocol = optarg;
                t_provided = true;
                break;
            case 's':
                args.server_address = optarg;
                s_provided = true;
                break;
            case 'p':
                try {
                    int port = std::stoi(optarg);
                    if (port <= 0 || port > 65535) {
                        throw std::range_error("Port must be between 1 and 65535");
                    }
                    args.server_port = static_cast<uint16_t>(port);
                } catch (const std::exception& e) {
                    throw std::runtime_error("Error: Invalid port number");
                }
                break;
            case 'd':
                args.udp_timeout = static_cast<uint16_t>(std::stoi(optarg));
                break;
            case 'r':
                args.udp_retransmissions = static_cast<uint8_t>(std::stoi(optarg));
                break;
            case 'h':
                printHelp(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            default:
                printHelp(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    // Validate required arguments
    if (!t_provided) {
        throw std::runtime_error("Error: Transport protocol (-t) must be specified");
    }
    
    if (!s_provided) {
        throw std::runtime_error("Error: Server address (-s) must be specified");
    }
    
    // Validate transport protocol value
    if (args.transport_protocol != "tcp" && args.transport_protocol != "udp") {
        throw std::runtime_error("Error: Transport protocol (-t) must be either 'tcp' or 'udp'");
    }
    
    return args;
}