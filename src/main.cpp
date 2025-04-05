#include <iostream>
#include <stdexcept>
#include <getopt.h>
#include <signal.h>
#include "tcp_client.h"
#include "udp_client.h"

// Signal handling for graceful termination (Ctrl+C)
volatile sig_atomic_t terminationRequested = 0;

void signalHandler(int signum) {
    (void)signum; // Suppress unused parameter warning
    terminationRequested = 1;
}

// Program arguments structure
struct ProgramArgs {
    std::string transport_protocol;  
    std::string server_address;      
    uint16_t server_port = 4567;     
    uint16_t udp_timeout = 250;      
    uint8_t udp_retransmissions = 3; 
};

// Print usage help
void printHelp(const char* programName) {
    std::cerr << "Usage: " << programName << " -t PROTOCOL -s SERVER [-p PORT] [-d TIMEOUT] [-r RETRANSMIT] [-h]" << std::endl;
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

// Parse command-line arguments
ProgramArgs parseArgs(int argc, char* argv[]) {
    ProgramArgs args;
    bool t_provided = false;
    bool s_provided = false;
    int opt;
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
            case 'p': {
                try {
                    int port = std::stoi(optarg);
                    if (port <= 0 || port > 65535)
                        throw std::range_error("Port must be between 1 and 65535");
                    args.server_port = static_cast<uint16_t>(port);
                } catch (const std::exception& e) {
                    throw std::runtime_error("Error: Invalid port number");
                }
                break;
            }
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
    if (!t_provided)
        throw std::runtime_error("Error: Transport protocol (-t) must be specified");
    if (!s_provided)
        throw std::runtime_error("Error: Server address (-s) must be specified");
    if (args.transport_protocol != "tcp" && args.transport_protocol != "udp")
        throw std::runtime_error("Error: Transport protocol (-t) must be either 'tcp' or 'udp'");
    return args;
}

// Main function
int main(int argc, char* argv[]) {
    // Set up signal handler for CTRL+C
    signal(SIGINT, signalHandler);

    try {
        ProgramArgs args = parseArgs(argc, argv);
        std::cout << "Transport protocol: " << args.transport_protocol << std::endl;
        std::cout << "Server address: " << args.server_address << std::endl;
        std::cout << "Server port: " << args.server_port << std::endl;
        
        Client* client = nullptr;
        int result = EXIT_FAILURE;
        
        if (args.transport_protocol == "udp") {
            std::cout << "UDP timeout: " << args.udp_timeout << " ms" << std::endl;
            std::cout << "UDP retransmissions: " << (int)args.udp_retransmissions << std::endl;
            client = new UdpClient(args.server_address, args.server_port, 
                                 args.udp_timeout, args.udp_retransmissions);
        } else {
            client = new TcpClient(args.server_address, args.server_port);
        }
        
        // Set hardcoded credentials for testing
        client->setCredentials("xsevcim00", args.transport_protocol == "tcp" ? "tcpp" : "udpp", "33df184d-207f-42a9-b331-7ecebde96416");
        
        result = client->run();
        delete client;
        return result;
        
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}