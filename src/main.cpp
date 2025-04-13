/**
 * @file main.cpp
 * @brief Main entry point for the IPK25-CHAT client application.
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
  * @brief Global flag for graceful termination handling
  *
  * This variable is modified by the signal handler when SIGINT (Ctrl+C)
  * is received. The client implementation checks this flag to initiate
  * graceful shutdown.
  */
 volatile sig_atomic_t terminationRequested = 0;
 
 /**
  * @brief Signal handler for graceful termination
  *
  * Sets the terminationRequested flag when SIGINT is received.
  *
  * @param signum Signal number that triggered the handler
  */
 void signalHandler(int signum) {
     (void)signum; // Suppress unused parameter warning
     terminationRequested = 1;
 }
 
 /**
  * @brief Structure to hold program command-line arguments
  */
 struct ProgramArgs {
     std::string transport_protocol;  ///< Transport protocol (tcp/udp)
     std::string server_address;      ///< Server hostname or IP address
     uint16_t server_port = 4567;     ///< Server port number
     uint16_t udp_timeout = 250;      ///< UDP confirmation timeout in milliseconds
     uint8_t udp_retransmissions = 3; ///< Maximum number of UDP retransmissions
 };
 
 /**
  * @brief Prints program usage information
  *
  * Displays help message with all supported command-line arguments.
  *
  * @param programName Name of the executable
  */
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
 
 /**
  * @brief Parses command-line arguments
  *
  * Validates and extracts program arguments from command line.
  *
  * @param argc Number of arguments
  * @param argv Array of argument strings
  * @return ProgramArgs structure with parsed arguments
  * @throws std::runtime_error if required arguments are missing or invalid
  */
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
                     if (port <= 0 || port > 65535) {
                         throw std::range_error("Port must be between 1 and 65535");
                     }
                     args.server_port = static_cast<uint16_t>(port);
                 } catch (const std::exception& e) {
                     throw std::runtime_error("Error: Invalid port number");
                 }
                 break;
             }
             
             case 'd':
                 try {
                     int timeout = std::stoi(optarg);
                     if (timeout <= 0) {
                         throw std::range_error("Timeout must be positive");
                     }
                     args.udp_timeout = static_cast<uint16_t>(timeout);
                 } catch (const std::exception& e) {
                     throw std::runtime_error("Error: Invalid timeout value");
                 }
                 break;
                 
             case 'r':
                 try {
                     int retransmissions = std::stoi(optarg);
                     if (retransmissions < 0 || retransmissions > 255) {
                         throw std::range_error("Retransmissions must be between 0 and 255");
                     }
                     args.udp_retransmissions = static_cast<uint8_t>(retransmissions);
                 } catch (const std::exception& e) {
                     throw std::runtime_error("Error: Invalid retransmission value");
                 }
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
     if (args.transport_protocol != "tcp" && args.transport_protocol != "udp") {
         throw std::runtime_error("Error: Transport protocol (-t) must be either 'tcp' or 'udp'");
     }
     
     return args;
 }
 
 /**
  * @brief Creates the appropriate client based on transport protocol
  * 
  * Factory function to create either a TCP or UDP client instance.
  *
  * @param args Program arguments with client configuration
  * @return Pointer to created client instance
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
  * @brief Main entry point for the application
  *
  * Initializes signal handling, parses command-line arguments,
  * creates the appropriate client, and runs the client application.
  *
  * @param argc Number of arguments
  * @param argv Array of argument strings
  * @return EXIT_SUCCESS on clean exit, EXIT_FAILURE on error
  */
 int main(int argc, char* argv[]) {
     // Set up signal handler for CTRL+C
     signal(SIGINT, signalHandler);
 
     try {
         // Parse command-line arguments
         ProgramArgs args = parseArgs(argc, argv);
         
         // Log configuration
         std::cerr << "Transport protocol: " << args.transport_protocol << std::endl;
         std::cerr << "Server address: " << args.server_address << std::endl;
         std::cerr << "Server port: " << args.server_port << std::endl;
         
         if (args.transport_protocol == "udp") {
             std::cerr << "UDP timeout: " << args.udp_timeout << " ms" << std::endl;
             std::cerr << "UDP retransmissions: " << static_cast<int>(args.udp_retransmissions) << std::endl;
         }
         
         // Create appropriate client based on transport protocol
         std::unique_ptr<Client> client = createClient(args);
         
         // Display authentication instructions
         std::cerr << "\nPlease authenticate using: /auth <username> <secret> <displayName>" << std::endl;
         
         // Run client and return its result code
         return client->run();
         
     } catch (const std::exception& e) {
         std::cerr << e.what() << std::endl;
         return EXIT_FAILURE;
     }
 }