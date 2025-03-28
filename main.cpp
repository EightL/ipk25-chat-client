// Combined IPK25-chat client for testing purposes
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <getopt.h>
#include <stdexcept>
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netdb.h>

// --- Message protocol definitions ---

// We define an enum to represent message types.
enum class MessageType {
    AUTH,
    JOIN,
    MSG,
    BYE,
    REPLY,
    ERR,
    UNKNOWN
};

bool resolveHostname(const std::string& hostname, struct sockaddr_in* addr) {
    struct addrinfo hints, *results, *result;
    
    // Initialize hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // Only IPv4 addresses
    hints.ai_socktype = SOCK_STREAM; // TCP socket type
    
    // Resolve hostname
    int status = getaddrinfo(hostname.c_str(), NULL, &hints, &results);
    if (status != 0) {
        std::cerr << "Failed to resolve hostname: " << hostname << ": " 
                  << gai_strerror(status) << std::endl;
        return false;
    }
    
    // Use the first valid result
    for (result = results; result != NULL; result = result->ai_next) {
        if (result->ai_family == AF_INET) {
            // Copy the resolved address
            memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
            freeaddrinfo(results);
            return true;
        }
    }
    
    freeaddrinfo(results);
    std::cerr << "No IPv4 address found for hostname: " << hostname << std::endl;
    return false;
}

// Helper to convert token to message type.
MessageType stringToMessageType(const std::string& token) {
    if (token == "AUTH") return MessageType::AUTH;
    if (token == "JOIN") return MessageType::JOIN;
    if (token == "MSG") return MessageType::MSG;
    if (token == "BYE") return MessageType::BYE;
    if (token == "REPLY") return MessageType::REPLY;
    if (token == "ERR") return MessageType::ERR;
    return MessageType::UNKNOWN;
}

// Structure to hold the parsed message components.
struct ParsedMessage {
    MessageType type = MessageType::UNKNOWN;
    std::string param1; // For AUTH: username; JOIN: channelID; MSG: displayName; BYE: displayName; REPLY/ERR: first parameter (e.g. OK/NOK or displayName)
    std::string param2; // For AUTH: displayName; JOIN: displayName; MSG: message content; REPLY/ERR: message content
    std::string param3; // For AUTH only: secret
};

// --- Finite State Machine (FSM) ---
// Define the possible client states.
enum class ClientState {
    INIT,
    AUTHENTICATED,
    JOINED,
    TERMINATED
};

// Context to store the client's current state and display name.
struct ClientContext {
    ClientState state = ClientState::INIT;
    std::string displayName;
    std::string username;
    std::string channelID;
};

// --- Serialization functions ---
// These functions create protocol-compliant messages ending with "\r\n"

std::string serializeAuth(const std::string& username, const std::string& displayName, const std::string& secret) {
    return "AUTH " + username + " AS " + displayName + " USING " + secret + "\r\n";
}

std::string serializeJoin(const std::string& channelID, const std::string& displayName) {
    return "JOIN " + channelID + " AS " + displayName + "\r\n";
}

std::string serializeMsg(const std::string& displayName, const std::string& messageContent) {
    return "MSG FROM " + displayName + " IS " + messageContent + "\r\n";
}

std::string serializeBye(const std::string& displayName) {
    return "BYE FROM " + displayName + "\r\n";
}

// A naive parser that works with our text-based protocol formats.
ParsedMessage parseMessage(const std::string& raw) {
    ParsedMessage msg;
    std::istringstream iss(raw);
    std::string token;
    
    // Get the message type token.
    iss >> token;
    msg.type = stringToMessageType(token);
    
    switch (msg.type) {
        case MessageType::AUTH:
            // Format: AUTH {Username} AS {DisplayName} USING {Secret}\r\n
            iss >> msg.param1;          // username
            iss >> token;               // Expect "AS"
            iss >> msg.param2;          // displayName
            iss >> token;               // Expect "USING"
            std::getline(iss, msg.param3); // secret (rest of the line)
            // Trim trailing whitespace and CRLF.
            msg.param3.erase(msg.param3.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::JOIN:
            // Format: JOIN {ChannelID} AS {DisplayName}\r\n
            iss >> msg.param1;          // channelID
            iss >> token;               // Expect "AS"
            iss >> msg.param2;          // displayName
            break;
        case MessageType::MSG:
            // Format: MSG FROM {DisplayName} IS {MessageContent}\r\n
            iss >> token;               // Expect "FROM"
            iss >> msg.param1;          // displayName
            iss >> token;               // Expect "IS"
            std::getline(iss, msg.param2); // message content
            // Trim leading spaces and trailing CRLF.
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::BYE:
            // Format: BYE FROM {DisplayName}\r\n
            iss >> token;               // Expect "FROM"
            iss >> msg.param1;          // displayName
            break;
        case MessageType::REPLY:
            // Format: REPLY {"OK"|"NOK"} IS {MessageContent}\r\n
            iss >> token;               // Should be "OK" or "NOK"
            msg.param1 = token;
            iss >> token;               // Expect "IS"
            std::getline(iss, msg.param2); // message content
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::ERR:
            // Format: ERR FROM {DisplayName} IS {MessageContent}\r\n
            iss >> token;               // Expect "FROM"
            iss >> msg.param1;          // displayName
            iss >> token;               // Expect "IS"
            std::getline(iss, msg.param2); // message content
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        default:
            break;
    }
    return msg;
}

// A simple handler that processes incoming messages and updates the client context.
void handleIncomingMessage(const ParsedMessage& msg, ClientContext& ctx) {
    switch (msg.type) {
        case MessageType::REPLY:
            if (msg.param1 == "OK") {
                std::cout << "Action Success: " << msg.param2 << "\n";
                if (ctx.state == ClientState::INIT)
                    ctx.state = ClientState::AUTHENTICATED;
                else if (ctx.state == ClientState::AUTHENTICATED)
                    ctx.state = ClientState::JOINED;
            } else {
                std::cout << "Action Failure: " << msg.param2 << "\n";
            }
            break;
        case MessageType::MSG:
            std::cout << msg.param1 << ": " << msg.param2 << "\n";
            break;
        case MessageType::ERR:
            std::cout << "ERROR FROM " << msg.param1 << ": " << msg.param2 << "\n";
            ctx.state = ClientState::TERMINATED;
            break;
        case MessageType::BYE:
            std::cout << "Connection terminated by server.\n";
            ctx.state = ClientState::TERMINATED;
            break;
        default:
            std::cout << "Received unknown or unhandled message type.\n";
            break;
    }
}

// Program arguments structure
struct ProgramArgs {
    std::string transport_protocol;  // Required: "tcp" or "udp"
    std::string server_address;      // Required: IP or hostname
    uint16_t server_port = 4567;     // Default: 4567
    uint16_t udp_timeout = 250;      // Default: 250ms
    uint8_t udp_retransmissions = 3; // Default: 3
};

// Print help information
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

// Parse command line arguments
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

// Set file descriptor to non-blocking mode
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        perror("fcntl(F_SETFL)");
        return -1;
    }
    return 0;
}

// TCP Client implementation with message protocol integration
int run_tcp_client(const std::string& server_ip, int server_port) {
    // Initialize client context
    ClientContext ctx;
    std::cout << "Enter username: ";
    std::getline(std::cin, ctx.username);
    std::cout << "Enter display name: ";
    std::getline(std::cin, ctx.displayName);
    std::string secret;
    std::cout << "Enter secret: ";
    std::getline(std::cin, secret);
    
    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    
    // Set the socket to non-blocking mode
    if (set_nonblocking(sockfd) < 0) {
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Prepare the server address structure
    sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    // First try to parse as direct IP address
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) > 0) {
        std::cout << "Using direct IP address" << std::endl;
    } 
    else if (!resolveHostname(server_ip, &server_addr)) {
        std::cerr << "Could not resolve server address: " << server_ip << std::endl;
        close(sockfd);
        return EXIT_FAILURE;
    }
    else {
        std::cout << "Successfully resolved hostname" << std::endl;
    }

    std::cout << "Connecting to " << server_ip << " (" 
              << inet_ntoa(server_addr.sin_addr) << "):" << server_port << std::endl;
    
    // Initiate non-blocking connection
    int ret = connect(sockfd, (sockaddr*)&server_addr, sizeof(server_addr));
    if (ret < 0 && errno != EINPROGRESS) {
        perror("connect");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Create an epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Register socket with epoll for reading and writing (edge-triggered)
    epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = sockfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        perror("epoll_ctl: sockfd");
        close(sockfd);
        close(epoll_fd);
        return EXIT_FAILURE;
    }
    
    // Also register STDIN to read user input
    ev.events = EPOLLIN;
    ev.data.fd = STDIN_FILENO;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0) {
        perror("epoll_ctl: STDIN");
        close(sockfd);
        close(epoll_fd);
        return EXIT_FAILURE;
    }
    
    const int MAX_EVENTS = 10;
    epoll_event events[MAX_EVENTS];
    bool running = true;
    char buffer[1024];
    bool connected = false;
    bool auth_sent = false;
    
    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }
        
        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;
            if (fd == sockfd) {
                // Handle events on the network socket
                if (events[i].events & EPOLLIN) {
                    // Data available to read from server
                    while (true) {
                        ssize_t count = read(sockfd, buffer, sizeof(buffer) - 1);
                        if (count == -1) {
                            if (errno == EAGAIN || EWOULDBLOCK)
                                break;
                            perror("read from socket");
                            running = false;
                            break;
                        } else if (count == 0) {
                            std::cout << "Server closed the connection.\n";
                            running = false;
                            break;
                        }
                        buffer[count] = '\0';
                        std::string received(buffer, count);
                        std::cout << "Received raw data: [" << received << "]" << std::endl; // Add this debug line

                        // Parse and handle the message
                        ParsedMessage msg = parseMessage(received);
                        std::cout << "Parsed message type: " << static_cast<int>(msg.type) << std::endl; // Add this debug
                        handleIncomingMessage(msg, ctx);
                        
                        // If terminated, exit the loop
                        if (ctx.state == ClientState::TERMINATED) {
                            running = false;
                            break;
                        }
                    }
                }
                
                if (events[i].events & EPOLLOUT) {
                    // Socket ready for writing
                    if (!connected) {
                        // Check if connection was successful
                        int err = 0;
                        socklen_t len = sizeof(err);
                        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                            perror("getsockopt");
                            running = false;
                        }
                        if (err != 0) {
                            std::cerr << "Connection error: " << strerror(err) << "\n";
                            running = false;
                        }
                        
                        // Connection established, send AUTH message
                        if (!auth_sent) {
                            // Check if serializeAuth adds proper CRLF terminators
                            std::string authMsg = serializeAuth(ctx.username, ctx.displayName, secret);
                            std::cout << "Sending auth: [" << authMsg << "]" << std::endl;  // Debug the outgoing message
                            if (write(sockfd, authMsg.c_str(), authMsg.length()) < 0) {
                                perror("write AUTH message");
                                running = false;
                            }
                            auth_sent = true;
                        }
                        
                        connected = true;
                        
                        // Once connected and AUTH sent, modify the socket to only listen for incoming data
                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.fd = sockfd;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sockfd, &ev) < 0) {
                            perror("epoll_ctl: modify sockfd");
                            running = false;
                        }
                    }
                }
            } else if (fd == STDIN_FILENO) {
                // Handle user input from stdin
                std::string input;
                if (!std::getline(std::cin, input)) {
                    running = false;
                    break;
                }
                
                // Process user commands
                if (input.empty()) {
                    continue;
                }
                
                if (input[0] == '/') {
                    // Command processing
                    std::istringstream iss(input.substr(1));
                    std::string cmd;
                    iss >> cmd;
                    
                    if (cmd == "join" && ctx.state == ClientState::AUTHENTICATED) {
                        std::string channelID;
                        iss >> channelID;
                        if (!channelID.empty()) {
                            ctx.channelID = channelID;
                            std::string joinMsg = serializeJoin(channelID, ctx.displayName);
                            if (write(sockfd, joinMsg.c_str(), joinMsg.length()) < 0) {
                                perror("write JOIN message");
                                running = false;
                            }
                        }
                    } else if (cmd == "bye") {
                        std::string byeMsg = serializeBye(ctx.displayName);
                        if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                            perror("write BYE message");
                        }
                        running = false;
                    } else if (cmd == "help") {
                        std::cout << "Available commands:\n";
                        std::cout << "  /join <channel> - Join a channel\n";
                        std::cout << "  /bye - Disconnect from server\n";
                        std::cout << "  /help - Show this help\n";
                    } else {
                        std::cout << "Unknown command. Type /help for available commands.\n";
                    }
                } else if (ctx.state == ClientState::JOINED) {
                    // Regular message in a channel
                    std::string msgContent = serializeMsg(ctx.displayName, input);
                    if (write(sockfd, msgContent.c_str(), msgContent.length()) < 0) {
                        perror("write MSG message");
                        running = false;
                    }
                } else {
                    std::cout << "You must join a channel before sending messages.\n";
                    std::cout << "Use /join <channel> to join a channel.\n";
                }
            }
        }
    }
    
    close(sockfd);
    close(epoll_fd);
    return EXIT_SUCCESS;
}

// UDP Client implementation (placeholder)
int run_udp_client(const std::string& server_ip, int server_port, 
                   uint16_t timeout, uint8_t retransmissions) {
    // TODO: Implement UDP client functionality
    std::cout << "UDP client not yet implemented. Using server: " << server_ip 
              << ":" << server_port << " with timeout: " << timeout 
              << "ms and " << (int)retransmissions << " retransmissions." << std::endl;
    return EXIT_SUCCESS;
}

// Main function
int main(int argc, char* argv[]) {
    try {
        // Parse command-line arguments
        ProgramArgs args = parseArgs(argc, argv);
        
        // Print parsed arguments
        std::cout << "Transport protocol: " << args.transport_protocol << std::endl;
        std::cout << "Server address: " << args.server_address << std::endl;
        std::cout << "Server port: " << args.server_port << std::endl;
        
        if (args.transport_protocol == "udp") {
            std::cout << "UDP timeout: " << args.udp_timeout << " ms" << std::endl;
            std::cout << "UDP retransmissions: " << (int)args.udp_retransmissions << std::endl;
            return run_udp_client(args.server_address, args.server_port, 
                                  args.udp_timeout, args.udp_retransmissions);
        } else {
            return run_tcp_client(args.server_address, args.server_port);
        }
        
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}