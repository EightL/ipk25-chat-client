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
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>
#include <signal.h>

// Signal handling for graceful termination
volatile sig_atomic_t terminationRequested = 0;

void signalHandler(int signum) {
    (void)signum; 
    terminationRequested = 1;
}

// --- Message protocol definitions ---

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
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      
    hints.ai_socktype = SOCK_STREAM; 
    
    int status = getaddrinfo(hostname.c_str(), NULL, &hints, &results);
    if (status != 0) {
        std::cerr << "Failed to resolve hostname: " << hostname << ": " 
                  << gai_strerror(status) << std::endl;
        return false;
    }
    
    for (result = results; result != NULL; result = result->ai_next) {
        if (result->ai_family == AF_INET) {
            memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
            freeaddrinfo(results);
            return true;
        }
    }
    
    freeaddrinfo(results);
    std::cerr << "No IPv4 address found for hostname: " << hostname << std::endl;
    return false;
}

MessageType stringToMessageType(const std::string& token) {
    if (token == "AUTH")  return MessageType::AUTH;
    if (token == "JOIN")  return MessageType::JOIN;
    if (token == "MSG")   return MessageType::MSG;
    if (token == "BYE")   return MessageType::BYE;
    if (token == "REPLY") return MessageType::REPLY;
    if (token == "ERR")   return MessageType::ERR;
    return MessageType::UNKNOWN;
}

struct ParsedMessage {
    MessageType type = MessageType::UNKNOWN;
    std::string param1;
    std::string param2;
    std::string param3;
};

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

// Parses raw message into our ParsedMessage structure.
ParsedMessage parseMessage(const std::string& raw) {
    ParsedMessage msg;
    std::istringstream iss(raw);
    std::string token;
    
    // Attempt to read the first token to identify message type
    if (!(iss >> token)) { 
        // no token => malformed
        msg.type = MessageType::UNKNOWN;
        return msg;
    }
    msg.type = stringToMessageType(token);
    
    switch (msg.type) {
        case MessageType::AUTH:
            // Expect: AUTH <username> AS <displayName> USING <secret>
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> msg.param2)) { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            std::getline(iss, msg.param3);
            msg.param3.erase(msg.param3.find_last_not_of(" \r\n") + 1);
            break;

        case MessageType::JOIN:
            // Expect: JOIN <channelID> AS <displayName>
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> msg.param2)) { msg.type = MessageType::UNKNOWN; break; }
            break;

        case MessageType::MSG:
            // Expect: MSG FROM <displayName> IS <messageContent>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip FROM
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // displayName
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip IS
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;

        case MessageType::BYE:
            // Expect: BYE FROM <displayName>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; }
            break;

        case MessageType::REPLY:
            // Expect: REPLY <OK|NOK> IS <some content>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            msg.param1 = token; // e.g., "OK" or "NOK"
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip "IS"
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;

        case MessageType::ERR:
            // Expect: ERR FROM <displayName> IS <errorMessage>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip FROM
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // displayName
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip IS
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;

        default:
            // If the token isn’t recognized, mark the message as malformed.
            msg.type = MessageType::UNKNOWN;
            break;
    }
    return msg;
}

enum class ClientState {
    INIT,
    AUTHENTICATED,
    JOINED,
    TERMINATED
};

struct ClientContext {
    ClientState state = ClientState::INIT;
    std::string displayName;
    std::string username;
    std::string channelID;
};

// Validates that the given message type is allowed in the current client state.
bool isValidTransition(ClientState state, MessageType msgType) {
    switch (state) {
        case ClientState::INIT:
            // After sending AUTH, we typically expect REPLY (OK or NOK), ERR, or BYE
            return (msgType == MessageType::REPLY ||
                    msgType == MessageType::ERR   ||
                    msgType == MessageType::BYE);
        
        case ClientState::AUTHENTICATED:
            // Possibly the server auto-joins or sends REPLY, ERR, MSG, or BYE
            return (msgType == MessageType::REPLY ||
                    msgType == MessageType::ERR   ||
                    msgType == MessageType::BYE   ||
                    msgType == MessageType::MSG);

        case ClientState::JOINED:
            // We expect MSG, REPLY (e.g., from /join), ERR, or BYE
            return (msgType == MessageType::MSG   ||
                    msgType == MessageType::REPLY ||
                    msgType == MessageType::ERR   ||
                    msgType == MessageType::BYE);

        case ClientState::TERMINATED:
            // Once terminated, no further messages are valid
            return false;
    }
    // Fallback
    return false;
}

void handleIncomingMessage(const ParsedMessage& msg, ClientContext& ctx, int sockfd) {
    switch (msg.type) {
        case MessageType::REPLY:
            if (msg.param1 == "OK") {
                std::cout << "Action Success: " << msg.param2 << "\n";
                // If we were in INIT or AUTHENTICATED, transition to JOINED
                if (ctx.state == ClientState::INIT || ctx.state == ClientState::AUTHENTICATED) {
                    ctx.state = ClientState::JOINED;
                }
            } else {
                std::cout << "Action Failure: " << msg.param2 << "\n";
            }
            break;

        case MessageType::MSG:
            std::cout << msg.param1 << ": " << msg.param2 << "\n";
            break;

        case MessageType::ERR:
            std::cout << "ERROR FROM " << msg.param1 << ": " << msg.param2 << "\n";
            // The spec says ERR leads to termination
            ctx.state = ClientState::TERMINATED;
            break;

        case MessageType::BYE:
            std::cout << "Connection terminated by server.\n";
            ctx.state = ClientState::TERMINATED;
            break;

        default:
        std::cout << "ERROR: Received malformed or invalid message from server.\n";
        // Optionally, send an ERR message back if the socket is still valid.
        std::string errMsg = "ERR FROM " + ctx.displayName + " IS Malformed message\r\n";
        // Assuming sockfd is accessible in this context.
        if (write(sockfd, errMsg.c_str(), errMsg.length()) < 0) {
            perror("write ERR message");
        }
        ctx.state = ClientState::TERMINATED;
            break;
    }
}

struct ProgramArgs {
    std::string transport_protocol;  
    std::string server_address;      
    uint16_t server_port = 4567;     
    uint16_t udp_timeout = 250;      
    uint8_t udp_retransmissions = 3; 
};

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
    
    // Prepare getaddrinfo hints
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4 only
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_ADDRCONFIG;  // Use address configuration

    // Convert port to string for getaddrinfo
    std::string port_str = std::to_string(server_port);
    struct addrinfo* result;
    int s = getaddrinfo(server_ip.c_str(), port_str.c_str(), &hints, &result);
    if (s != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(s) << std::endl;
        return EXIT_FAILURE;
    }

    // Try each address until we successfully connect
    int sockfd = -1;
    struct addrinfo* rp;
    bool connected = false;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)rp->ai_addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
        std::cout << "Trying to connect to " << ip_str << " on port " << server_port << "..." << std::endl;
        
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue;
        }
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            std::cout << "Connected to " << ip_str << std::endl;
            connected = true;
            break;  // Successfully connected
        } else {
            perror("connect");
            close(sockfd);
            sockfd = -1;
        }
    }
    freeaddrinfo(result);

    if (!connected) {
        std::cerr << "Could not connect to any resolved address." << std::endl;
        return EXIT_FAILURE;
    }

    // Send AUTH message
    std::string authMsg = serializeAuth(ctx.username, ctx.displayName, secret);
    std::cout << "Sending AUTH message:\n" << authMsg;
    ssize_t bytes_written = write(sockfd, authMsg.c_str(), authMsg.length());
    if (bytes_written < 0) {
        perror("write AUTH message");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Set up for I/O handling with the connected socket
    bool running = true;
    char buffer[1024];
    
    // Read server response to AUTH (the first message from server)
    {
        // Set up a 5-second timeout for authentication
        fd_set auth_readfds;
        struct timeval auth_tv;
        auth_tv.tv_sec = 5;
        auth_tv.tv_usec = 0;
        
        FD_ZERO(&auth_readfds);
        FD_SET(sockfd, &auth_readfds);
        
        int auth_result = select(sockfd + 1, &auth_readfds, NULL, NULL, &auth_tv);
        if (auth_result == 0) {
            std::cout << "ERROR: Authentication response timeout (5 seconds).\n";
            close(sockfd);
            return EXIT_FAILURE;
        } else if (auth_result < 0) {
            perror("select on AUTH response");
            close(sockfd);
            return EXIT_FAILURE;
        }
        
        ssize_t count = read(sockfd, buffer, sizeof(buffer) - 1);
        if (count < 0) {
            perror("read from socket");
            close(sockfd);
            return EXIT_FAILURE;
        } else if (count == 0) {
            std::cout << "Server closed the connection.\n";
            close(sockfd);
            return EXIT_FAILURE;
        }
        
        buffer[count] = '\0';
        std::string received(buffer, count);
        std::cout << "Received response:\n" << received;  // Add debug output
        ParsedMessage msg = parseMessage(received);

        // Check for malformed or invalid transition in the INIT state
        if (msg.type == MessageType::UNKNOWN || !isValidTransition(ctx.state, msg.type)) {
            std::cout << "ERROR: Protocol violation or malformed message from server.\n";
            // Send ERR back to server
            std::string errMsg = "ERR FROM " + ctx.displayName + " IS Protocol violation or malformed message\r\n";
            if (write(sockfd, errMsg.c_str(), errMsg.length()) < 0) {
                perror("write ERR message");
            }
            ctx.state = ClientState::TERMINATED;
        } else {
            handleIncomingMessage(msg, ctx, sockfd);
        }
        
        if (ctx.state == ClientState::TERMINATED) {
            close(sockfd);
            return EXIT_FAILURE;
        }
    }
    
    // After successful authentication, handle further I/O using select()
    fd_set readfds;
    bool waitingForReply = false;
    time_t replyDeadline = 0;

    while (running) {
        if (terminationRequested) {
            // On Ctrl-C, gracefully close
            std::string byeMsg = serializeBye(ctx.displayName);
            if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                perror("write BYE message");
            }
            running = false;
            break;
        }
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        // Prepare timeout if needed
        struct timeval tv;
        struct timeval* tv_ptr = nullptr;
        if (waitingForReply) {
            time_t now = time(nullptr);
            if (now >= replyDeadline) {
                std::cout << "ERROR: No REPLY received within 5 seconds.\n";
                // Optionally send ERR, then close
                close(sockfd);
                return EXIT_FAILURE;
            } else {
                time_t secsLeft = replyDeadline - now;
                tv.tv_sec  = secsLeft;
                tv.tv_usec = 0;
                tv_ptr = &tv;
            }
        }

        int max_fd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;
        int activity = select(max_fd + 1, &readfds, NULL, NULL, tv_ptr);
        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        } else if (activity == 0) {
            // Timeout occurred, check if we were waiting for a reply
            std::cout << "ERROR: No REPLY within 5 seconds (timeout).\n";
            close(sockfd);
            return EXIT_FAILURE;
        }
        
        // Handle socket input
        if (FD_ISSET(sockfd, &readfds)) {
            ssize_t count = read(sockfd, buffer, sizeof(buffer) - 1);
            if (count < 0) {
                perror("read from socket");
                running = false;
                break;
            } else if (count == 0) {
                std::cout << "Server closed the connection.\n";
                running = false;
                break;
            }
            
            buffer[count] = '\0';
            std::string received = std::string(buffer, count);
            // Parse and validate the incoming message
            ParsedMessage msg = parseMessage(received);

            if (msg.type == MessageType::REPLY) {
                // Got a REPLY, so clear the waiting flag.
                waitingForReply = false;
            }

            if (msg.type == MessageType::UNKNOWN || !isValidTransition(ctx.state, msg.type)) {
                std::cout << "ERROR: Protocol violation or malformed message from server.\n";
                // Send ERR back to server
                std::string errMsg = "ERR FROM " + ctx.displayName + " IS Protocol violation or malformed message\r\n";
                if (write(sockfd, errMsg.c_str(), errMsg.length()) < 0) {
                    perror("write ERR message");
                }
                ctx.state = ClientState::TERMINATED;
            } else {
                // Handle the valid message
                handleIncomingMessage(msg, ctx, sockfd);
            }
            
            // If we have moved to TERMINATED, break the loop
            if (ctx.state == ClientState::TERMINATED) {
                running = false;
                break;
            }
        }
        
        // Handle user input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            std::string input;
            if (!std::getline(std::cin, input)) {
                running = false;
                break;
            }
            if (input.empty()) continue;
            
            const size_t MAX_MSG_LEN = 60000;
            
            // Process user commands
            if (input[0] == '/') {
                std::istringstream iss(input.substr(1));
                std::string cmd;
                iss >> cmd;
                if (cmd == "join" && (ctx.state == ClientState::AUTHENTICATED || ctx.state == ClientState::JOINED)) {
                    std::string channelID;
                    iss >> channelID;
                    if (!channelID.empty()) {
                        ctx.channelID = channelID;
                        std::string joinMsg = serializeJoin(channelID, ctx.displayName);
                        std::cout << "Sending JOIN message:\n" << joinMsg;  // Add debug output
                        if (write(sockfd, joinMsg.c_str(), joinMsg.length()) < 0) {
                            perror("write JOIN message");
                            running = false;
                        } else {
                            waitingForReply = true;
                            replyDeadline = time(nullptr) + 5;
                            std::cout << "Waiting for reply with deadline in 5 seconds...\n";  // Debug
                        }
                    } else {
                        std::cout << "Error: Channel name cannot be empty\n";
                        std::cout << "Usage: /join <channel>\n"; 
                    }
                } 
                else if (cmd == "auth") {
                    std::string newUsername, newSecret, newDisplayName;
                    iss >> newUsername >> newSecret >> newDisplayName;
                    if (newUsername.empty() || newSecret.empty() || newDisplayName.empty()) {
                        std::cout << "Usage: /auth <username> <secret> <displayName>\n";
                    } else {
                        ctx.username = newUsername;
                        ctx.displayName = newDisplayName;
                        std::string authMsg = serializeAuth(newUsername, newDisplayName, newSecret);
                        if (write(sockfd, authMsg.c_str(), authMsg.length()) < 0) {
                            perror("write AUTH message");
                            running = false;
                        } else {
                            std::cout << "Sent re-authentication message.\n";
                            waitingForReply = true;
                            replyDeadline = time(nullptr) + 5;
                        }
                    }
                }
                else if (cmd == "rename") {
                    // Expected format: /rename <displayName>
                    std::string newDisplayName;
                    iss >> newDisplayName;
                    if (newDisplayName.empty()) {
                        std::cout << "Usage: /rename <displayName>\n";
                    } else {
                        ctx.displayName = newDisplayName;
                        std::cout << "Display name updated to: " << newDisplayName << "\n";
                    }
                } 
                else if (cmd == "bye") {
                    std::string byeMsg = serializeBye(ctx.displayName);
                    if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                        perror("write BYE message");
                    }
                    running = false;
                } 
                else if (cmd == "help") {
                    std::cout << "Available commands:\n";
                    std::cout << "  /join <channel>       - Join a channel\n";
                    std::cout << "  /auth <u> <s> <d>       - Re-authenticate with new credentials (username, secret, displayName)\n";
                    std::cout << "  /rename <displayName>   - Change your display name locally\n";
                    std::cout << "  /bye                  - Disconnect from server\n";
                    std::cout << "  /help                 - Show this help\n";
                } 
                else {
                    std::cout << "Unknown command. Type /help for available commands.\n";
                }
            } else if (ctx.state == ClientState::JOINED) {
                // Validate message length:
                if (input.size() > MAX_MSG_LEN) {
                    std::cout << "ERROR: Message exceeds maximum allowed length (" 
                              << MAX_MSG_LEN << " characters). Truncating message.\n";
                    input = input.substr(0, MAX_MSG_LEN);
                }
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
    
    close(sockfd);
    return EXIT_SUCCESS;
}

int run_udp_client(const std::string& server_ip, int server_port, 
                   uint16_t timeout, uint8_t retransmissions) {
    std::cout << "UDP client not yet implemented. Using server: " << server_ip 
              << ":" << server_port << " with timeout: " << timeout 
              << "ms and " << (int)retransmissions << " retransmissions." << std::endl;
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);

    try {
        ProgramArgs args = parseArgs(argc, argv);
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
