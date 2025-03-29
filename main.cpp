// Standard libraries
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <getopt.h>
#include <stdexcept>
#include <string>
#include <sstream>
#include <unistd.h>
#include <time.h>

// Network libraries
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>

// Signal handling for graceful termination (Ctrl+C)
volatile sig_atomic_t terminationRequested = 0;

void signalHandler(int signum) {
    (void)signum; // Suppress unused parameter warning
    terminationRequested = 1;
}

// --- Message protocol definitions ---

/**
 * Supported message types according to the IPK25-CHAT protocol
 */
enum class MessageType {
    AUTH,     // Authentication request
    JOIN,     // Channel join request
    MSG,      // Chat message
    BYE,      // Connection termination
    REPLY,    // Server reply to request 
    ERR,      // Error message
    UNKNOWN   // Unrecognized message
};

/**
 * Converts a string token to a MessageType enum
 */
MessageType stringToMessageType(const std::string& token) {
    if (token == "AUTH")  return MessageType::AUTH;
    if (token == "JOIN")  return MessageType::JOIN;
    if (token == "MSG")   return MessageType::MSG;
    if (token == "BYE")   return MessageType::BYE;
    if (token == "REPLY") return MessageType::REPLY;
    if (token == "ERR")   return MessageType::ERR;
    return MessageType::UNKNOWN;
}

/**
 * Structure for parsed protocol messages
 */
struct ParsedMessage {
    MessageType type = MessageType::UNKNOWN;
    std::string param1;  // First parameter (varies by message type)
    std::string param2;  // Second parameter (varies by message type)
    std::string param3;  // Third parameter (only used in AUTH)
};

/**
 * Message serialization functions for outgoing messages
 */
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

/**
 * Parses raw message into our ParsedMessage structure.
 * Handles all protocol message formats according to specification.
 */
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
            // If the token isn't recognized, mark the message as malformed.
            msg.type = MessageType::UNKNOWN;
            break;
    }
    return msg;
}

/**
 * Client states - aligned with Finite State Machine diagram
 */
enum class ClientState {
    INIT,           // "start" in FSM - initial state
    AUTHENTICATING, // "auth" in FSM - sending AUTH and waiting for REPLY
    JOINED,         // "open" in FSM - authenticated and ready to send messages 
    JOIN_WAITING,   // "join" in FSM - sent JOIN, waiting for REPLY
    TERMINATED      // "end" in FSM - connection terminated
};

/**
 * Client context - stores current state and user information
 */
struct ClientContext {
    ClientState state = ClientState::INIT;
    std::string displayName;
    std::string username;
    std::string channelID;
};

/**
 * Checks if the received message type is valid in the current client state
 * Based on the protocol FSM diagram
 */
bool isValidTransition(ClientState state, MessageType msgType) {
    switch (state) {
        case ClientState::INIT:
            // Initial state - just starting
            return false; // No incoming messages expected
            
        case ClientState::AUTHENTICATING:
            // After sending AUTH, we expect REPLY, ERR, or BYE
            return (msgType == MessageType::REPLY ||
                    msgType == MessageType::ERR   ||
                    msgType == MessageType::BYE);
        
        case ClientState::JOINED:
            // In the "open" state, we can receive MSG, REPLY, ERR, or BYE
            return (msgType == MessageType::MSG   ||
                    msgType == MessageType::REPLY ||
                    msgType == MessageType::ERR   ||
                    msgType == MessageType::BYE);

        case ClientState::JOIN_WAITING:
            // In the "join" state, we expect REPLY, MSG, ERR, or BYE
            return (msgType == MessageType::MSG   ||
                    msgType == MessageType::REPLY ||
                    msgType == MessageType::ERR   ||
                    msgType == MessageType::BYE);

        case ClientState::TERMINATED:
            // Once terminated, no further messages are valid
            return false;
    }
    return false;
}

/**
 * Handles incoming messages from server according to FSM rules
 */
void handleIncomingMessage(const ParsedMessage& msg, ClientContext& ctx, int sockfd) {
    switch (msg.type) {
        case MessageType::REPLY:
            // Per FSM: When in "join" state, any REPLY returns us to "open" state
            if (ctx.state == ClientState::JOIN_WAITING) {
                ctx.state = ClientState::JOINED;
                if (msg.param1 == "OK") {
                    std::cout << "Action Success: " << msg.param2 << "\n";
                } else {
                    std::cout << "Action Failure: " << msg.param2 << "\n";
                }
            }
            // Per FSM: When in "auth" state, REPLY moves us to "open" state
            else if (ctx.state == ClientState::AUTHENTICATING) {
                if (msg.param1 == "OK") {
                    std::cout << "Authentication Success: " << msg.param2 << "\n";
                    ctx.state = ClientState::JOINED;
                } else {
                    std::cout << "Authentication Failure: " << msg.param2 << "\n";
                    // Stay in AUTHENTICATING state per FSM (auth self-loop for !REPLY)
                }
            } 
            // In JOINED state, just show the reply
            else {
                if (msg.param1 == "OK") {
                    std::cout << "Action Success: " << msg.param2 << "\n";
                } else {
                    std::cout << "Action Failure: " << msg.param2 << "\n";
                }
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
            std::cout << "ERROR: Received malformed or invalid message from server.\n";
            std::string errMsg = "ERR FROM " + ctx.displayName + " IS Malformed message\r\n";
            if (write(sockfd, errMsg.c_str(), errMsg.length()) < 0) {
                perror("write ERR message");
            }
            ctx.state = ClientState::TERMINATED;
            break;
    }
}

/**
 * Program command-line arguments structure
 */
struct ProgramArgs {
    std::string transport_protocol;  
    std::string server_address;      
    uint16_t server_port = 4567;     
    uint16_t udp_timeout = 250;      
    uint8_t udp_retransmissions = 3; 
};

/**
 * Prints program usage help
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
 * Parses command-line arguments
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

/**
 * TCP Client implementation that follows the IPK25-CHAT protocol FSM
 * Handles connection establishment, authentication, joining channels,
 * and sending/receiving messages according to the protocol specification.
 */
int run_tcp_client(const std::string& server_ip, int server_port) {
    // Initialize client context with user credentials
    ClientContext ctx;
    ctx.state = ClientState::INIT; 
    std::cout << "Enter username: ";
    std::getline(std::cin, ctx.username);
    std::cout << "Enter display name: ";
    std::getline(std::cin, ctx.displayName);
    std::string secret;
    std::cout << "Enter secret: ";
    std::getline(std::cin, secret);
    
    // Set up TCP connection to server using IPv4
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4 only (as per spec)
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_ADDRCONFIG;  

    // Resolve server address
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
            break;
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

    // Begin protocol FSM - Send AUTH message (transition from start→auth)
    std::string authMsg = serializeAuth(ctx.username, ctx.displayName, secret);
    std::cout << "Sending AUTH message:\n" << authMsg;
    ctx.state = ClientState::AUTHENTICATING;
    if (write(sockfd, authMsg.c_str(), authMsg.length()) < 0) {
        perror("write AUTH message");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Buffer for incoming messages
    char buffer[1024];
    bool running = true;
    
    // Handle auth response with 5-second timeout (required by protocol)
    {
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
        if (count <= 0) {
            if (count < 0) {
                perror("read from socket");
            }
            std::cout << "Server closed the connection.\n";
            close(sockfd);
            return EXIT_FAILURE;
        }
        
        buffer[count] = '\0';
        std::string received(buffer, count);
        std::cout << "Received response:\n" << received;
        
        ParsedMessage msg = parseMessage(received);
        if (msg.type == MessageType::UNKNOWN || !isValidTransition(ctx.state, msg.type)) {
            std::cout << "ERROR: Protocol violation or malformed message from server.\n";
            std::string errMsg = "ERR FROM " + ctx.displayName + " IS Protocol violation or malformed message\r\n";
            write(sockfd, errMsg.c_str(), errMsg.length());
            close(sockfd);
            return EXIT_FAILURE;
        } 
        
        handleIncomingMessage(msg, ctx, sockfd);
        if (ctx.state == ClientState::TERMINATED) {
            close(sockfd);
            return EXIT_FAILURE;
        }
    }
    
    // Main client loop - handle user input and server messages
    fd_set readfds;
    bool waitingForReply = false;
    time_t replyDeadline = 0;

    while (running) {
        // Handle graceful shutdown on SIGINT
        if (terminationRequested) {
            std::string byeMsg = serializeBye(ctx.displayName);
            write(sockfd, byeMsg.c_str(), byeMsg.length());
            break;
        }
        
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        // Setup timeout for waiting for replies
        struct timeval tv;
        struct timeval* tv_ptr = nullptr;
        if (waitingForReply) {
            time_t now = time(nullptr);
            if (now >= replyDeadline) {
                std::cout << "ERROR: No REPLY received within 5 seconds.\n";
                close(sockfd);
                return EXIT_FAILURE;
            } else {
                tv.tv_sec = replyDeadline - now;
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
            std::cout << "ERROR: No REPLY within 5 seconds (timeout).\n";
            close(sockfd);
            return EXIT_FAILURE;
        }
        
        // Handle server messages
        if (FD_ISSET(sockfd, &readfds)) {
            ssize_t count = read(sockfd, buffer, sizeof(buffer) - 1);
            if (count <= 0) {
                if (count < 0) perror("read from socket");
                else std::cout << "Server closed the connection.\n";
                break;
            }
            
            buffer[count] = '\0';
            std::string received(buffer, count);
            ParsedMessage msg = parseMessage(received);

            // Update reply waiting status
            if (msg.type == MessageType::REPLY) {
                waitingForReply = false;
            }

            // Validate message against FSM
            if (msg.type == MessageType::UNKNOWN || !isValidTransition(ctx.state, msg.type)) {
                std::cout << "ERROR: Protocol violation or malformed message from server.\n";
                std::string errMsg = "ERR FROM " + ctx.displayName + " IS Protocol violation or malformed message\r\n";
                write(sockfd, errMsg.c_str(), errMsg.length());
                ctx.state = ClientState::TERMINATED;
            } else {
                handleIncomingMessage(msg, ctx, sockfd);
            }
            
            if (ctx.state == ClientState::TERMINATED) {
                break;
            }
        }
        
        // Handle user input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            std::string input;
            if (!std::getline(std::cin, input) || input.empty()) {
                continue;
            }
            
            // Process user commands (starting with /)
            if (input[0] == '/') {
                std::istringstream iss(input.substr(1));
                std::string cmd;
                iss >> cmd;
                
                // JOIN command - FSM transition from open→join
                if (cmd == "join" && ctx.state == ClientState::JOINED) {
                    std::string channelID;
                    iss >> channelID;
                    if (!channelID.empty()) {
                        ctx.channelID = channelID;
                        std::string joinMsg = serializeJoin(channelID, ctx.displayName);
                        std::cout << "Sending JOIN message:\n" << joinMsg;
                        if (write(sockfd, joinMsg.c_str(), joinMsg.length()) < 0) {
                            perror("write JOIN message");
                            break;
                        }
                        // Update state according to FSM
                        ctx.state = ClientState::JOIN_WAITING;
                        waitingForReply = true;
                        replyDeadline = time(nullptr) + 5; // 5-second timeout
                    } else {
                        std::cout << "Error: Channel name cannot be empty\n";
                        std::cout << "Usage: /join <channel>\n"; 
                    }
                } 
                // AUTH command - support re-authentication
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
                            break;
                        }
                        // Update state according to FSM
                        ctx.state = ClientState::AUTHENTICATING;
                        waitingForReply = true;
                        replyDeadline = time(nullptr) + 5;
                    }
                }
                // Local rename command (client-side only)
                else if (cmd == "rename") {
                    std::string newDisplayName;
                    iss >> newDisplayName;
                    if (!newDisplayName.empty()) {
                        ctx.displayName = newDisplayName;
                        std::cout << "Display name updated to: " << newDisplayName << "\n";
                    } else {
                        std::cout << "Usage: /rename <displayName>\n";
                    }
                } 
                // BYE command - terminate connection
                else if (cmd == "bye") {
                    std::string byeMsg = serializeBye(ctx.displayName);
                    write(sockfd, byeMsg.c_str(), byeMsg.length());
                    break;
                } 
                // Help command
                else if (cmd == "help") {
                    std::cout << "Available commands:\n";
                    std::cout << "  /join <channel>       - Join a channel\n";
                    std::cout << "  /auth <u> <s> <d>     - Re-authenticate with new credentials\n";
                    std::cout << "  /rename <displayName> - Change display name locally\n";
                    std::cout << "  /bye                  - Disconnect from server\n";
                    std::cout << "  /help                 - Show this help\n";
                } 
                else {
                    std::cout << "Unknown command. Type /help for available commands.\n";
                }
            } 
            // Regular message - send to channel if in JOINED state
            else if (ctx.state == ClientState::JOINED) {
                const size_t MAX_MSG_LEN = 60000;
                if (input.size() > MAX_MSG_LEN) {
                    std::cout << "Message truncated to " << MAX_MSG_LEN << " characters.\n";
                    input = input.substr(0, MAX_MSG_LEN);
                }
                std::string msgContent = serializeMsg(ctx.displayName, input);
                if (write(sockfd, msgContent.c_str(), msgContent.length()) < 0) {
                    perror("write MSG message");
                    break;
                }
            } 
            // Not in JOINED state
            else {
                std::cout << "You must join a channel before sending messages.\n";
                std::cout << "Use /join <channel> to join a channel.\n";
            }
        }
    }
    
    close(sockfd);
    return EXIT_SUCCESS;
}

/**
 * UDP Client implementation stub
 * This will need to be implemented to fully meet the project requirements
 */
int run_udp_client(const std::string& server_ip, int server_port, 
                  uint16_t timeout, uint8_t retransmissions) {
    std::cout << "UDP client not yet implemented. Using server: " << server_ip 
              << ":" << server_port << " with timeout: " << timeout 
              << "ms and " << (int)retransmissions << " retransmissions." << std::endl;
    return EXIT_SUCCESS;
}

/**
 * Main function - parses command line arguments and runs the appropriate client
 */
int main(int argc, char* argv[]) {
    // Set up signal handler for CTRL+C
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