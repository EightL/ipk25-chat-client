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
#include <set>
#include <vector>
#include <chrono>
#include <fcntl.h>

// Network libraries
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <signal.h>

// Debug logging macro
#ifdef DEBUG_PRINT
#define printf_debug(format, ...) fprintf(stderr, "%s:%-4d | %15s | " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define printf_debug(format, ...) (0)
#endif

// Signal handling for graceful termination (Ctrl+C)
volatile sig_atomic_t terminationRequested = 0;

void signalHandler(int signum) {
    (void)signum; // Suppress unused parameter warning
    terminationRequested = 1;
}

// UDP protocol constants
const uint8_t AUTH_TYPE    = 0x02;
const uint8_t CONFIRM_TYPE = 0x00;
const uint8_t REPLY_TYPE   = 0x01;
const uint8_t JOIN_TYPE    = 0x03;
const uint8_t MSG_TYPE     = 0x04;
const uint8_t PING_TYPE    = 0xFD;
const uint8_t ERR_TYPE     = 0xFE;
const uint8_t BYE_TYPE     = 0xFF;

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
    CONFIRM,  // UDP message confirmation
    PING,     // UDP ping message
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
    uint16_t msgId = 0;  // Message ID for UDP
    uint16_t refMsgId = 0; // Referenced message ID for UDP REPLY/CONFIRM
    bool success = false; // For REPLY messages, indicates OK vs NOK
};

/**
 * Message serialization functions for outgoing TCP messages
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
 * Parses raw TCP message into our ParsedMessage structure.
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
            msg.param3.erase(0, msg.param3.find_first_not_of(" "));
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
            msg.success = (token == "OK");
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
    uint16_t nextMsgId = 0;        // For UDP, next outgoing message ID
    std::set<uint16_t> seenMsgIds; // For UDP, track seen message IDs
    bool isUdp = false;            // True if using UDP mode
    sockaddr_in serverAddr;        // For UDP, server address
    int socketFd = -1;             // Socket file descriptor
    
    // Get and increment message ID
    uint16_t getNextMsgId() {
        return nextMsgId++;
    }
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
 * Set a file descriptor to non-blocking mode
 */
void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "Error getting flags for fd " << fd << ": " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "Error setting non-blocking mode for fd " << fd << ": " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
}

/**
 * Helper function for hostname resolution
 */
std::string resolveHostname(const std::string& hostname) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;     // Only IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket
    
    int status = getaddrinfo(hostname.c_str(), NULL, &hints, &result);
    if (status != 0) {
        std::cerr << "Failed to resolve hostname: " << gai_strerror(status) << std::endl;
        return "";
    }
    
    char ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(result->ai_addr);
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    freeaddrinfo(result);
    return std::string(ipstr);
}

/**
 * UDP Binary Message Building Functions
 */
std::vector<char> buildUdpAuthMessage(uint16_t msgId, const std::string& username, 
                                   const std::string& displayName, const std::string& secret) {
    std::vector<char> message;
    message.push_back(AUTH_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), username.begin(), username.end());
    message.push_back('\0');
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    message.insert(message.end(), secret.begin(), secret.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildUdpJoinMessage(uint16_t msgId, const std::string& channelId, const std::string& displayName) {
    std::vector<char> message;
    message.push_back(JOIN_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), channelId.begin(), channelId.end());
    message.push_back('\0');
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildUdpMsgMessage(uint16_t msgId, const std::string& displayName, const std::string& msgContent) {
    std::vector<char> message;
    message.push_back(MSG_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    message.insert(message.end(), msgContent.begin(), msgContent.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildUdpByeMessage(uint16_t msgId, const std::string& displayName) {
    std::vector<char> message;
    message.push_back(BYE_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildConfirmMessage(uint16_t refMsgId) {
    std::vector<char> message;
    message.push_back(CONFIRM_TYPE);
    uint16_t netMsgId = htons(refMsgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    return message;
}

/**
 * Parse UDP binary message
 */
ParsedMessage parseUdpMessage(const char* buffer, size_t length) {
    ParsedMessage msg;
    
    if (length < 3) { // All messages have at least type + msgId (3 bytes)
        msg.type = MessageType::UNKNOWN;
        return msg;
    }
    
    uint8_t msgType = buffer[0];
    uint16_t msgId;
    memcpy(&msgId, &buffer[1], 2);
    msg.msgId = ntohs(msgId);
    
    switch (msgType) {
        case CONFIRM_TYPE:
            msg.type = MessageType::CONFIRM;
            if (length >= 3) {
                msg.refMsgId = msg.msgId; // In CONFIRM, msgId is actually refMsgId
            }
            break;
            
        case REPLY_TYPE:
            msg.type = MessageType::REPLY;
            if (length >= 6) {
                msg.success = (buffer[3] == 1);
                uint16_t refId;
                memcpy(&refId, &buffer[4], 2);
                msg.refMsgId = ntohs(refId);
                
                // Extract message content if present
                if (length > 6) {
                    const char* content = &buffer[6];
                    msg.param2 = std::string(content); // Content after the null terminator
                }
            }
            break;
            
        case MSG_TYPE:
            msg.type = MessageType::MSG;
            if (length > 3) {
                // Extract displayName and content
                const char* displayName = &buffer[3];
                size_t nameLen = strlen(displayName);
                if (3 + nameLen + 1 < length) {
                    msg.param1 = std::string(displayName);
                    const char* content = displayName + nameLen + 1;
                    msg.param2 = std::string(content);
                }
            }
            break;
            
        case BYE_TYPE:
            msg.type = MessageType::BYE;
            if (length > 3) {
                const char* displayName = &buffer[3];
                msg.param1 = std::string(displayName);
            }
            break;
            
        case ERR_TYPE:
            msg.type = MessageType::ERR;
            if (length > 3) {
                // Extract displayName and error message
                const char* displayName = &buffer[3];
                size_t nameLen = strlen(displayName);
                if (3 + nameLen + 1 < length) {
                    msg.param1 = std::string(displayName);
                    const char* errMsg = displayName + nameLen + 1;
                    msg.param2 = std::string(errMsg);
                }
            }
            break;
            
        case PING_TYPE:
            msg.type = MessageType::PING;
            break;
            
        default:
            msg.type = MessageType::UNKNOWN;
    }
    
    return msg;
}

/**
 * Helper function to update server port when receiving messages from dynamic port
 */
void checkAndUpdateServerPort(sockaddr_in& serverAddr, const sockaddr_in& peerAddr) {
    uint16_t currentServerPort = ntohs(serverAddr.sin_port);
    uint16_t incomingPort = ntohs(peerAddr.sin_port);
    
    if (currentServerPort != incomingPort) {
        printf_debug("Server changed ports: %d -> %d. Updating connection.", currentServerPort, incomingPort);
        serverAddr.sin_port = htons(incomingPort);
    }
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
                if (msg.success) {
                    std::cout << "Action Success: " << msg.param2 << "\n";
                } else {
                    std::cout << "Action Failure: " << msg.param2 << "\n";
                }
            }
            // Per FSM: When in "auth" state, REPLY moves us to "open" state
            else if (ctx.state == ClientState::AUTHENTICATING) {
                if (msg.success) {
                    std::cout << "Authentication Success: " << msg.param2 << "\n";
                    ctx.state = ClientState::JOINED;
                } else {
                    std::cout << "Authentication Failure: " << msg.param2 << "\n";
                    // Stay in AUTHENTICATING state per FSM (auth self-loop for !REPLY)
                }
            } 
            // In JOINED state, just show the reply
            else {
                if (msg.success) {
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
            if (!ctx.isUdp) {
                std::string errMsg = "ERR FROM " + ctx.displayName + " IS Malformed message\r\n";
                if (write(sockfd, errMsg.c_str(), errMsg.length()) < 0) {
                    perror("write ERR message");
                }
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
 * UDP Client implementation that follows the IPK25-CHAT protocol
 */
int run_udp_client(const std::string& server_ip, int server_port, 
                   uint16_t timeoutMs, uint8_t maxRetransmissions) {
    // Initialize client context
    ClientContext ctx;
    ctx.state = ClientState::INIT; 
    ctx.isUdp = true;
    std::cout << "Enter username: ";
    std::getline(std::cin, ctx.username);
    std::cout << "Enter display name: ";
    std::getline(std::cin, ctx.displayName);
    std::string secret;
    std::cout << "Enter secret: ";
    std::getline(std::cin, secret);
    
    // Resolve hostname to IP if needed
    std::string resolvedIP = resolveHostname(server_ip);
    std::string serverIP = resolvedIP.empty() ? server_ip : resolvedIP;
    
    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return EXIT_FAILURE;
    }
    ctx.socketFd = sockfd;
    setNonBlocking(sockfd);
    
    // Bind to any available port
    sockaddr_in localAddr;
    std::memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(0);
    if (bind(sockfd, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr)) < 0) {
        perror("bind failed");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Set up server address
    memset(&ctx.serverAddr, 0, sizeof(ctx.serverAddr));
    ctx.serverAddr.sin_family = AF_INET;
    ctx.serverAddr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, serverIP.c_str(), &ctx.serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid server address: " << serverIP << std::endl;
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Set up epoll for I/O multiplexing
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Add socket to epoll
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sockfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        perror("epoll_ctl: sockfd");
        close(epoll_fd);
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Add stdin to epoll
    setNonBlocking(STDIN_FILENO);
    epoll_event ev_stdin;
    ev_stdin.events = EPOLLIN;
    ev_stdin.data.fd = STDIN_FILENO;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev_stdin) < 0) {
        perror("epoll_ctl: stdin");
        close(epoll_fd);
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Send AUTH message
    uint16_t authMsgId = ctx.getNextMsgId();
    std::vector<char> authMsg = buildUdpAuthMessage(authMsgId, ctx.username, ctx.displayName, secret);
    
    // Set up for AUTH with retransmissions
    bool authConfirmReceived = false;
    bool authReplyReceived = false;
    int retransmissions = 0;
    auto lastSendTime = std::chrono::steady_clock::now();
    auto overallStart = std::chrono::steady_clock::now();
    
    ssize_t sent = sendto(sockfd, authMsg.data(), authMsg.size(), 0,
                        reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
    if (sent < 0) {
        perror("sendto AUTH failed");
        close(epoll_fd);
        close(sockfd);
        return EXIT_FAILURE;
    }
    std::cout << "Sent AUTH message to server" << std::endl;
    ctx.state = ClientState::AUTHENTICATING;
    
    // Event loop
    char buffer[65536]; // Large buffer for UDP messages
    epoll_event events[10];
    std::string stdinBuffer;
    bool running = true;
    
    while (running) {
        // Handle Ctrl+C
        if (terminationRequested) {
            std::cout << "Termination requested, sending BYE." << std::endl;
            uint16_t byeMsgId = ctx.getNextMsgId();
            std::vector<char> byeMsg = buildUdpByeMessage(byeMsgId, ctx.displayName);
            sendto(sockfd, byeMsg.data(), byeMsg.size(), 0,
                   reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
            break;
        }
        
        // Special handling for AUTH state
        if (ctx.state == ClientState::AUTHENTICATING && !authReplyReceived) {
            auto now = std::chrono::steady_clock::now();
            auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSendTime).count();
            auto overallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - overallStart).count();
            
            // Check for AUTH timeout (5 seconds)
            if (overallElapsed >= 5000) {
                std::cerr << "ERROR: Authentication response timeout (5 seconds)." << std::endl;
                close(epoll_fd);
                close(sockfd);
                return EXIT_FAILURE;
            }
            
            // Handle AUTH retransmission if needed
            if (!authConfirmReceived && elapsedMs >= timeoutMs) {
                if (retransmissions < maxRetransmissions) {
                    std::cout << "No CONFIRM received, retransmitting AUTH (attempt " << retransmissions + 1 << ")" << std::endl;
                    sendto(sockfd, authMsg.data(), authMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
                    lastSendTime = now;
                    retransmissions++;
                } else {
                    std::cerr << "ERROR: Maximum AUTH retransmissions reached" << std::endl;
                    close(epoll_fd);
                    close(sockfd);
                    return EXIT_FAILURE;
                }
            }
        }
        
        // Wait for events with a short timeout
        int nfds = epoll_wait(epoll_fd, events, 10, 100); // 100ms timeout
        if (nfds == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait failed");
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            // Handle socket events
            if (events[i].data.fd == sockfd) {
                sockaddr_in peerAddr;
                socklen_t peerLen = sizeof(peerAddr);
                ssize_t bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                                         reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
                if (bytes < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recvfrom failed");
                    }
                    continue;
                }
                
                // Update server address if different port
                checkAndUpdateServerPort(ctx.serverAddr, peerAddr);
                
                // Parse the UDP message
                ParsedMessage msg = parseUdpMessage(buffer, bytes);
                
                // If it's a CONFIRM message, handle it specially
                if (msg.type == MessageType::CONFIRM) {
                    // For AUTH handling
                    if (ctx.state == ClientState::AUTHENTICATING && msg.refMsgId == authMsgId) {
                        printf_debug("Received CONFIRM for AUTH message");
                        authConfirmReceived = true;
                    }
                    continue; // Skip normal message processing
                }
                
                // For non-CONFIRM messages, we need to send a CONFIRM
                if (msg.type != MessageType::UNKNOWN) {
                    std::vector<char> confirmMsg = buildConfirmMessage(msg.msgId);
                    sendto(sockfd, confirmMsg.data(), confirmMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
                    
                    // Track the message as seen
                    ctx.seenMsgIds.insert(msg.msgId);
                }
                
                // Special handling for AUTH reply
                if (ctx.state == ClientState::AUTHENTICATING && msg.type == MessageType::REPLY && msg.refMsgId == authMsgId) {
                    printf_debug("Received REPLY for AUTH message");
                    authReplyReceived = true;
                    // Handle the AUTH reply
                    handleIncomingMessage(msg, ctx, sockfd);
                    continue;
                }
                
                // Handle other messages
                if (msg.type != MessageType::UNKNOWN) {
                    handleIncomingMessage(msg, ctx, sockfd);
                    if (msg.type == MessageType::BYE || msg.type == MessageType::ERR) {
                        running = false;
                        break;
                    }
                }
            }
            // Handle stdin events
            else if (events[i].data.fd == STDIN_FILENO) {
                char buf[1024];
                ssize_t bytes = read(STDIN_FILENO, buf, sizeof(buf));
                if (bytes > 0) {
                    stdinBuffer.append(buf, bytes);
                    size_t pos;
                    while ((pos = stdinBuffer.find('\n')) != std::string::npos) {
                        std::string line = stdinBuffer.substr(0, pos);
                        stdinBuffer.erase(0, pos + 1);
                        
                        // Process user commands or messages
                        if (line.empty()) continue;
                        
                        if (line[0] == '/') { // Command
                            std::istringstream iss(line.substr(1));
                            std::string cmd;
                            iss >> cmd;
                            
                            if (cmd == "join" && ctx.state == ClientState::JOINED) {
                                std::string channelId;
                                iss >> channelId;
                                if (!channelId.empty()) {
                                    ctx.channelID = channelId;
                                    uint16_t joinMsgId = ctx.getNextMsgId();
                                    std::vector<char> joinMsg = buildUdpJoinMessage(joinMsgId, channelId, ctx.displayName);
                                    
                                    // Send JOIN message
                                    sendto(sockfd, joinMsg.data(), joinMsg.size(), 0,
                                           reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
                                    
                                    ctx.state = ClientState::JOIN_WAITING;
                                    std::cout << "Sent JOIN request for channel: " << channelId << std::endl;
                                } else {
                                    std::cout << "Error: Channel name cannot be empty\n";
                                    std::cout << "Usage: /join <channel>\n";
                                }
                            }
                            else if (cmd == "bye") {
                                // Send BYE message
                                uint16_t byeMsgId = ctx.getNextMsgId();
                                std::vector<char> byeMsg = buildUdpByeMessage(byeMsgId, ctx.displayName);
                                sendto(sockfd, byeMsg.data(), byeMsg.size(), 0,
                                       reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
                                std::cout << "Sent BYE message, terminating connection." << std::endl;
                                running = false;
                                break;
                            }
                            else if (cmd == "rename") {
                                std::string newDisplayName;
                                iss >> newDisplayName;
                                if (!newDisplayName.empty()) {
                                    ctx.displayName = newDisplayName;
                                    std::cout << "Display name updated to: " << newDisplayName << std::endl;
                                } else {
                                    std::cout << "Usage: /rename <displayName>\n";
                                }
                            }
                            else if (cmd == "help") {
                                std::cout << "Available commands:\n";
                                std::cout << "  /join <channel>       - Join a channel\n";
                                std::cout << "  /rename <displayName> - Change display name locally\n";
                                std::cout << "  /bye                  - Disconnect from server\n";
                                std::cout << "  /help                 - Show this help\n";
                            }
                            else {
                                std::cout << "Unknown command. Type /help for available commands.\n";
                            }
                        }
                        else if (ctx.state == ClientState::JOINED) {
                            // Send chat message
                            const size_t MAX_MSG_LEN = 60000;
                            if (line.size() > MAX_MSG_LEN) {
                                std::cout << "Message truncated to " << MAX_MSG_LEN << " characters.\n";
                                line = line.substr(0, MAX_MSG_LEN);
                            }
                            
                            uint16_t msgId = ctx.getNextMsgId();
                            std::vector<char> msgData = buildUdpMsgMessage(msgId, ctx.displayName, line);
                            sendto(sockfd, msgData.data(), msgData.size(), 0,
                                   reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
                        }
                        else {
                            std::cout << "You must join a channel before sending messages.\n";
                            std::cout << "Use /join <channel> to join a channel.\n";
                        }
                    }
                }
                else if (bytes == 0) {
                    // EOF on stdin, exit gracefully
                    uint16_t byeMsgId = ctx.getNextMsgId();
                    std::vector<char> byeMsg = buildUdpByeMessage(byeMsgId, ctx.displayName);
                    sendto(sockfd, byeMsg.data(), byeMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&ctx.serverAddr), sizeof(ctx.serverAddr));
                    running = false;
                    break;
                }
            }
        }
    }
    
    close(epoll_fd);
    close(sockfd);
    return EXIT_SUCCESS;
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
    ctx.isUdp = false;
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

    ctx.socketFd = sockfd;

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