#include "client.h"
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <netdb.h>

Client::Client(bool isUdpClient) : isUdp(isUdpClient) {
    // Initialize in INIT state
    state = ClientState::INIT;
}

Client::~Client() {
    // Close socket if open
    if (socketFd != -1) {
        close(socketFd);
        socketFd = -1;
    }
}

void Client::setNonBlocking(int fd) {
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

std::vector<std::string> Client::resolveHostname(const std::string& hostname, bool isTcp, int port) {
    struct addrinfo hints, *result, *rp;
    std::vector<std::string> addresses;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;     // IPv4 only (as per specification)
    hints.ai_socktype = isTcp ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_flags = AI_ADDRCONFIG;
    
    // Convert port to string if provided
    std::string port_str = (port > 0) ? std::to_string(port) : "";
    const char* port_cstr = port_str.empty() ? NULL : port_str.c_str();
    
    int status = getaddrinfo(hostname.c_str(), port_cstr, &hints, &result);
    if (status != 0) {
        std::cerr << "Failed to resolve hostname: " << gai_strerror(status) << std::endl;
        return addresses;
    }
    
    // Extract all resolved IP addresses
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char ipstr[INET_ADDRSTRLEN];
        struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(rp->ai_addr);
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
        addresses.push_back(std::string(ipstr));
    }
    
    freeaddrinfo(result);
    return addresses;
}

bool Client::isValidTransition(MessageType msgType) {
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

// Validation functions
bool isValidUsername(const std::string& username) {
    if (username.length() > 20) return false;
    
    // Check if username contains only allowed characters [a-zA-Z0-9_-]
    for (char c : username) {
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || 
              c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

bool isValidChannelID(const std::string& channelID) {
    if (channelID.length() > 20) return false;
    
    // Special case for Discord integration - allow period in "discord.channelname" format
    if (channelID.find("discord.") == 0) {
        // Check each character after "discord." prefix
        for (size_t i = 8; i < channelID.length(); i++) {
            char c = channelID[i];
            if (!((c >= 'a' && c <= 'z') || 
                  (c >= 'A' && c <= 'Z') || 
                  (c >= '0' && c <= '9') || 
                  c == '_' || c == '-')) {
                return false;
            }
        }
        return true;
    }
    
    // Standard case - only allow [a-zA-Z0-9_-]
    for (char c : channelID) {
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || 
              c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

bool isValidSecret(const std::string& secret) {
    if (secret.length() > 128) return false;
    
    // Secret has the same character set constraints as username
    for (char c : secret) {
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || 
              c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

bool isValidDisplayName(const std::string& displayName) {
    if (displayName.length() > 20) return false;
    
    // Check if displayName contains only printable characters (0x21-7E)
    for (char c : displayName) {
        if (c < 0x21 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

bool isValidMessageContent(const std::string& messageContent) {
    // Check if message contains only allowed characters: printable chars, space, and line feed
    for (char c : messageContent) {
        if (!((c >= 0x20 && c <= 0x7E) || c == 0x0A)) {
            return false;
        }
    }
    return true;
}

void Client::processUserInput(const std::string& input) {
    if (input.empty()) return;
    
    if (input[0] == '/') { // Command
        std::istringstream iss(input.substr(1));
        std::string cmd;
        iss >> cmd;
        
        if (cmd == "auth") {
            // Prevent re-authentication if already in authenticated state
            if (state == ClientState::JOINED || state == ClientState::JOIN_WAITING) {
                std::cout << "ERROR: Already authenticated. Start a new client instance to authenticate with different credentials." << std::endl;
                return;
            }
            
            std::string newUsername, newSecret, newDisplayName;
            iss >> newUsername >> newSecret >> newDisplayName;
            
            if (newUsername.empty() || newSecret.empty() || newDisplayName.empty()) {
                std::cout << "ERROR: Invalid authentication parameters" << std::endl;
                std::cerr << "Usage: /auth <username> <secret> <displayName>" << std::endl;
                return;
            }
            
            // Validate parameters
            if (!isValidUsername(newUsername)) {
                std::cout << "ERROR: Invalid username. Must be max 20 characters and contain only [a-zA-Z0-9_-]" << std::endl;
                return;
            }
            
            if (!isValidSecret(newSecret)) {
                std::cout << "ERROR: Invalid secret. Must be max 128 characters and contain only [a-zA-Z0-9_-]" << std::endl;
                return;
            }
            
            if (!isValidDisplayName(newDisplayName)) {
                std::cout << "ERROR: Invalid display name. Must be max 20 characters and contain only printable ASCII characters" << std::endl;
                return;
            }
            
            username = newUsername;
            displayName = newDisplayName;
            
            // Call protocol-specific authentication
            state = ClientState::AUTHENTICATING;
            if (!authenticate(newSecret)) {
                state = ClientState::INIT;
            }
        }
        else if (cmd == "join" && state == ClientState::JOINED) {
            std::string channelId;
            iss >> channelId;
            
            if (channelId.empty()) {
                std::cout << "ERROR: Channel name cannot be empty" << std::endl;
                std::cerr << "Usage: /join <channel>" << std::endl;
                return;
            }
            
            // Validate channel ID
            if (!isValidChannelID(channelId)) {
                std::cout << "ERROR: Invalid channel ID. Must be max 20 characters and contain only [a-zA-Z0-9_-]" << std::endl;
                return;
            }
            
            channelID = channelId;
            if (joinChannel(channelId)) {
                state = ClientState::JOIN_WAITING;
            } else {
                std::cout << "ERROR: Failed to send join request" << std::endl;
            }
        }
        else if (cmd == "rename") {
            std::string newDisplayName;
            iss >> newDisplayName;
            if (newDisplayName.empty()) {
                std::cerr << "Usage: /rename <displayName>" << std::endl;
                return;
            }
            
            // Validate display name
            if (!isValidDisplayName(newDisplayName)) {
                std::cout << "ERROR: Invalid display name. Must be max 20 characters and contain only printable ASCII characters" << std::endl;
                return;
            }
            
            displayName = newDisplayName;
            std::cerr << "Display name updated to: " << newDisplayName << std::endl;
        }
        else if (cmd == "bye") {
            sendByeMessage();
        }
        else if (cmd == "help") {
            std::cerr << "Available commands:" << std::endl;
            std::cerr << "  /auth <u> <s> <d>     - Authenticate with username, secret and display name" << std::endl;
            std::cerr << "  /join <channel>       - Join a channel" << std::endl;
            std::cerr << "  /rename <displayName> - Change display name locally" << std::endl;
            std::cerr << "  /bye                  - Disconnect from server" << std::endl;
            std::cerr << "  /help                 - Show this help" << std::endl;
        }
        else {
            std::cerr << "Unknown command. Type /help for available commands." << std::endl;
        }
    }
    else if (state == ClientState::JOINED) {
        // Send chat message with protocol-specific implementation
        const size_t MAX_MSG_LEN = 60000;
        std::string message = input;
        
        // Validate message content
        if (!isValidMessageContent(message)) {
            std::cout << "ERROR: Message contains invalid characters. Only printable ASCII, spaces and line feeds allowed." << std::endl;
            return;
        }
        
        if (message.size() > MAX_MSG_LEN) {
            std::cout << "ERROR: Message truncated to " << MAX_MSG_LEN << " characters." << std::endl;
            message = message.substr(0, MAX_MSG_LEN);
        }
        
        sendChatMessage(message);
    }
    else {
        std::cerr << "You must join a channel before sending messages." << std::endl;
        std::cerr << "Use /join <channel> to join a channel." << std::endl;
    }
}

void Client::handleIncomingMessage(const ParsedMessage& msg) {
    switch (msg.type) {
        case MessageType::REPLY:
            if (state == ClientState::JOIN_WAITING) {
                state = ClientState::JOINED;
                if (msg.success) {
                    std::cout << "Action Success: " << msg.param2 << "\n";
                } else {
                    std::cout << "Action Failure: " << msg.param2 << "\n";
                }
            } else if (state == ClientState::AUTHENTICATING) {
                if (msg.success) {
                    std::cout << "Authentication Success: " << msg.param2 << "\n";
                    state = ClientState::JOINED;
                } else {
                    std::cout << "Authentication Failure: " << msg.param2 << "\n";
                }
            } else {
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
            state = ClientState::TERMINATED;
            break;

        case MessageType::BYE:
            std::cout << "Connection terminated by server.\n";
            state = ClientState::TERMINATED;
            
            break;

        case MessageType::PING:
            // Simply ignore PING messages
            break;

        default:
            std::cout << "ERROR: Received malformed or invalid message from server.\n";
            state = ClientState::TERMINATED;
            break;
    }
}