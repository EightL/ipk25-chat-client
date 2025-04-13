/**
 * @file client.cpp
 * @brief Implementation of the base Client class for the IPK25-CHAT protocol
 *
 * This file implements the core functionality shared by both TCP and UDP clients,
 * including user input processing, message validation, and state management.
 *
 * @author xsevcim00
 */

 #include "client.h"
 #include <fcntl.h>
 #include <iostream>
 #include <unistd.h>
 #include <cstring>
 #include <arpa/inet.h>
 #include <string>
 #include <vector>
 #include <netdb.h>
 #include "debug.h"
 
 // Initialize the client with the specified protocol type
 Client::Client(bool isUdpClient) : isUdp(isUdpClient) {
     state = ClientState::INIT;
 }
 
 // Clean up socket resources if necessary
 Client::~Client() {
     if (socketFd != -1) {
         close(socketFd);
         socketFd = -1;
     }
 }
 
 // Set file descriptor to non-blocking mode for epoll usage
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
 
 // Resolve hostname to list of IP addresses using the appropriate socket type
 std::vector<std::string> Client::resolveHostname(const std::string& hostname, bool isTcp, int port) {
     struct addrinfo hints, *result, *rp;
     std::vector<std::string> addresses;
     
     // Set up hints structure based on protocol
     memset(&hints, 0, sizeof(hints));
     hints.ai_family = AF_INET;     // IPv4 only (as per specification)
     hints.ai_socktype = isTcp ? SOCK_STREAM : SOCK_DGRAM;
     hints.ai_flags = AI_ADDRCONFIG;
     
     // Convert port to string if provided
     std::string port_str = (port > 0) ? std::to_string(port) : "";
     const char* port_cstr = port_str.empty() ? NULL : port_str.c_str();
     
     // Perform the actual hostname resolution
     int status = getaddrinfo(hostname.c_str(), port_cstr, &hints, &result);
     if (status != 0) {
         std::cerr << "Failed to resolve hostname: " << gai_strerror(status) << std::endl;
         return addresses;
     }
     
     // Extract all resolved IP addresses and add to result vector
     for (rp = result; rp != NULL; rp = rp->ai_next) {
         char ipstr[INET_ADDRSTRLEN];
         struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(rp->ai_addr);
         inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
         addresses.push_back(std::string(ipstr));
     }
     
     freeaddrinfo(result);
     return addresses;
 }
 
 // Check if incoming message type is valid for current client state
 bool Client::isValidTransition(MessageType msgType) {
     switch (state) {
         case ClientState::INIT:
             // No incoming messages expected in initial state
             return false;
             
         case ClientState::AUTHENTICATING:
             // After AUTH, expect REPLY, ERR, or BYE
             return (msgType == MessageType::REPLY ||
                     msgType == MessageType::ERR   ||
                     msgType == MessageType::BYE);
         
         case ClientState::JOINED:
             // In "open" state, can receive MSG, REPLY, ERR, or BYE
             return (msgType == MessageType::MSG   ||
                     msgType == MessageType::REPLY ||
                     msgType == MessageType::ERR   ||
                     msgType == MessageType::BYE);
 
         case ClientState::JOIN_WAITING:
             // In "join" state, expect REPLY, MSG, ERR, or BYE
             return (msgType == MessageType::MSG   ||
                     msgType == MessageType::REPLY ||
                     msgType == MessageType::ERR   ||
                     msgType == MessageType::BYE);
 
         case ClientState::TERMINATED:
             // No messages are valid after termination
             return false;
     }
     return false;
 }
 
 // Helper function to validate username according to protocol rules
 bool isValidUsername(const std::string& username) {
     if (username.length() > 20) return false;
     
     // Check for allowed characters [a-zA-Z0-9_-]
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
 
 // Helper function to validate channel ID according to protocol rules
 bool isValidChannelID(const std::string& channelID) {
     if (channelID.length() > 20) return false;
     
     // Special case for Discord integration - period allowed in "discord.channelname"
     if (channelID.find("discord.") == 0) {
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
 
 // Helper function to validate secret according to protocol rules
 bool isValidSecret(const std::string& secret) {
     if (secret.length() > 128) return false;
     
     // Same character set constraints as username
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
 
 // Helper function to validate display name according to protocol rules
 bool isValidDisplayName(const std::string& displayName) {
     if (displayName.length() > 20) return false;
     
     // Check for printable ASCII characters (0x21-7E)
     for (char c : displayName) {
         if (c < 0x21 || c > 0x7E) {
             return false;
         }
     }
     return true;
 }
 
 // Helper function to validate message content according to protocol rules
 bool isValidMessageContent(const std::string& messageContent) {
     // Allow printable chars, space, and line feed (0x20-7E, 0x0A)
     for (char c : messageContent) {
         if (!((c >= 0x20 && c <= 0x7E) || c == 0x0A)) {
             return false;
         }
     }
     return true;
 }
 
 // Process user commands and chat messages
 void Client::processUserInput(const std::string& input) {
     if (input.empty()) return;
     
     // Handle command (starts with '/')
     if (input[0] == '/') {
         std::istringstream iss(input.substr(1));
         std::string cmd;
         iss >> cmd;
         
         if (cmd == "auth") {
             // Prevent re-authentication if already authenticated
             if (state == ClientState::JOINED || state == ClientState::JOIN_WAITING) {
                 std::cout << "ERROR: Already authenticated. Start a new client instance to authenticate with different credentials." << std::endl;
                 return;
             }
             
             // Parse authentication parameters
             std::string newUsername, newSecret, newDisplayName;
             iss >> newUsername >> newSecret >> newDisplayName;
             
             if (newUsername.empty() || newSecret.empty() || newDisplayName.empty()) {
                 std::cout << "ERROR: Invalid authentication parameters" << std::endl;
                 std::cerr << "Usage: /auth <username> <secret> <displayName>" << std::endl;
                 return;
             }
             
             // Validate all authentication parameters
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
             
             // Set credentials and attempt authentication
             username = newUsername;
             displayName = newDisplayName;
             
             state = ClientState::AUTHENTICATING;
             if (!authenticate(newSecret)) {
                 state = ClientState::INIT;
             }
         }
         else if (cmd == "join" && state == ClientState::JOINED) {
             // Handle join command
             std::string channelId;
             iss >> channelId;
             
             if (channelId.empty()) {
                 std::cout << "ERROR: Channel name cannot be empty" << std::endl;
                 std::cerr << "Usage: /join <channel>" << std::endl;
                 return;
             }
             
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
             // Handle rename command
             std::string newDisplayName;
             iss >> newDisplayName;
             if (newDisplayName.empty()) {
                 std::cerr << "Usage: /rename <displayName>" << std::endl;
                 return;
             }
             
             if (!isValidDisplayName(newDisplayName)) {
                 std::cout << "ERROR: Invalid display name. Must be max 20 characters and contain only printable ASCII characters" << std::endl;
                 return;
             }
             
             displayName = newDisplayName;
             std::cerr << "Display name updated to: " << newDisplayName << std::endl;
         }
         else if (cmd == "bye") {
             // Handle bye command
             sendByeMessage();
         }
         else if (cmd == "help") {
             // Show help message
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
     // Handle normal chat message (when in JOINED state)
     else if (state == ClientState::JOINED) {
         const size_t MAX_MSG_LEN = 60000;
         std::string message = input;
         
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
 
 // Process incoming messages and update client state
 void Client::handleIncomingMessage(const ParsedMessage& msg) {
     switch (msg.type) {
         case MessageType::REPLY:
             // Handle replies based on current state
             if (state == ClientState::JOIN_WAITING) {
                 state = ClientState::JOINED;
                 if (msg.success) {
                     std::cout << "Action Success: " << msg.param2 << "\n";
                 } else {
                     std::cout << "Action Failure: " << msg.param2 << "\n";
                 }
             } else if (state == ClientState::AUTHENTICATING) {
                 if (msg.success) {
                     std::cout << "Action Success: " << msg.param2 << "\n";
                     state = ClientState::JOINED;
                 } else {
                     std::cout << "Action Failure: " << msg.param2 << "\n";
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
             // Display chat message
             std::cout << msg.param1 << ": " << msg.param2 << "\n";
             break;
 
         case MessageType::ERR:
             // Display error and terminate
             std::cout << "ERROR FROM " << msg.param1 << ": " << msg.param2 << "\n";
             printf_debug("[DEBUG-TERM] Setting state to TERMINATED due to ERR message");
             state = ClientState::TERMINATED;
             printf_debug("[DEBUG-TERM] State is now %d (TERMINATED=4)", (int)state);
             break;
 
         case MessageType::BYE:
             // Handle server termination
             std::cerr << "Connection terminated by server.\n";
             state = ClientState::TERMINATED;
             break;
 
         case MessageType::PING:
             // Ignore PING messages
             break;
 
         default:
             // Handle malformed messages
             std::cout << "ERROR: Received malformed or invalid message from server.\n";
             state = ClientState::TERMINATED;
             break;
     }
 }
 
 // Set client identity parameters
 void Client::setIdentity(const std::string& user, const std::string& display) {
     username = user;
     displayName = display;
 }