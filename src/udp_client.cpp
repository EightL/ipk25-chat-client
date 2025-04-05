#include "udp_client.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <chrono>
#include <signal.h>

// External signal handler variable declared in main.cpp
extern volatile sig_atomic_t terminationRequested;

UdpClient::UdpClient(const std::string& serverIp, int port, uint16_t timeout, uint8_t retransmissions) 
    : Client(true), serverAddress(serverIp), serverPort(port), 
      timeoutMs(timeout), maxRetransmissions(retransmissions) {
}

UdpClient::~UdpClient() {
    // Base destructor handles socket cleanup
}

uint16_t UdpClient::getNextMsgId() {
    return nextMsgId++;
}

void UdpClient::checkAndUpdateServerPort(const sockaddr_in& peerAddr) {
    uint16_t currentServerPort = ntohs(serverAddr.sin_port);
    uint16_t incomingPort = ntohs(peerAddr.sin_port);
    
    if (currentServerPort != incomingPort) {
        std::cout << "Server changed ports: " << currentServerPort << " -> " 
                 << incomingPort << ". Updating connection." << std::endl;
        serverAddr.sin_port = htons(incomingPort);
    }
}

bool UdpClient::sendUdpMessage(const std::vector<char>& msg, bool requireConfirm) {
    if (!requireConfirm) {
        // Just send the message once without waiting for confirmation
        sendto(socketFd, msg.data(), msg.size(), 0,
               reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
        return true;
    }
    
    // With retransmissions
    int attempts = 0;
    bool confirmed = false;
    uint16_t msgId = 0;
    
    // Extract message ID from binary message
    if (msg.size() >= 3) {
        memcpy(&msgId, &msg[1], 2);
        msgId = ntohs(msgId); 
    }
    
    auto startTime = std::chrono::steady_clock::now();
    auto lastSendTime = startTime;
    
    // Initial send
    sendto(socketFd, msg.data(), msg.size(), 0,
           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    
    while (!confirmed && attempts < maxRetransmissions) {
        char buffer[1024];
        sockaddr_in peerAddr;
        socklen_t peerLen = sizeof(peerAddr);
        
        // Wait for response with timeout
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(socketFd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = timeoutMs * 1000;
        
        int ready = select(socketFd + 1, &readfds, NULL, NULL, &tv);
        
        if (ready > 0) {
            ssize_t bytes = recvfrom(socketFd, buffer, sizeof(buffer), 0,
                                     reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
            if (bytes > 0) {
                // Update server port if needed
                checkAndUpdateServerPort(peerAddr);
                
                // Parse message
                ParsedMessage response = parseUdpMessage(buffer, bytes);
                
                // Check if it's a CONFIRM for our message
                if (response.type == MessageType::CONFIRM && response.refMsgId == msgId) {
                    confirmed = true;
                    break;
                } 
                else if (response.type != MessageType::UNKNOWN) {
                    // Confirm other messages from server
                    std::vector<char> confirmMsg = buildConfirmMessage(response.msgId);
                    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                    
                    // Process the received message
                    handleIncomingMessage(response);
                }
            }
        } else {
            // Timeout - retransmit
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSendTime).count();
            
            if (elapsed >= timeoutMs) {
                sendto(socketFd, msg.data(), msg.size(), 0,
                       reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                lastSendTime = now;
                attempts++;
            }
        }
        
        // Check overall timeout (5 seconds)
        auto now = std::chrono::steady_clock::now();
        auto overallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
        if (overallElapsed >= 5000) {
            std::cout << "Message transmission timeout (5 seconds)" << std::endl;
            return false;
        }
    }
    
    return confirmed;
}

bool UdpClient::authenticateWithRetries(const std::string& secret) {
    // Send AUTH message
    uint16_t authMsgId = getNextMsgId();
    std::vector<char> authMsg = buildUdpAuthMessage(authMsgId, username, displayName, secret);
    
    bool success = sendUdpMessage(authMsg, true);
    if (!success) {
        std::cerr << "Authentication failed: couldn't get confirmation" << std::endl;
        return false;
    }
    
    // Wait for REPLY message
    auto startTime = std::chrono::steady_clock::now();
    bool authReplyReceived = false;
    
    while (!authReplyReceived) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
        
        if (elapsed >= 5000) {
            std::cerr << "Authentication failed: no REPLY received within 5 seconds" << std::endl;
            return false;
        }
        
        char buffer[1024];
        sockaddr_in peerAddr;
        socklen_t peerLen = sizeof(peerAddr);
        
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(socketFd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms
        
        int ready = select(socketFd + 1, &readfds, NULL, NULL, &tv);
        
        if (ready > 0) {
            ssize_t bytes = recvfrom(socketFd, buffer, sizeof(buffer), 0,
                                     reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
            if (bytes > 0) {
                // Update server port if needed
                checkAndUpdateServerPort(peerAddr);
                
                // Parse message
                ParsedMessage response = parseUdpMessage(buffer, bytes);
                
                // Always send CONFIRM for any server message
                if (response.type != MessageType::UNKNOWN && response.type != MessageType::CONFIRM) {
                    std::vector<char> confirmMsg = buildConfirmMessage(response.msgId);
                    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                }
                
                // Check if it's a REPLY for our AUTH message
                if (response.type == MessageType::REPLY && response.refMsgId == authMsgId) {
                    handleIncomingMessage(response);
                    if (state == ClientState::JOINED) {
                        return true; // Authentication successful
                    } else {
                        return false; // Authentication failed
                    }
                }
                else {
                    // Process other messages
                    handleIncomingMessage(response);
                }
            }
        }
    }
    
    return false;
}

void UdpClient::processUserInput(const std::string& input) {
    if (input.empty()) return;
    
    if (input[0] == '/') { // Command
        std::istringstream iss(input.substr(1));
        std::string cmd;
        iss >> cmd;
        
        if (cmd == "join" && state == ClientState::JOINED) {
            std::string channelId;
            iss >> channelId;
            if (!channelId.empty()) {
                channelID = channelId;
                uint16_t joinMsgId = getNextMsgId();
                std::vector<char> joinMsg = buildUdpJoinMessage(joinMsgId, channelId, displayName);
                
                // Send JOIN message
                if (sendUdpMessage(joinMsg)) {
                    state = ClientState::JOIN_WAITING;
                    std::cout << "Sent JOIN request for channel: " << channelId << std::endl;
                } else {
                    std::cout << "Failed to send JOIN request." << std::endl;
                }
            } else {
                std::cout << "Error: Channel name cannot be empty\n";
                std::cout << "Usage: /join <channel>\n";
            }
        }
        else if (cmd == "bye") {
            // Send BYE message
            uint16_t byeMsgId = getNextMsgId();
            std::vector<char> byeMsg = buildUdpByeMessage(byeMsgId, displayName);
            sendto(socketFd, byeMsg.data(), byeMsg.size(), 0,
                   reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
            std::cout << "Sent BYE message, terminating connection." << std::endl;
            state = ClientState::TERMINATED;
        }
        else if (cmd == "rename") {
            std::string newDisplayName;
            iss >> newDisplayName;
            if (!newDisplayName.empty()) {
                displayName = newDisplayName;
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
    else if (state == ClientState::JOINED) {
        // Send chat message
        const size_t MAX_MSG_LEN = 60000;
        std::string line = input;
        if (line.size() > MAX_MSG_LEN) {
            std::cout << "Message truncated to " << MAX_MSG_LEN << " characters.\n";
            line = line.substr(0, MAX_MSG_LEN);
        }
        
        uint16_t msgId = getNextMsgId();
        std::vector<char> msgData = buildUdpMsgMessage(msgId, displayName, line);
        if (!sendUdpMessage(msgData)) {
            std::cout << "Failed to send message." << std::endl;
        }
    }
    else {
        std::cout << "You must join a channel before sending messages.\n";
        std::cout << "Use /join <channel> to join a channel.\n";
    }
}

void UdpClient::handleIncomingMessage(const ParsedMessage& msg) {
    // Use base class implementation
    Client::handleIncomingMessage(msg);
}

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

int UdpClient::run() {
    // Resolve hostname to IP if needed
    std::string resolvedIP = resolveHostname(serverAddress);
    std::string serverIP = resolvedIP.empty() ? serverAddress : resolvedIP;
    
    // Create UDP socket
    socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        perror("socket creation failed");
        return EXIT_FAILURE;
    }
    
    setNonBlocking(socketFd);
    
    // Bind to any available port
    sockaddr_in localAddr;
    std::memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(0);
    if (bind(socketFd, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr)) < 0) {
        perror("bind failed");
        close(socketFd);
        return EXIT_FAILURE;
    }
    
    // Set up server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid server address: " << serverIP << std::endl;
        close(socketFd);
        return EXIT_FAILURE;
    }
    
    // Set up epoll for I/O multiplexing
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create");
        close(socketFd);
        return EXIT_FAILURE;
    }
    
    // Add socket to epoll
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = socketFd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socketFd, &ev) < 0) {
        perror("epoll_ctl: sockfd");
        close(epoll_fd);
        close(socketFd);
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
        close(socketFd);
        return EXIT_FAILURE;
    }
    
    // Authenticate with server
    std::string secret = "33df184d-207f-42a9-b331-7ecebde96416"; // Hardcoded for testing
    state = ClientState::AUTHENTICATING;
    if (!authenticateWithRetries(secret)) {
        std::cerr << "Authentication failed." << std::endl;
        close(epoll_fd);
        close(socketFd);
        return EXIT_FAILURE;
    }
    
    // Main event loop
    char buffer[65536]; // Large buffer for UDP messages
    epoll_event events[10];
    std::string stdinBuffer;
    bool running = true;
    
    while (running && state != ClientState::TERMINATED) {
        // Handle Ctrl+C
        if (terminationRequested) {
            std::cout << "Termination requested, sending BYE." << std::endl;
            uint16_t byeMsgId = getNextMsgId();
            std::vector<char> byeMsg = buildUdpByeMessage(byeMsgId, displayName);
            sendto(socketFd, byeMsg.data(), byeMsg.size(), 0,
                   reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
            break;
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
            if (events[i].data.fd == socketFd) {
                sockaddr_in peerAddr;
                socklen_t peerLen = sizeof(peerAddr);
                ssize_t bytes = recvfrom(socketFd, buffer, sizeof(buffer), 0, 
                                         reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
                if (bytes < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recvfrom failed");
                    }
                    continue;
                }
                
                // Update server address if different port
                checkAndUpdateServerPort(peerAddr);
                
                // Parse the UDP message
                ParsedMessage msg = parseUdpMessage(buffer, bytes);
                
                // If it's a CONFIRM message, handle it specially
                if (msg.type == MessageType::CONFIRM) {
                    continue; // Skip normal message processing for CONFIRM messages
                }
                
                // For non-CONFIRM messages, we need to send a CONFIRM
                if (msg.type != MessageType::UNKNOWN) {
                    std::vector<char> confirmMsg = buildConfirmMessage(msg.msgId);
                    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                    
                    // Track the message as seen
                    seenMsgIds.insert(msg.msgId);
                    
                    // Handle the message
                    handleIncomingMessage(msg);
                    
                    if (state == ClientState::TERMINATED) {
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
                        
                        // Process user input
                        processUserInput(line);
                        
                        if (state == ClientState::TERMINATED) {
                            running = false;
                            break;
                        }
                    }
                }
                else if (bytes == 0) {
                    // EOF on stdin, exit gracefully
                    uint16_t byeMsgId = getNextMsgId();
                    std::vector<char> byeMsg = buildUdpByeMessage(byeMsgId, displayName);
                    sendto(socketFd, byeMsg.data(), byeMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                    running = false;
                    break;
                }
            }
        }
    }
    
    close(epoll_fd);
    return EXIT_SUCCESS;
}