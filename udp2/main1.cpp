#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <vector>
#include <string>
#include <chrono>
#include <errno.h>
#include <netdb.h> // Add this for hostname resolution functions
#include <set>
#include <thread>
#include <atomic>

#define MAX_EVENTS 10

const uint8_t AUTH_TYPE    = 0x02;
const uint8_t CONFIRM_TYPE = 0x00;
const uint8_t REPLY_TYPE   = 0x01;
const uint8_t JOIN_TYPE    = 0x03;
const uint8_t MSG_TYPE     = 0x04;
const uint8_t BYE_TYPE     = 0xFF;

#ifdef DEBUG_PRINT
#define printf_debug(format, ...) fprintf(stderr, "%s:%-4d | %15s | " format "\n", __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define printf_debug(format, ...) (0)
#endif

// Helper function: update server port if dynamic port changed
void checkAndUpdateServerPort(sockaddr_in& serverAddr, const sockaddr_in& peerAddr) {
    uint16_t currentServerPort = ntohs(serverAddr.sin_port);
    uint16_t incomingPort = ntohs(peerAddr.sin_port);
    
    if (currentServerPort != incomingPort) {
        printf_debug("Server changed ports: %d -> %d. Updating connection.", currentServerPort, incomingPort);
        serverAddr.sin_port = htons(incomingPort);
    }
}

// Helper function to resolve hostname to IPv4 address
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

// Helper function to print usage information
void printUsage(const char* progName) {
    std::cout << "Usage: " << progName 
              << " -t {tcp|udp} -s <server_ip> [-p <port>] [-d <timeout_ms>] [-r <retransmissions>] [-h]"
              << std::endl;
}

// Helper function to build the AUTH message
std::vector<char> buildAuthMessage(uint16_t msgId, 
                                   const std::string& username, 
                                   const std::string& displayName, 
                                   const std::string& secret) {
    std::vector<char> message;
    message.push_back(AUTH_TYPE);
    
    uint16_t netMsgId = htons(msgId);
    char* idPtr = reinterpret_cast<char*>(&netMsgId);
    message.push_back(idPtr[0]);
    message.push_back(idPtr[1]);
    
    message.insert(message.end(), username.begin(), username.end());
    message.push_back('\0');
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    message.insert(message.end(), secret.begin(), secret.end());
    message.push_back('\0');
    
    return message;
}

// Helper function to build a MSG (chat) message
std::vector<char> buildMsgMessage(uint16_t msgId, 
                                  const std::string& displayName, 
                                  const std::string& msgContent) {
    std::vector<char> message;
    message.push_back(MSG_TYPE);
    
    uint16_t netMsgId = htons(msgId);
    char* idPtr = reinterpret_cast<char*>(&netMsgId);
    message.push_back(idPtr[0]);
    message.push_back(idPtr[1]);
    
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    message.insert(message.end(), msgContent.begin(), msgContent.end());
    message.push_back('\0');
    
    return message;
}

// Helper function to build a JOIN message
std::vector<char> buildJoinMessage(uint16_t msgId, 
                                   const std::string& channelId, 
                                   const std::string& displayName) {
    std::vector<char> message;
    message.push_back(JOIN_TYPE);
    
    uint16_t netMsgId = htons(msgId);
    char* idPtr = reinterpret_cast<char*>(&netMsgId);
    message.push_back(idPtr[0]);
    message.push_back(idPtr[1]);
    
    message.insert(message.end(), channelId.begin(), channelId.end());
    message.push_back('\0');
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    
    return message;
}

// Helper function to build a CONFIRM message
std::vector<char> buildConfirmMessage(uint16_t refMsgId) {
    std::vector<char> message;
    message.push_back(CONFIRM_TYPE);
    uint16_t netRefMsgId = htons(refMsgId);
    char* idPtr = reinterpret_cast<char*>(&netRefMsgId);
    message.push_back(idPtr[0]);
    message.push_back(idPtr[1]);
    return message;
}

// Helper function to build a BYE message
std::vector<char> buildByeMessage(uint16_t msgId, const std::string& displayName) {
    std::vector<char> message;
    message.push_back(BYE_TYPE);
    uint16_t netMsgId = htons(msgId);
    char* idPtr = reinterpret_cast<char*>(&netMsgId);
    message.push_back(idPtr[0]);
    message.push_back(idPtr[1]);
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    return message;
}

// Set a file descriptor to non-blocking mode.
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

int main(int argc, char* argv[]) {
    std::string transport;
    std::string serverIP;
    uint16_t serverPort = 4567;
    uint16_t timeoutMs = 250;  
    uint8_t maxRetransmissions = 3;

    int opt;
    while ((opt = getopt(argc, argv, "t:s:p:d:r:h")) != -1) {
        switch (opt) {
            case 't': transport = optarg; break;
            case 's': serverIP = optarg; break;
            case 'p': serverPort = static_cast<uint16_t>(std::stoi(optarg)); break;
            case 'd': timeoutMs = static_cast<uint16_t>(std::stoi(optarg)); break;
            case 'r': maxRetransmissions = static_cast<uint8_t>(std::stoi(optarg)); break;
            case 'h': default: printUsage(argv[0]); return 0;
        }
    }
    if (transport.empty() || serverIP.empty()) {
        std::cerr << "Error: Transport (-t) and Server IP (-s) are required." << std::endl;
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }
    if (transport != "udp") {
        std::cerr << "Error: Only UDP variant is implemented." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Arguments:" << std::endl;
    std::cout << "  Transport: " << transport << std::endl;
    std::cout << "  Server IP: " << serverIP << std::endl;
    std::cout << "  Server Port: " << serverPort << std::endl;
    std::cout << "  Timeout (ms): " << timeoutMs << std::endl;
    std::cout << "  Max Retransmissions: " << static_cast<int>(maxRetransmissions) << std::endl;

    // --- UDP Socket Setup and epoll ---
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { std::cerr << "Error creating socket: " << strerror(errno) << std::endl; exit(EXIT_FAILURE); }
    setNonBlocking(sockfd);
    
    sockaddr_in localAddr;
    std::memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(0);
    if (bind(sockfd, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr)) < 0) {
        std::cerr << "Error binding socket: " << strerror(errno) << std::endl; close(sockfd); exit(EXIT_FAILURE);
    }
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(sockfd, reinterpret_cast<sockaddr*>(&localAddr), &addrLen) < 0) {
        std::cerr << "Error getting socket name: " << strerror(errno) << std::endl; close(sockfd); exit(EXIT_FAILURE);
    }
    std::cout << "Socket bound to " << inet_ntoa(localAddr.sin_addr)
              << ":" << ntohs(localAddr.sin_port) << std::endl;
    
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { std::cerr << "Error creating epoll: " << strerror(errno) << std::endl; close(sockfd); exit(EXIT_FAILURE); }
    epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sockfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        std::cerr << "Error adding socket to epoll: " << strerror(errno) << std::endl; close(sockfd); close(epoll_fd); exit(EXIT_FAILURE);
    }
    
    // Add STDIN to epoll
    setNonBlocking(STDIN_FILENO);
    epoll_event ev_stdin;
    ev_stdin.events = EPOLLIN | EPOLLET;
    ev_stdin.data.fd = STDIN_FILENO;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev_stdin) < 0) {
        std::cerr << "Error adding STDIN to epoll: " << strerror(errno) << std::endl; close(sockfd); close(epoll_fd); exit(EXIT_FAILURE);
    }
    std::cout << "UDP socket and STDIN added to epoll." << std::endl;
    
    // --- AUTH Phase ---
    uint16_t messageId = 0;
    std::string userStr = "xsevcim00";
    std::string dispStr = "udpp";
    std::string secret = "33df184d-207f-42a9-b331-7ecebde96416";
    
    std::string resolvedIP = resolveHostname(serverIP);
    if (resolvedIP.empty()) {
        std::cerr << "Failed to resolve server IP address." << std::endl; close(sockfd); close(epoll_fd); exit(EXIT_FAILURE);
    }
    serverIP = resolvedIP; // Use resolved IP for sending AUTH message

    std::vector<char> authMessage = buildAuthMessage(messageId, userStr, dispStr, secret);
    sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);

    std::cout << "Sending AUTH message to " << inet_ntoa(serverAddr.sin_addr) 
              << ":" << ntohs(serverAddr.sin_port) << std::endl;

    if (inet_aton(serverIP.c_str(), &serverAddr.sin_addr) == 0) {
        std::cerr << "Invalid server IP address: " << serverIP << std::endl; close(sockfd); close(epoll_fd); exit(EXIT_FAILURE);
    }
    
    auto sendAuth = [&]() -> bool {
        ssize_t sentBytes = sendto(sockfd, authMessage.data(), authMessage.size(), 0,
                                   reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
        if (sentBytes < 0) {
            std::cerr << "Error sending AUTH message: " << strerror(errno) << std::endl;
            return false;
        }
        std::cout << "Sent AUTH message (" << sentBytes << " bytes) to " 
                  << serverIP << ":" << serverPort << std::endl;
        return true;
    };
    
    auto overallStart = std::chrono::steady_clock::now();
    if (!sendAuth()) { close(sockfd); close(epoll_fd); exit(EXIT_FAILURE); }
    
    auto lastSendTime = std::chrono::steady_clock::now();
    int retransmissions = 0;
    bool confirmReceived = false;
    bool replyReceived = false;
    epoll_event events[MAX_EVENTS];
    
    while (!replyReceived) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        if (n < 0) { std::cerr << "Error in epoll_wait: " << strerror(errno) << std::endl; break; }
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == sockfd) {
                char buffer[1024];
                sockaddr_in peerAddr;
                socklen_t peerLen = sizeof(peerAddr);
                ssize_t bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                          reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
                if (bytes >= 3) {
                    uint8_t msgType = buffer[0];
                    if (msgType == CONFIRM_TYPE) { // CONFIRM
                        uint16_t confirmMsgId;
                        std::memcpy(&confirmMsgId, &buffer[1], 2);
                        confirmMsgId = ntohs(confirmMsgId);
                        if (confirmMsgId == messageId) {
                            if (!confirmReceived) {
                                std::cout << "Received CONFIRM for AUTH message (MessageID " 
                                          << messageId << ")" << std::endl;
                                confirmReceived = true;
                            }
                        }
                    } else if (msgType == REPLY_TYPE) { // REPLY
                        std::cout << "Processing REPLY message (" << bytes << " bytes)" << std::endl;
                        if (bytes >= 6) {
                            uint16_t msgId, refMsgId;
                            std::memcpy(&msgId, &buffer[1], 2);
                            msgId = ntohs(msgId);
                            uint8_t result = buffer[3];
                            std::memcpy(&refMsgId, &buffer[4], 2);
                            refMsgId = ntohs(refMsgId);
                            std::cout << "REPLY details: MsgID=" << msgId << ", Result=" << (int)result 
                                      << ", RefMsgID=" << refMsgId << std::endl;
                            
                            if (refMsgId == messageId) {
                                uint16_t dynamicPort = ntohs(peerAddr.sin_port);
                                serverAddr.sin_port = htons(dynamicPort);
                                std::cout << "Received REPLY for AUTH message (Ref MsgID " 
                                          << messageId << ") from dynamic port " << dynamicPort << std::endl;
                                std::cout << "Authentication " 
                                          << (result == 1 ? "succeeded" : "failed") << " with message: ";
                                if (bytes > 6) std::cout << &buffer[6];
                                std::cout << std::endl;
                                replyReceived = true;
                                // Send CONFIRM for this REPLY message
                                std::vector<char> confirmMsg = buildConfirmMessage(msgId);
                                sendto(sockfd, confirmMsg.data(), confirmMsg.size(), 0,
                                       reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                                std::cout << "Sent CONFIRM for REPLY message" << std::endl;
                                break;
                            } else {
                                std::cout << "Received REPLY for different message ID: expected=" 
                                          << messageId << ", received=" << refMsgId << std::endl;
                            }
                        } else {
                            std::cout << "REPLY message too short: " << bytes << " bytes" << std::endl;
                        }
                    }
                } else if (bytes == -1 && errno != EAGAIN) {
                    std::cerr << "Error in recvfrom: " << strerror(errno) << std::endl;
                }
            }
        }
        auto now = std::chrono::steady_clock::now();
        auto overallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - overallStart).count();
        if (overallElapsed >= 5000) {
            std::cerr << "REPLY not received within 5000 ms. Terminating." << std::endl;
            break;
        }
        if (!confirmReceived) {
            auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSendTime).count();
            if (elapsedMs >= timeoutMs) {
                if (retransmissions < maxRetransmissions) {
                    std::cout << "No CONFIRM received within " << timeoutMs 
                              << " ms. Retransmitting AUTH message (attempt " 
                              << (retransmissions + 1) << ")..." << std::endl;
                    if (!sendAuth()) break;
                    retransmissions++;
                    lastSendTime = now;
                } else {
                    std::cerr << "Maximum retransmission attempts reached. Terminating." << std::endl;
                    break;
                }
            }
        }
    }
    
    if (!(confirmReceived && replyReceived)) {
        std::cerr << "AUTH process failed." << std::endl;
        close(sockfd);
        close(epoll_fd);
        return EXIT_FAILURE;
    }
    std::cout << "AUTH message successfully confirmed and REPLY received." << std::endl;
    
    // --- JOIN Phase: Join a channel before chatting ---
    messageId++; // Increment message ID for JOIN
    std::string channelId = "default";
    if (channelId != "default") {
        messageId++; // Increment message ID for JOIN
        std::vector<char> joinMessage = buildJoinMessage(messageId, channelId, dispStr);
        std::cout << "Sending JOIN message for channel '" << channelId << "'..." << std::endl;
        ssize_t joinSent = sendto(sockfd, joinMessage.data(), joinMessage.size(), 0,
                                  reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
        if (joinSent < 0) {
            std::cerr << "Error sending JOIN message: " << strerror(errno) << std::endl;
            close(sockfd);
            close(epoll_fd);
            return EXIT_FAILURE;
        }
        
        bool joinReplyReceived = false;
        auto joinStart = std::chrono::steady_clock::now();
        while (!joinReplyReceived) {
            int m = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
            if (m < 0) {
                std::cerr << "Error in epoll_wait during JOIN: " << strerror(errno) << std::endl;
                break;
            }
            for (int i = 0; i < m; ++i) {
                if (events[i].data.fd == sockfd) {
                    char buf[1024];
                    sockaddr_in peer;
                    socklen_t peerLen = sizeof(peer);
                    ssize_t b = recvfrom(sockfd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&peer), &peerLen);
                    if (b >= 6 && buf[0] == REPLY_TYPE) { // REPLY message
                        uint16_t refMsg;
                        std::memcpy(&refMsg, &buf[4], 2);
                        refMsg = ntohs(refMsg);
                        if (refMsg == messageId) {
                            uint8_t result = buf[3];
                            std::cout << "Received REPLY for JOIN message, result: " 
                                      << (result == 1 ? "succeeded" : "failed") << std::endl;
                            joinReplyReceived = true;
                            break;
                        }
                    }
                }
            }
            auto nowJoin = std::chrono::steady_clock::now();
            auto joinElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(nowJoin - joinStart).count();
            if (joinElapsed >= 5000) {
                std::cerr << "JOIN REPLY not received within timeout." << std::endl;
                break;
            }
        }
        if (!joinReplyReceived) {
            std::cerr << "Failed to join channel. Exiting." << std::endl;
            close(sockfd);
            close(epoll_fd);
            return EXIT_FAILURE;
        }
    } else {
        std::cout << "Default channel assumed (server auto-joins). Proceeding to session phase." << std::endl;
    }

    // --- Session Phase: Process network and user input concurrently ---
    std::cout << "You have joined channel '" << channelId << "'. Enter chat messages (type '/quit' to exit):" << std::endl;
    std::string stdinBuffer;
    bool running = true;
    while (running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        if (n < 0) {
            std::cerr << "Error in epoll_wait: " << strerror(errno) << std::endl;
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == sockfd) {
                char buffer[2048];
                sockaddr_in peerAddr;
                socklen_t peerLen = sizeof(peerAddr);
                ssize_t bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                          reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
                if (bytes > 0) {
                    // Debug output to stderr
                    printf_debug("Received packet of %zd bytes, type: 0x%02x from %s:%d",
                                 bytes, (unsigned int)(uint8_t)buffer[0],
                                 inet_ntoa(peerAddr.sin_addr), ntohs(peerAddr.sin_port));
            
                    // Extract message type and MessageID
                    uint8_t msgType = buffer[0];
                    uint16_t recvMsgId;
                    std::memcpy(&recvMsgId, &buffer[1], 2);
                    recvMsgId = ntohs(recvMsgId);
            
                    // Track processed message IDs to avoid duplicates
                    static std::set<uint16_t> processedMsgIDs;
                    if (processedMsgIDs.find(recvMsgId) != processedMsgIDs.end()) {
                        printf_debug("Duplicate message ID %d received. Sending CONFIRM only.", recvMsgId);
                        std::vector<char> confirmMsg = buildConfirmMessage(recvMsgId);
                        sendto(sockfd, confirmMsg.data(), confirmMsg.size(), 0,
                               reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                        continue;
                    }
                    processedMsgIDs.insert(recvMsgId);
            
                    // Always send CONFIRM for non-CONFIRM messages
                    if (msgType != CONFIRM_TYPE) {
                        std::vector<char> confirmMsg = buildConfirmMessage(recvMsgId);
                        ssize_t sent = sendto(sockfd, confirmMsg.data(), confirmMsg.size(), 0,
                                              reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                        if (sent < 0) {
                            std::cerr << "Error sending CONFIRM: " << strerror(errno) << std::endl;
                        }
                    }
            
                    // Process message based on its type
                    if (msgType == MSG_TYPE) {
                        std::string sender, content;
                        int index = 3;
                        while (index < bytes && buffer[index] != '\0') {
                            sender.push_back(buffer[index]);
                            index++;
                        }
                        index++; // Skip null terminator
                        while (index < bytes && buffer[index] != '\0') {
                            content.push_back(buffer[index]);
                            index++;
                        }
                        std::cout << sender << ": " << content << std::endl;
                    }
                    else if (msgType == 0xFD) { // PING
                        printf_debug("PING received. Sending CONFIRM.");
                    }
                    else if (msgType == 0xFE) { // ERR
                        std::cerr << "ERR message received from server." << std::endl;
                        running = false;
                    }
                    else if (msgType == BYE_TYPE) { // BYE
                        std::cout << "BYE message received from server. Connection terminated." << std::endl;
                        running = false;
                    }
                    else {
                        printf_debug("Received packet with unknown type: 0x%02x", (unsigned int)msgType);
                    }
                }
            } else if (fd == STDIN_FILENO) {
                char buf[512];
                ssize_t nbytes = read(STDIN_FILENO, buf, sizeof(buf));
                if (nbytes > 0) {
                    stdinBuffer.append(buf, nbytes);
                    size_t pos;
                    while ((pos = stdinBuffer.find('\n')) != std::string::npos) {
                        std::string line = stdinBuffer.substr(0, pos);
                        stdinBuffer.erase(0, pos + 1);
                        if (line == "/bye") {
                            messageId++;
                            std::vector<char> byeMsg = buildByeMessage(messageId, dispStr);
                            ssize_t sentBytes = sendto(sockfd, byeMsg.data(), byeMsg.size(), 0,
                                                       reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                            if (sentBytes < 0) {
                                std::cerr << "Error sending BYE message: " << strerror(errno) << std::endl;
                            } else {
                                std::cout << "Sent BYE message (" << sentBytes << " bytes). Waiting up to 5s for CONFIRM..." << std::endl;
                            }
                        
                            bool byeConfirmed = false;
                            auto byeStart = std::chrono::steady_clock::now();
                            while (!byeConfirmed) {
                                int m = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
                                if (m < 0) {
                                    std::cerr << "Error in epoll_wait while awaiting BYE confirm: "
                                              << strerror(errno) << std::endl;
                                    break;
                                }
                                for (int i = 0; i < m; ++i) {
                                    if (events[i].data.fd == sockfd) {
                                        char buf[1024];
                                        sockaddr_in peer;
                                        socklen_t peerLen = sizeof(peer);
                                        ssize_t b = recvfrom(sockfd, buf, sizeof(buf), 0,
                                                             reinterpret_cast<sockaddr*>(&peer), &peerLen);
                                        if (b >= 3 && buf[0] == CONFIRM_TYPE) {
                                            uint16_t refId;
                                            std::memcpy(&refId, &buf[1], 2);
                                            refId = ntohs(refId);
                                            if (refId == messageId) {
                                                std::cout << "Received CONFIRM for BYE message. Terminating." << std::endl;
                                                byeConfirmed = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                auto nowBye = std::chrono::steady_clock::now();
                                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(nowBye - byeStart).count();
                                if (elapsed >= 5000) {
                                    std::cerr << "No CONFIRM for BYE within 5s. Terminating anyway." << std::endl;
                                    break;
                                }
                            }
                            running = false;
                            break;
                        }
                        else if (line.rfind("/join ", 0) == 0) {
                            std::string newChannel = line.substr(6);
                            if (newChannel.empty()) {
                                std::cout << "Usage: /join <channel>" << std::endl;
                                continue;
                            }
                            
                            messageId++;
                            std::vector<char> joinMsg = buildJoinMessage(messageId, newChannel, dispStr);
                            std::cout << "Sending JOIN message for channel '" << newChannel << "'..." << std::endl;
                            
                            ssize_t joinSent = sendto(sockfd, joinMsg.data(), joinMsg.size(), 0,
                                                      reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                            if (joinSent < 0) {
                                std::cerr << "Error sending JOIN message: " << strerror(errno) << std::endl;
                                continue;
                            }
                            
                            auto joinStart = std::chrono::steady_clock::now();
                            auto lastSendTime = std::chrono::steady_clock::now();
                            int joinRetries = 0;
                            bool joinConfirmReceived = false;
                            bool joinReplyReceived = false;
                            uint16_t currentJoinMsgId = messageId;
                            
                            while (!(joinConfirmReceived && joinReplyReceived)) {
                                auto now = std::chrono::steady_clock::now();
                                auto overallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - joinStart).count();
                                if (overallElapsed >= 5000) {
                                    std::cerr << "JOIN process timed out after 5 seconds" << std::endl;
                                    break;
                                }
                                
                                if (!joinConfirmReceived) {
                                    auto resendElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSendTime).count();
                                    if (resendElapsed >= timeoutMs) {
                                        if (joinRetries < maxRetransmissions) {
                                            std::cout << "No confirmation for JOIN message within " << timeoutMs 
                                                      << " ms. Retransmitting JOIN message (attempt " 
                                                      << (joinRetries + 1) << ")..." << std::endl;
                                            
                                            sendto(sockfd, joinMsg.data(), joinMsg.size(), 0,
                                                   reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                                            lastSendTime = now;
                                            joinRetries++;
                                        } else {
                                            std::cerr << "JOIN REPLY not received within timeout after maximum retransmissions." << std::endl;
                                            break;
                                        }
                                    }
                                }
                                
                                int m = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
                                if (m < 0) {
                                    if (errno != EINTR) {
                                        std::cerr << "Error in epoll_wait during JOIN: " << strerror(errno) << std::endl;
                                        break;
                                    }
                                    continue;
                                }
                                
                                for (int i = 0; i < m; ++i) {
                                    if (events[i].data.fd == sockfd) {
                                        char buf[1024];
                                        sockaddr_in peer;
                                        socklen_t peerLen = sizeof(peer);
                                        ssize_t bytes = recvfrom(sockfd, buf, sizeof(buf), 0,
                                                                 reinterpret_cast<sockaddr*>(&peer), &peerLen);
                                        printf_debug("Received %zd bytes from %s:%d (current server port: %d)",
                                                     bytes, inet_ntoa(peer.sin_addr), ntohs(peer.sin_port),
                                                     ntohs(serverAddr.sin_port));
                                        
                                        if (bytes < 3) continue;
                                        
                                        checkAndUpdateServerPort(serverAddr, peer);
                                        
                                        uint8_t msgType = buf[0];
                                        uint16_t recvId;
                                        std::memcpy(&recvId, &buf[1], 2);
                                        recvId = ntohs(recvId);
                                        
                                        if (msgType == CONFIRM_TYPE) {
                                            if (recvId == currentJoinMsgId) {
                                                std::cout << "Received CONFIRM for JOIN message" << std::endl;
                                                joinConfirmReceived = true;
                                            }
                                        } 
                                        else if (msgType == REPLY_TYPE && bytes >= 6) {
                                            uint16_t replyId, refId;
                                            std::memcpy(&replyId, &buf[1], 2);
                                            replyId = ntohs(replyId);
                                            
                                            uint8_t result = buf[3];
                                            std::memcpy(&refId, &buf[4], 2);
                                            refId = ntohs(refId);
                                            
                                            std::vector<char> confirmMsg = buildConfirmMessage(replyId);
                                            sendto(sockfd, confirmMsg.data(), confirmMsg.size(), 0,
                                                   reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                                            
                                            if (refId == currentJoinMsgId) {
                                                std::cout << "Received REPLY for JOIN message with result: " 
                                                          << (result == 1 ? "success" : "failure") << std::endl;
                                                
                                                if (result == 1) {
                                                    channelId = newChannel;
                                                    std::cout << "Successfully joined channel '" << newChannel << "'" << std::endl;
                                                } else {
                                                    std::cout << "Failed to join channel '" << newChannel << "'" << std::endl;
                                                    if (bytes > 6) {
                                                        std::string reason(&buf[6]);
                                                        std::cout << "Reason: " << reason << std::endl;
                                                    }
                                                }
                                                joinReplyReceived = true;
                                            }
                                        } 
                                        else if (msgType != CONFIRM_TYPE) {
                                            std::vector<char> confirmMsg = buildConfirmMessage(recvId);
                                            sendto(sockfd, confirmMsg.data(), confirmMsg.size(), 0,
                                                   reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                                            printf_debug("Received message type 0x%02x during JOIN operation", (unsigned int)msgType);
                                        }
                                    }
                                }
                            }
                            
                            if (joinConfirmReceived && joinReplyReceived) {
                                std::cout << "JOIN process completed for channel '" << newChannel << "'" << std::endl;
                            } else {
                                std::cerr << "Failed to join channel." << std::endl;
                            }
                            
                            continue;
                        }
                        else {
                            messageId++;
                            std::vector<char> msgMessage = buildMsgMessage(messageId, dispStr, line);
                            ssize_t sentBytes = sendto(sockfd, msgMessage.data(), msgMessage.size(), 0,
                                                       reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                            if (sentBytes < 0) {
                                std::cerr << "Error sending MSG message: " << strerror(errno) << std::endl;
                            } else {
                                std::cout << "Sent MSG message (" << sentBytes << " bytes)" << std::endl;
                            }
                        }
                    }
                }
            }
        }
    }
    
    close(sockfd);
    close(epoll_fd);
    return EXIT_SUCCESS;
}
