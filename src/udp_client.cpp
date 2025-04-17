/**
 * @file udp_client.cpp
 * @brief Implementation of the UDP client for the IPK25-CHAT protocol
 *
 * This file provides UDP-specific implementation of the Client interface
 * for the IPK25-CHAT protocol. It handles connectionless UDP communication,
 * message transmission with retransmissions, and message confirmation.
 *
 * @author xsevcim00
 */

#include "udp_client.h"
#include "debug.h"
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
const int OVERALL_TIMEOUT_MS = 5000; // 5 seconds overall timeout

// Initialize UDP client with server details and transmission parameters
UdpClient::UdpClient(const std::string& serverIp, int port, uint16_t timeout, uint8_t retransmissions) 
        : Client(true), serverAddress(serverIp), serverPort(port), timeoutMs(timeout), maxRetransmissions(retransmissions) {
}

// Base destructor handles socket cleanup
UdpClient::~UdpClient() {
    // Base destructor handles socket cleanup
}

// Generate a new unique message ID
uint16_t UdpClient::getNextMsgId() {
    return nextMsgId++;
}

// Update server port if it changed (common with UDP servers)
void UdpClient::checkAndUpdateServerPort(const sockaddr_in& peerAddr) {
    uint16_t currentServerPort = ntohs(serverAddr.sin_port);
    uint16_t incomingPort = ntohs(peerAddr.sin_port);
    
    if (currentServerPort != incomingPort) {
        printf_debug("Server changed ports: %d -> %d. Updating connection.", currentServerPort, incomingPort);
        serverAddr.sin_port = htons(incomingPort);
    }
}

// Send a UDP message, with optional reliable delivery via retransmissions
bool UdpClient::sendUdpMessage(const std::vector<char>& msg, bool requireConfirm) {
    if (!requireConfirm) {
        // Just send the message once without waiting for confirmation
        printf_debug("Sending message without confirmation (type: %d)", msg[0]);
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
        printf_debug("Sending message type %d with ID %d, waiting for confirmation", msg[0], msgId);
    }
    
    auto startTime = std::chrono::steady_clock::now();
    auto lastSendTime = startTime;
    
    // Initial send
    sendto(socketFd, msg.data(), msg.size(), 0,
           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
    
    while (!confirmed && attempts < maxRetransmissions && state != ClientState::TERMINATED) {
        // At the start of each iteration
        printf_debug("[DEBUG-TERM] Retransmission loop: attempt %d/%d, client state: %d", 
                    attempts, maxRetransmissions, (int)state);

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
        
        // Check if terminated during select
        if (state == ClientState::TERMINATED) {
            printf_debug("Client terminated during message confirmation, aborting");
            return false;
        }
        
        if (ready > 0) {
            ssize_t bytes = recvfrom(socketFd, buffer, sizeof(buffer), 0,
                                     reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
            if (bytes > 0) {
                // Update server port if needed
                checkAndUpdateServerPort(peerAddr);
                
                // Parse message
                ParsedMessage response = parseUdpMessage(buffer, bytes);
                printf_debug("Received response of type %d with ID %d while waiting for CONFIRM for msgId %d", 
                           (int)response.type, response.msgId, msgId);
                
                // Check if it's a CONFIRM for our message
                if (response.type == MessageType::CONFIRM && response.refMsgId == msgId) {
                    printf_debug("Received confirmation for message ID %d", msgId);
                    confirmed = true;
                    break;
                } 
                else if (response.type != MessageType::UNKNOWN) {
                    // Confirm other messages from server
                    printf_debug("Received non-target message (type: %d, ID: %d), sending CONFIRM", 
                               (int)response.type, response.msgId);
                    std::vector<char> confirmMsg = createUdpConfirmMessage(response.msgId);
                    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                    
                    // Process the received message
                    handleIncomingMessage(response);
                    
                    // Check if we transitioned to TERMINATED state
                    if (state == ClientState::TERMINATED) {
                        printf_debug("Client transitioned to TERMINATED state while waiting for confirmation");
                        return false;
                    }
                }
            }
        } else {
            // Timeout - retransmit
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSendTime).count();
            
            // Check if we're in TERMINATED state before retransmitting
            if (state == ClientState::TERMINATED) {
                printf_debug("Detected TERMINATED state, breaking out of retransmission loop");
                return false;
            }
            
            if (elapsed >= timeoutMs) {
                printf_debug("Timeout (no response in %d ms) for message ID %d, retransmitting (attempt %d/%d)", 
                           timeoutMs, msgId, attempts+1, maxRetransmissions);
                sendto(socketFd, msg.data(), msg.size(), 0,
                       reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                lastSendTime = now;
                attempts++;
            }
        }
        
        // Check overall timeout (5 seconds) and state before next iteration
        auto now = std::chrono::steady_clock::now();
        auto overallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
        if (state == ClientState::TERMINATED) {
            printf_debug("Detected TERMINATED state, breaking out of retransmission loop");
            return false;
        }
        if (overallElapsed >= OVERALL_TIMEOUT_MS) {
            printf_debug("ERROR: Overall timeout (%d ms) reached for message ID %d", OVERALL_TIMEOUT_MS, msgId);
            std::cout << "ERROR: Message transmission timeout (5 seconds)" << std::endl;
            return false;
        }

        // After processing any message, double-check state
        if (state == ClientState::TERMINATED) {
            printf_debug("[DEBUG-TERM] State changed to TERMINATED during message processing");
            return false;
        }
    }
    
    if (!confirmed) {
        printf_debug("Failed to get confirmation for message ID %d after %d attempts", msgId, attempts);
        state = ClientState::TERMINATED;
        fatalError = true;
        return false;
    }
    
    // FIX: Return just the confirmation status; do not treat TERMINATED as a success.
    return confirmed;
}

// Authenticate with the server - UDP implementation
bool UdpClient::authenticateWithRetries(const std::string& secret) {
    // Send AUTH message
    uint16_t authMsgId = getNextMsgId();
    std::vector<char> authMsg = createUdpAuthMessage(authMsgId, username, displayName, secret);
    
    if (!sendUdpMessage(authMsg, true)) {
        std::cout << "ERROR: Authentication failed: couldn't get confirmation" << std::endl;
        fatalError = true;
        return false;
    }
    
    // Wait for REPLY
    return awaitReply(authMsgId);
}


void UdpClient::sendProtocolError(const std::string& errorMessage) {
    uint16_t errId = getNextMsgId();
    auto errMsg = createUdpErrMessage(errId, displayName, errorMessage);
    sendto(socketFd, errMsg.data(), errMsg.size(), 0,
           reinterpret_cast<sockaddr*>(&serverAddr),
           sizeof(serverAddr));
}

// Authenticate with the server - UDP implementation
bool UdpClient::authenticate(const std::string& secret) {
    return authenticateWithRetries(secret);
}

// Send a join channel request - UDP implementation
bool UdpClient::joinChannel(const std::string& channelId) {
    printf_debug("Attempting to join channel: '%s'", channelId.c_str());
    uint16_t joinMsgId = getNextMsgId();
    std::vector<char> joinMsg = createUdpJoinMessage(joinMsgId, channelId, displayName);
    
    printf_debug("Created JOIN message with ID %d for channel '%s' as user '%s'", 
               joinMsgId, channelId.c_str(), displayName.c_str());
    
    // Get server address info for logging
    char serverIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(serverAddr.sin_addr), serverIpStr, INET_ADDRSTRLEN);
    printf_debug("Server connection details - IP: %s, Port: %d", 
               serverIpStr, ntohs(serverAddr.sin_port));
    
    if (!sendUdpMessage(joinMsg, true)) {
        printf_debug("JOIN request failed: couldn't get confirmation for channel: %s (message ID: %d)", 
                   channelId.c_str(), joinMsgId);
        fatalError = true;
        return false;
    }
    
    // Wait for REPLY with 5-second timeout
    if (!awaitReply(joinMsgId)) {
        printf_debug("JOIN request failed: no positive REPLY received for channel: %s (message ID: %d)", 
                   channelId.c_str(), joinMsgId);
        fatalError = true;
        return false;
    }
    
    printf_debug("JOIN request successful for channel: %s (message ID: %d)", 
               channelId.c_str(), joinMsgId);
    return true;
}

// Send a chat message - UDP implementation
bool UdpClient::sendChatMessage(const std::string& text) {
    uint16_t id = getNextMsgId();
    auto datagram = createUdpMsgMessage(id, displayName, text);

    // ask for confirmation & retransmit
    return sendUdpMessage(datagram, /*requireConfirm=*/true);
}

// Send BYE message - UDP implementation
bool UdpClient::sendByeMessage() {
    printf_debug("[DEBUG-TERM] Attempting to send BYE message");
    uint16_t byeMsgId = getNextMsgId();
    std::vector<char> byeMsg = createUdpByeMessage(byeMsgId, displayName);
    
    if (sendUdpMessage(byeMsg, true)) {
        printf_debug("[DEBUG-TERM] BYE message confirmed by server");
        state = ClientState::TERMINATED;
        return true;
    } else {
        printf_debug("[DEBUG-TERM] Failed to get confirmation for BYE message");
        fatalError = true;
        return false;
    }
}

// UDP-specific message handling
void UdpClient::handleIncomingMessage(const ParsedMessage& msg) {
    printf_debug("[DEBUG-TERM] Handling message of type %d (before base implementation)", (int)msg.type);
    
    // Handle malformed messages (UNKNOWN type)
    if (msg.type == MessageType::UNKNOWN) {
        uint16_t errId = getNextMsgId();
        auto err = createUdpErrMessage(errId, displayName, "Malformed message");
        sendto(socketFd, err.data(), err.size(), 0,
               reinterpret_cast<sockaddr*>(&serverAddr),
               sizeof(serverAddr));
        state = ClientState::TERMINATED;
        std::cout << "ERROR: Received malformed message, closing.\n";
        return; // Skip base implementation
    }
    
    // State before handling
    ClientState beforeState = state;
    
    // Use base class implementation
    Client::handleIncomingMessage(msg);
    
    // Check if state changed, especially to TERMINATED
    if (beforeState != state) {
        printf_debug("[DEBUG-TERM] State changed from %d to %d after handling message type %d", 
                    (int)beforeState, (int)state, (int)msg.type);
    }
    
    // Special debug for ERR messages
    if (msg.type == MessageType::ERR) {
        printf_debug("[DEBUG-TERM] Received ERR message, client state set to %d (TERMINATED=4)", (int)state);
        terminationRequested = 1;
    }
}

// Wait for a REPLY message with specified reference ID
bool UdpClient::awaitReply(uint16_t expectedRefId) {
    // Wait for REPLY message
    auto startTime = std::chrono::steady_clock::now();
    
    while (state != ClientState::TERMINATED) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
        
        if (elapsed >= OVERALL_TIMEOUT_MS) {
            std::cout << "ERROR: No REPLY received within 5 seconds" << std::endl;
            sendProtocolError("No REPLY in time");
            state = ClientState::TERMINATED;
            fatalError = true;
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
                    std::vector<char> confirmMsg = createUdpConfirmMessage(response.msgId);
                    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0,
                          reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                }
                
                // Check if it's a REPLY for our message
                if (response.type == MessageType::REPLY && response.refMsgId == expectedRefId) {
                    handleIncomingMessage(response);
                    return response.success; // Return true for OK, false for NOK
                }
                else if (response.type == MessageType::ERR) {
                    // Handle ERR message
                    handleIncomingMessage(response);
                    return false; // Failed due to error
                }
                else {
                    // Process other messages
                    handleIncomingMessage(response);
                    
                    // If we transitioned to TERMINATED state, exit
                    if (state == ClientState::TERMINATED) {
                        return false;
                    }
                }
            }
        }
    }
    
    return false; // Failed (TERMINATED state or other error)
}

// UDP client run loop
int UdpClient::run() {
    // Resolve hostname to IP
    std::vector<std::string> ip_addresses = Client::resolveHostname(serverAddress, false);
    if (ip_addresses.empty()) {
        std::cout << "ERROR: Could not resolve any address for host: " << serverAddress << std::endl;
        return EXIT_FAILURE;
    }
    
    // Use the first resolved IP
    std::string serverIP = ip_addresses[0];
    
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
        std::cout << "ERROR: Invalid server address: " << serverIP << std::endl;
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
    
    
    // Main event loop
    char buffer[65536]; // Large buffer for UDP messages
    epoll_event events[10];
    std::string stdinBuffer;
    bool running = true;
    
    while (running) {
        // Explicit check for TERMINATED state at the beginning of each loop iteration
        if (state == ClientState::TERMINATED) {
            printf_debug("[DEBUG-TERM] Client in TERMINATED state, exiting main loop");
            running = false;
            break;
        }
        
        // Handle Ctrl+C
        if (terminationRequested) {
            printf_debug("[DEBUG-TERM] Termination requested, sending BYE");
            uint16_t byeMsgId = getNextMsgId();
            std::vector<char> byeMsg = createUdpByeMessage(byeMsgId, displayName);
            
            // Use sendUdpMessage with confirmation to ensure the BYE is received
            if (sendUdpMessage(byeMsg, true)) {
                printf_debug("[DEBUG-TERM] BYE message confirmed by server");
            } else {
                printf_debug("[DEBUG-TERM] Failed to get confirmation for BYE message");
            }
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
                printf_debug("[DEBUG-TERM] Received message type %d with ID %d from server in main loop", (int)msg.type, msg.msgId);

                // If it's a CONFIRM message, handle it specially
                if (msg.type == MessageType::CONFIRM) {
                    printf_debug("[DEBUG-TERM] Skipping processing for CONFIRM message (refMsgId: %d)", msg.refMsgId);
                    continue; // Skip normal message processing for CONFIRM messages
                }

                // For all non-CONFIRM messages, send a CONFIRM response
                if (msg.type != MessageType::CONFIRM) {
                    std::vector<char> confirmMsg = createUdpConfirmMessage(msg.msgId);
                    printf_debug("[DEBUG-TERM] Sending CONFIRM for message ID %d", msg.msgId);
                    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0,
                           reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
                    
                    // Check if we've already seen this message ID
                    if (seenMsgIds.find(msg.msgId) == seenMsgIds.end()) {
                        // Check for message ID wrap-around
                        if (msg.msgId < 1000 && seenMsgIds.size() > 60000) {
                            // We've likely wrapped around, clear the old IDs
                            printf_debug("Message ID wrap-around detected, clearing seen IDs cache");
                            seenMsgIds.clear();
                        }
                        
                        printf_debug("[DEBUG-TERM] Processing message ID %d (type: %d)", msg.msgId, (int)msg.type);
                        // Not a duplicate - process and track it
                        seenMsgIds.insert(msg.msgId);
                        
                        // Process ALL messages, including UNKNOWN types
                        handleIncomingMessage(msg);
                        
                        if (state == ClientState::TERMINATED) {
                            printf_debug("[DEBUG-TERM] Client state changed to TERMINATED after processing message ID %d", msg.msgId);
                            running = false;
                            break;
                        }
                    } else {
                        printf_debug("[DEBUG-TERM] Ignoring duplicate message with ID: %d (type: %d)", msg.msgId, (int)msg.type);
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
                        Client::processUserInput(line);
                        
                        if (state == ClientState::TERMINATED) {
                            printf_debug("[DEBUG-TERM] State is TERMINATED after processing user input");
                            running = false;
                            break;
                        }
                    }
                }
                else if (bytes == 0) {
                    // EOF on stdin, exit gracefully
                    if (sendByeMessage()) {
                        printf_debug("BYE message sent and confirmed on EOF");
                    } else {
                        printf_debug("Failed to confirm BYE message on EOF");
                    }
                    running = false;
                    break;
                }
            }
        }
        
        // Add an extra check at the end of each loop iteration
        if (state == ClientState::TERMINATED) {
            printf_debug("[DEBUG-TERM] End of main loop: state is TERMINATED, will break on next iteration");
        }
    }
    
    printf_debug("[DEBUG-TERM] UDP client main loop terminated, cleaning up");
    close(epoll_fd);
    return fatalError ? EXIT_FAILURE : EXIT_SUCCESS;
}
