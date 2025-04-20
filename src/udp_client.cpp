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
#include <array>
#include <signal.h>

// flag set by main on SIGINT for graceful exit
extern volatile sig_atomic_t terminationRequested;

const int OVERALL_TIMEOUT_MS = 5000; // 5 seconds overall timeout

// ===================================== Constructors & Destructors ======================================== //

// Initialize UDP client with server details and transmission parameters
UdpClient::UdpClient(const std::string& serverIp, int port, uint16_t timeout, uint8_t retransmissions) 
        : Client(true), serverAddress(serverIp), serverPort(port), timeoutMs(timeout), maxRetransmissions(retransmissions) {
}

// Base destructor handles socket cleanup
UdpClient::~UdpClient() {
    // Base destructor handles socket cleanup
}

// ===================================== Message ID & Server Management ======================================== //

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

// Check if the overall timeout has been exceeded
static bool overallTimeoutExceeded(const std::chrono::steady_clock::time_point& start) {
    constexpr int OVERALL_MS = 5000;
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    return elapsed >= OVERALL_MS;
}

// ===================================== Message Transmission ======================================== //

// Send a UDP message, optionally requiring confirmation
bool UdpClient::sendUdpMessage(const std::vector<char>& msg, bool requireConfirm) {
    // simple case: unreliable send, no confirmation needed
    if (!requireConfirm) {
        ssize_t sent = sendto(socketFd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr));
        if (sent < 0) perror("sendto");
        printf_debug("Sent (no confirm) type=%d, bytes=%zd", msg[0], sent);
        return sent >= 0;
    }

    // extract the message ID from the packet for tracking confirmations
    uint16_t msgId = 0;
    if (msg.size() >= 3) {
        memcpy(&msgId, &msg[1], 2);
        msgId = ntohs(msgId);  // convert from network byte order
    }
    int attempts = 0;  // track retransmission count
    bool confirmed = false;  // flag for confirmation received
    auto start = std::chrono::steady_clock::now();  // track overall timeout

    // send initial packet (first attempt)
    ssize_t rc = sendto(socketFd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr));
    if (rc < 0) {
        perror("sendto");
    }
    printf_debug("send attempt %d for id=%d, bytes=%zd", attempts + 1, msgId, rc);

    // retry loop: continue until confirmed, too many retries, or client terminated
    while (!confirmed && attempts < maxRetransmissions && state != ClientState::TERMINATED) {
        // check if overall timeout (5s) has been exceeded
        if (overallTimeoutExceeded(start)) {
            std::cout << "ERROR: Message transmission timeout (5 seconds)" << std::endl;
            return false;
        }

        // wait for response with short timeout (configurable)
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(socketFd, &rfds);
        struct timeval tv{0, static_cast<int>(timeoutMs * 1000)};
        int ready = select(socketFd + 1, &rfds, nullptr, nullptr, &tv);
        if (state == ClientState::TERMINATED) break;  // check if client terminated during wait

        if (ready > 0) {
            // data is available to read - might be our confirmation or another message
            char buf[65536];
            sockaddr_in peer{};
            socklen_t len = sizeof(peer);
            ssize_t n = recvfrom(socketFd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&peer), &len);
            if (n > 0) {
                // check and update server port if it changed
                checkAndUpdateServerPort(peer);
                ParsedMessage resp = parseUdpMessage(buf, n);

                // check if this is the confirmation we are waiting for
                if (resp.type == MessageType::CONFIRM && resp.refMsgId == msgId) {
                    confirmed = true;
                    break;  // exit retry loop, message confirmed
                }
                else if (resp.type != MessageType::UNKNOWN) {
                    // not our confirmation, but valid message - must send ACK
                    auto ack = createUdpConfirmMessage(resp.msgId);
                    if (sendto(socketFd, ack.data(), ack.size(), 0,
                            reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
                        perror("sendto confirm");
                    }
                    // also process the message
                    handleIncomingMessage(resp);
                    if (state == ClientState::TERMINATED) {
                        break;
                    }
                }
            }
        } 
        else {
            // select timeout without data - retransmit the message
            attempts++;
            ssize_t rc = sendto(socketFd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr));
            if (rc < 0) perror("sendto");
            printf_debug("send attempt %d for id=%d, bytes=%zd", attempts + 1, msgId, rc);
        }
    }

    // check final outcome of transmission attempt
    if (!confirmed) {
        std::cout << "ERROR: Message transmission failed: no confirmation received\n";
        printf_debug("Failed to confirm id=%d after %d attempts", msgId, attempts + 1);
        state = ClientState::TERMINATED;  // fatal error - terminate client
        return false;
    }
    return true;  // success - message was confirmed
}

// Send a message to the server and wait for confirmation
bool UdpClient::authenticate(const std::string& secret) {
    uint16_t id = getNextMsgId();
    auto m = createUdpAuthMessage(id, username, displayName, secret);
    if (!sendUdpMessage(m, true)) {
        std::cout << "ERROR: Authentication failed: no confirmation\n";
        fatalError = true;
        return false;
    }
    return awaitReply(id);
}

// Send a JOIN message to the server and wait for confirmation
bool UdpClient::joinChannel(const std::string& channelId) {
    uint16_t id = getNextMsgId();
    auto m = createUdpJoinMessage(id, channelId, displayName);
    printf_debug("Joining %s (msg %d)", channelId.c_str(), id);
    if (!sendUdpMessage(m, true)) {
        fatalError = true;
        return false;
    }
    return awaitReply(id);
}

// Send a chat message to the server
bool UdpClient::sendChatMessage(const std::string& text) {
    uint16_t id = getNextMsgId();
    auto m = createUdpMsgMessage(id, displayName, text);
    return sendUdpMessage(m, true);
}

// Send a BYE message to the server and wait for confirmation
bool UdpClient::sendByeMessage() {
    uint16_t id = getNextMsgId();
    auto m = createUdpByeMessage(id, displayName);
    if (sendUdpMessage(m, true)) {
        state = ClientState::TERMINATED;
        return true;
    }
    fatalError = true;
    return false;
}

// Send a protocol error message to the server without confirmation
void UdpClient::sendProtocolError(const std::string& err) {
    uint16_t id = getNextMsgId();
    auto m = createUdpErrMessage(id, displayName, err);
    sendUdpMessage(m, /*requireConfirm=*/false);
}

// Helper to send BYE and wait for its CONFIRM before quitting stdin-EOF
void UdpClient::sendByeAndWaitConfirm() {
    uint16_t byeId = getNextMsgId();
    auto byeMsg  = createUdpByeMessage(byeId, displayName);
    // reuse your reliable-usend logic
    if (!sendUdpMessage(byeMsg, true)) {
        std::cerr << "ERROR: Failed to send BYE or receive confirmation\n";
    }
}

// Send a CONFIRM back to the server for the given message ID
void UdpClient::sendConfirm(uint16_t msgId) {
    auto confirmMsg = createUdpConfirmMessage(msgId);
    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
}

// ===================================== Message Processing ======================================== //

// Handle incoming UDP messages
void UdpClient::handleIncomingMessage(const ParsedMessage& msg) {
    if (msg.type == MessageType::UNKNOWN) {
        sendProtocolError("Malformed message");
        std::cout << "ERROR: Received malformed message, closing.\n";
        state = ClientState::TERMINATED;
        return;
    }
    Client::handleIncomingMessage(msg);
}

// Wait for a REPLY message with specified reference ID
bool UdpClient::awaitReply(uint16_t expectedRefId) {
    // Compute absolute deadline 5s from now
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(OVERALL_TIMEOUT_MS);

    while (state != ClientState::TERMINATED) {
        // Time left until overall timeout
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            std::cout << "ERROR: No REPLY received within 5 seconds\n";
            sendProtocolError("No REPLY in time");
            state      = ClientState::TERMINATED;
            fatalError = true;
            return false;
        }

        // Build timeval for select(): min(100ms, time left)
        auto timeLeftMs = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        timeval tv { .tv_sec  = static_cast<long>(std::min<int64_t>(timeLeftMs, 100)), .tv_usec = 0};

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(socketFd, &readfds);

        int ready = select(socketFd + 1, &readfds, nullptr, nullptr, &tv);
        if (ready <= 0) continue;  // timeout or interrupted, loop again

        // We have data to read
        sockaddr_in peerAddr;
        socklen_t peerLen = sizeof(peerAddr);
        char buf[1024];
        ssize_t len = recvfrom(socketFd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
        if (len <= 0) continue;  // spurious or error; loop

        checkAndUpdateServerPort(peerAddr);
        ParsedMessage msg = parseUdpMessage(buf, len);

        // Always ACK non-UNKNOWN, non-CONFIRM
        if (msg.type != MessageType::UNKNOWN && msg.type != MessageType::CONFIRM) {
            auto ack = createUdpConfirmMessage(msg.msgId);
            sendto(socketFd, ack.data(), ack.size(), 0,
                reinterpret_cast<const sockaddr*>(&serverAddr),
                sizeof(serverAddr));
        }

        switch (msg.type) {
            case MessageType::REPLY:
                if (msg.refMsgId == expectedRefId) {
                    handleIncomingMessage(msg);
                    return msg.success;
                }
                // else: some other reply—ignore
                break;

            case MessageType::ERR:
                handleIncomingMessage(msg);
                return false;

            default:
                handleIncomingMessage(msg);
                // if that drove us to TERMINATED, we'll exit on next loop check
                break;
        }
    }

    // If we broke because state==TERMINATED
    return false;
}

// Return true if we've already processed this server message ID
bool UdpClient::isDuplicate(uint16_t msgId) {
    return seenMsgIds.find(msgId) != seenMsgIds.end();
}

// ===================================== Socket & Connection Management ======================================== //

// Initialize UDP socket: resolve, bind ephemeral, set serverAddr
bool UdpClient::initSocket() {
    auto addrs = resolveHostname(serverAddress);
    if (addrs.empty()) {
        std::cout << "ERROR: Could not resolve " << serverAddress << "\n";
        return false;
    }
    socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) { perror("socket"); return false; }
    setNonBlocking(socketFd);

    sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(0);
    if (bind(socketFd, (sockaddr*)&local, sizeof local) < 0) {
        perror("bind"); return false;
    }

    memset(&serverAddr, 0, sizeof serverAddr);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(serverPort);
    if (inet_pton(AF_INET, addrs[0].c_str(), &serverAddr.sin_addr) <= 0) {
        std::cout << "ERROR: Invalid server IP\n";
        return false;
    }
    return true;
}

// Setup epoll to watch socket and stdin
bool UdpClient::setupEpoll() {
    epollFd = epoll_create1(0);
    if (epollFd < 0) { 
        perror("epoll");
        return false; 
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;

    ev.data.fd = socketFd;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, socketFd, &ev) < 0) {
        perror("epoll:add socket"); 
        return false;
    }
    setNonBlocking(STDIN_FILENO);
    ev.data.fd = STDIN_FILENO;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0) {
        perror("epoll:add stdin"); 
        return false;
    }
    return true;
}

// Clean up any resources (mirror what your base destructor does)
void UdpClient::cleanup() {
    if (socketFd != -1) {
        close(socketFd);
        socketFd = -1;
    }
}

// ===================================== Event Loop & I/O Processing ======================================== //

// Main event loop: handle stdin and socket until termination
int UdpClient::eventLoop() {
    std::array<epoll_event, 16> events;
    std::string stdinBuf;
    char udpBuf[65536];

    // loop until client terminates
    while (state != ClientState::TERMINATED) {
        // if requested, send BYE and exit loop
        if (terminationRequested) {
            sendByeAndWaitConfirm();
            break;
        }

        // wait for events with 100ms timeout for periodic checks
        int n = epoll_wait(epollFd, events.data(), events.size(), 100);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            return EXIT_FAILURE;
        }

        // process each ready file descriptor
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == socketFd){
                // handle incoming UDP packet
                handleSocketEvent(udpBuf);
            }      
            else if (fd == STDIN_FILENO){
                // handle user input, exit on fatal error
                if (handleStdinEvent(stdinBuf) == EXIT_FAILURE)
                return EXIT_FAILURE;
            }
        }
    }
    // handle exit depending if a fatal error occurred
    return fatalError ? EXIT_FAILURE : EXIT_SUCCESS;
}

int UdpClient::handleStdinEvent(std::string& buf) {
    char tmp[1024];
    auto n = read(STDIN_FILENO, tmp, sizeof tmp);
    // handle errors or non-blocking status
    if (n < 0) {
        return (errno==EAGAIN) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    // handle EOF (user pressed Ctrl+D) - gracefully exit
    if (n == 0) { 
        sendByeAndWaitConfirm();
         state = ClientState::TERMINATED;
          return EXIT_SUCCESS;
    }
    // append new data to buffer
    buf.append(tmp, n);
    size_t pos;

    // process each complete line
    while ((pos = buf.find('\n')) != std::string::npos) {
        processUserInput(buf.substr(0,pos));
        buf.erase(0, pos+1);
        if (state == ClientState::TERMINATED){
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

void UdpClient::handleSocketEvent(char* buf) {
    sockaddr_in peer;
    socklen_t len = sizeof peer;
    // receive UDP packet and handle errors
    auto n = recvfrom(socketFd, buf, 65536, 0, (sockaddr*)&peer, &len);
    if (n <= 0) {
        return;
    }
    // check if server changed ports and update
    checkAndUpdateServerPort(peer);

    // parse binary message format
    auto msg = parseUdpMessage(buf, n);

    // ignore CONFIRM messages - they are just ACKs
    if (msg.type == MessageType::CONFIRM) {
        return;
    } 

    // send confirmation for all other message types
    sendConfirm(msg.msgId);

    // drop duplicate messages
    if (isDuplicate(msg.msgId)) {
        return;
    }

    // record message ID to prevent duplicate processing
    seenMsgIds.insert(msg.msgId);

    // dispatch message for processing
    handleIncomingMessage(msg);
}

// Initialize, epoll setup, run loop, then cleanup
int UdpClient::run() {
    // setup UDP socket and resolve server hostname
    if (!initSocket()){
        return EXIT_FAILURE;
    } 

    // configure epoll to monitor both socket and stdin     
    if (!setupEpoll()){
        return EXIT_FAILURE;
    }
    
    // run the main event processing loop
    int rc = eventLoop();

    // cleanup stuff before exiting
    cleanup();

    return rc;
}