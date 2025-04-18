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

// Check if the overall timeout has been exceeded
static bool overallTimeoutExceeded(const std::chrono::steady_clock::time_point& start) {
    constexpr int OVERALL_MS = 5000;
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start
    ).count();
    return elapsed >= OVERALL_MS;
}

// Send a UDP message, optionally requiring confirmation
bool UdpClient::sendUdpMessage(const std::vector<char>& msg, bool requireConfirm) {
    if (!requireConfirm) {
        ssize_t sent = sendto(socketFd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr));
        if (sent < 0) perror("sendto");
        printf_debug("Sent (no confirm) type=%d, bytes=%zd", msg[0], sent);
        return sent >= 0;
    }

    // Reliable send: initial + retries
    uint16_t msgId = 0;
    if (msg.size() >= 3) {
        memcpy(&msgId, &msg[1], 2);
        msgId = ntohs(msgId);
    }
    int attempts = 0;
    bool confirmed = false;
    auto start = std::chrono::steady_clock::now();

    // initial send
    ssize_t rc = sendto(socketFd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr));
    if (rc < 0) {
        perror("sendto");
    }
    printf_debug("send attempt %d for id=%d, bytes=%zd", attempts + 1, msgId, rc);

    // loop until confirm or retries exhausted or terminated
    while (!confirmed && attempts < maxRetransmissions && state != ClientState::TERMINATED) {
        if (overallTimeoutExceeded(start)) {
            std::cout << "ERROR: Message transmission timeout (5 seconds)" << std::endl;
            return false;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(socketFd, &rfds);
        struct timeval tv{0, static_cast<int>(timeoutMs * 1000)};
        int ready = select(socketFd + 1, &rfds, nullptr, nullptr, &tv);
        if (state == ClientState::TERMINATED) break;

        if (ready > 0) {
            // handle incoming
            char buf[65536];
            sockaddr_in peer{};
            socklen_t len = sizeof(peer);
            ssize_t n = recvfrom(socketFd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&peer), &len);
            if (n > 0) {
                checkAndUpdateServerPort(peer);
                ParsedMessage resp = parseUdpMessage(buf, n);

                if (resp.type == MessageType::CONFIRM && resp.refMsgId == msgId) {
                    confirmed = true;
                    break;
                }
                else if (resp.type != MessageType::UNKNOWN) {
                    // ack other messages
                    auto ack = createUdpConfirmMessage(resp.msgId);
                    if (sendto(socketFd, ack.data(), ack.size(), 0,
                            reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
                        perror("sendto confirm");
                    }
                    handleIncomingMessage(resp);
                    if (state == ClientState::TERMINATED) break;
                }
            }
        } else {
            // timed out -> retransmit
            attempts++;
            ssize_t rc = sendto(socketFd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&serverAddr), sizeof(serverAddr));
            if (rc < 0) perror("sendto");
            printf_debug("send attempt %d for id=%d, bytes=%zd", attempts + 1, msgId, rc);
        }
    }

    if (!confirmed) {
        printf_debug("Failed to confirm id=%d after %d attempts", msgId, attempts + 1);
        state = ClientState::TERMINATED;
        return false;
    }
    return true;
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
    // Compute absolute deadline 5 s from now
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

        // Build timeval for select(): min(100 ms, time left)
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

        // Always ACK non‑UNKNOWN, non‑CONFIRM
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
                // if that drove us to TERMINATED, we’ll exit on next loop check
                break;
        }
    }

    // If we broke because state==TERMINATED
    return false;
}

int UdpClient::handleStdinEvent(std::string& buf) {
    char tmp[1024];
    auto n = read(STDIN_FILENO, tmp, sizeof tmp);
    if (n < 0) return (errno==EAGAIN)? EXIT_SUCCESS : EXIT_FAILURE;
    if (n == 0) { sendByeAndWaitConfirm(); state = ClientState::TERMINATED; return EXIT_SUCCESS; }
    buf.append(tmp, n);
    size_t pos;
    while ((pos = buf.find('\n')) != std::string::npos) {
        processUserInput(buf.substr(0,pos));
        buf.erase(0, pos+1);
        if (state == ClientState::TERMINATED) return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

void UdpClient::handleSocketEvent(char* buf) {
    sockaddr_in peer; socklen_t len = sizeof peer;
    auto n = recvfrom(socketFd, buf, 65536, 0, (sockaddr*)&peer, &len);
    if (n <= 0) return;
    checkAndUpdateServerPort(peer);
    auto msg = parseUdpMessage(buf, n);
    if (msg.type == MessageType::CONFIRM) return;
    sendConfirm(msg.msgId);
    if (isDuplicate(msg.msgId)) return;
    seenMsgIds.insert(msg.msgId);
    handleIncomingMessage(msg);
}

// Send a CONFIRM back to the server for the given message ID
void UdpClient::sendConfirm(uint16_t msgId) {
    auto confirmMsg = createUdpConfirmMessage(msgId);
    sendto(socketFd, confirmMsg.data(), confirmMsg.size(), 0, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
}

// Return true if we've already processed this server message ID
bool UdpClient::isDuplicate(uint16_t msgId) {
    return seenMsgIds.find(msgId) != seenMsgIds.end();
}

// Helper to send BYE and wait for its CONFIRM before quitting stdin‐EOF
void UdpClient::sendByeAndWaitConfirm() {
    uint16_t byeId = getNextMsgId();
    auto byeMsg  = createUdpByeMessage(byeId, displayName);
    // reuse your reliable‐send logic
    if (!sendUdpMessage(byeMsg, /*requireConfirm=*/true)) {
        std::cerr << "ERROR: Failed to send BYE or receive confirmation\n";
    }
}

// Clean up any resources (mirror what your base destructor does)
void UdpClient::cleanup() {
    if (socketFd != -1) {
        close(socketFd);
        socketFd = -1;
    }
}

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

// Main event loop: handle stdin and socket until termination
int UdpClient::eventLoop() {
    std::array<epoll_event, 16> events;
    std::string stdinBuf;
    char udpBuf[65536];

    while (state != ClientState::TERMINATED) {
        // if requested, send BYE and exit loop
        if (terminationRequested) {
            sendByeAndWaitConfirm();
            break;
        }
        int n = epoll_wait(epollFd, events.data(), events.size(), 100);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            return EXIT_FAILURE;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == socketFd){
                handleSocketEvent(udpBuf);
            }      
            else if (fd == STDIN_FILENO){
                if (handleStdinEvent(stdinBuf) == EXIT_FAILURE)
                return EXIT_FAILURE;
            }
        }
    }
    return fatalError ? EXIT_FAILURE : EXIT_SUCCESS;
}

// Initialize, epoll setup, run loop, then cleanup
int UdpClient::run() {
    if (!initSocket()){
        return EXIT_FAILURE;
    }      
    if (!setupEpoll()){
        return EXIT_FAILURE;
    }      
    int rc = eventLoop();
    cleanup();
    return rc;
}