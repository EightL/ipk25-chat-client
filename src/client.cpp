#include "client.h"
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <cstring>

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

void Client::setCredentials(const std::string& user, const std::string& display, const std::string& secret) {
    username = user;
    displayName = display;
    (void)secret;
    // The secret is not stored in the client object for security reasons
    // It will be passed directly to authentication methods
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