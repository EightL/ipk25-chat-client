/**
 * @file tcp_client.cpp
 * @brief TCP-specific implementation of the IPK25-CHAT Client interface
 *
 * Establishes and manages a TCP connection to the chat server, handles
 * message transmission, reception, and event loop using non-blocking I/O
 * with epoll.
 *
 * @author xsevcim00
 */

#include "tcp_client.h"
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
#include <utility>

extern volatile sig_atomic_t terminationRequested;  // flag set on SIGINT

// ===================================== Constructors & Destructors ======================================== //


// Constructor for TcpClient
TcpClient::TcpClient(const std::string& serverIp, int port) : Client(false), serverAddress(serverIp), serverPort(port){}

// Destructor
TcpClient::~TcpClient() = default;

// ===================================== Message Transmission ======================================== //

// Send raw string over TCP and return success
bool TcpClient::sendMessage(const std::string& msg) {
    const char* p = msg.data();
    size_t left  = msg.size();
    while (left) {
        ssize_t n = write(socketFd, p, left);
        if (n <= 0) { 
            if (errno==EINTR) continue; 
            perror("write"); 
            return false; 
        }
        p += n; 
        left -= n;
    }
    return true;
}

// Send protocol ERR message to server
void TcpClient::sendProtocolError(const std::string& errorMessage) {
    std::string errMsg = "ERR FROM " + displayName + " IS " + errorMessage + "\r\n";
    sendMessage(errMsg);  // transmit error
}

// Send AUTH request and start reply timeout
bool TcpClient::authenticate(const std::string& secret) {
    std::string authMsg = createTcpAuthMessage(username, displayName, secret);
    if (sendMessage(authMsg)) {
        waitingForReply = true;  // await server REPLY
        replyDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        return true;
    }
    return false;
}

// Send JOIN request and start reply timeout
bool TcpClient::joinChannel(const std::string& channelId) {
    std::string joinMsg = createTcpJoinMessage(channelId, displayName);
    printf_debug("Sending JOIN message: %s", joinMsg.c_str());  // debug
    
    if (sendMessage(joinMsg)) {
        waitingForReply = true;  // await server REPLY
        replyDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        return true;
    }
    return false;
}

// Send chat message over TCP
bool TcpClient::sendChatMessage(const std::string& message) {
    std::string msgContent = createTcpMsgMessage(displayName, message);
    return sendMessage(msgContent);  // transmit chat
}

// Send BYE and mark client terminated
bool TcpClient::sendByeMessage() {
    std::string byeMsg = createTcpByeMessage(displayName);
    if (sendMessage(byeMsg)) {
        state = ClientState::TERMINATED;  // termination
        return true;
    }
    return false;
}

// ===================================== Message Processing ======================================== //


// Handle received message and manage state/timeouts
void TcpClient::handleIncomingMessage(const ParsedMessage& msg) {
    if (msg.type == MessageType::REPLY) {
        waitingForReply = false;  // cancel reply timeout
    }
    Client::handleIncomingMessage(msg);  // base handling
    if (msg.type == MessageType::UNKNOWN) {
        sendProtocolError("Malformed message");  // notify server
        state = ClientState::TERMINATED;         // terminate on protocol error
    }
}

// Read socket input, extract CRLF-terminated messages
void TcpClient::processSocketInput(std::string& buffer) {
    char tempBuffer[4096];
    ssize_t bytesRead = read(socketFd, tempBuffer, sizeof(tempBuffer));
    if (bytesRead > 0) {
        buffer.append(tempBuffer, bytesRead);  // accumulate data
        size_t pos;
        while ((pos = buffer.find("\r\n")) != std::string::npos) {
            std::string completeMessage = buffer.substr(0, pos + 2);
            buffer.erase(0, pos + 2);  // remove processed chunk
            try {
                ParsedMessage parsedMsg = parseTcpMessage(completeMessage);
                handleIncomingMessage(parsedMsg);  // dispatch message
            } catch (const std::exception& e) {
                std::cerr << "ERROR: " << e.what() << std::endl;  // log parse error
            }
        }
    } 
    else if (bytesRead == 0) {
        sendByeMessage();  // server closed connection
    } 
    else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read from socket");  // unexpected read error
            state = ClientState::TERMINATED;
        }
    }
}

// ===================================== Main Event Loop ======================================== //

// Main event loop: resolve, connect, epoll setup, handle events
int TcpClient::run() {
    int ret = EXIT_SUCCESS;
    int epoll_fd = -1;
    socketFd = -1;

    do {
        // resolve server address: prepare hints for ipv4/tcp
        struct addrinfo hints{}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(serverAddress.c_str(), std::to_string(serverPort).c_str(), &hints, &res) != 0) {
            std::cout << "ERROR: Could not resolve host" << std::endl;
            ret = EXIT_FAILURE;
            break;
        }
        
        // attempt connection: try each returned address
        for (auto p = res; p; p = p->ai_next) {
            socketFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (socketFd < 0) continue;  // skip invalid socket
            if (connect(socketFd, p->ai_addr, p->ai_addrlen) == 0) break;  // connected
            close(socketFd);
            socketFd = -1;
        }
        freeaddrinfo(res);  // free address list
        if (socketFd < 0) {
            std::cout << "ERROR: Could not connect" << std::endl;
            ret = EXIT_FAILURE;
            break;
        }
        setNonBlocking(socketFd);  // enable non-blocking io
        state = ClientState::INIT;  // initialize state machine

        // setup epoll to monitor socket and stdin
        epoll_fd = epoll_create1(0);
        if (epoll_fd < 0) { perror("epoll_create"); ret = EXIT_FAILURE; break; }

        // helper to add fd to epoll
        auto add_fd = [&](int fd) {
            epoll_event ev{EPOLLIN, {.fd = fd}};
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                perror("epoll_ctl"); throw std::runtime_error("failed epoll_ctl");
            }
        };
        
        // register server socket and stdin
        add_fd(socketFd);
        setNonBlocking(STDIN_FILENO);
        add_fd(STDIN_FILENO);

        // buffers for incoming data
        std::string socketBuffer, stdinBuffer;
        bool running = true;
        
        // loop until termination or error
        while (running) {
            if (state == ClientState::TERMINATED) break;  // exit on termination state
            if (terminationRequested) { sendByeMessage(); break; }  // handle ctrl-c

            // calculate epoll timeout based on pending reply
            int timeoutMs = 1000; 
            if (waitingForReply) {
                auto now = std::chrono::steady_clock::now();
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(replyDeadline - now).count();
                if (rem <= 0) {
                    std::cout << "ERROR: No REPLY in 5s" << std::endl;
                    sendProtocolError("No REPLY in time");
                    sendByeMessage();
                    ret = EXIT_FAILURE;
                    break;  // break waiting loop
                }
                timeoutMs = std::min(1000, static_cast<int>(rem));  // shorten timeout
            }

            // poll for events
            epoll_event events[10];
            int nfds = epoll_wait(epoll_fd, events, 10, timeoutMs);
            if (nfds < 0) {
                if (errno == EINTR) continue;  // retry if interrupted
                perror("epoll_wait"); ret = EXIT_FAILURE; break;
            }

            // handle each event
            for (int i = 0; i < nfds; ++i) {
                int fd = events[i].data.fd;
                if (fd == socketFd) {
                    // data from server
                    processSocketInput(socketBuffer);
                    if (state == ClientState::TERMINATED) {
                        running = false; 
                        break; 
                    }
                } else {
                    // data from stdin
                    char buf[1024];
                    ssize_t n = read(fd, buf, sizeof(buf));
                    if (n > 0) {
                        stdinBuffer.append(buf, n);  // append input
                        size_t pos;
                        while ((pos = stdinBuffer.find('\n')) != std::string::npos) {
                            processUserInput(stdinBuffer.substr(0, pos));
                            stdinBuffer.erase(0, pos + 1);
                            if (state == ClientState::TERMINATED) { 
                                running = false; 
                                break; 
                            }
                        }
                    } 
                    else if (n == 0) {
                        // eof on stdin
                        sendByeMessage();
                        running = false;
                        break;
                    } 
                    else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("read stdin");  // unexpected stdin error
                    }
                }
            }
        }

    } while (false);

    // cleanup resources
    if (epoll_fd >= 0) close(epoll_fd);
    if (socketFd >= 0) close(socketFd);
    return ret;  // return status code
}
