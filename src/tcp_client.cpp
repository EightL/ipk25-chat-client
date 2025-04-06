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

// External signal handler variable declared in main.cpp
extern volatile sig_atomic_t terminationRequested;

TcpClient::TcpClient(const std::string& serverIp, int port) 
    : Client(false), serverAddress(serverIp), serverPort(port) {
}

TcpClient::~TcpClient() {
    // Base destructor handles socket cleanup
}

bool TcpClient::sendMessage(const std::string& msg) {
    if (socketFd < 0) return false;
    
    ssize_t result = write(socketFd, msg.c_str(), msg.length());
    if (result < 0) {
        perror("write failed");
        return false;
    }
    return true;
}

bool TcpClient::authenticate(const std::string& secret) {
    std::string authMsg = serializeAuth(username, displayName, secret);
    return sendMessage(authMsg);
}

bool TcpClient::joinChannel(const std::string& channelId) {
    std::string joinMsg = serializeJoin(channelId, displayName);
    printf_debug("Sending JOIN message: %s", joinMsg.c_str());
    return sendMessage(joinMsg);
}

bool TcpClient::sendChatMessage(const std::string& message) {
    std::string msgContent = serializeMsg(displayName, message);
    return sendMessage(msgContent);
}

bool TcpClient::sendByeMessage() {
    std::string byeMsg = serializeBye(displayName);
    if (sendMessage(byeMsg)) {
        state = ClientState::TERMINATED;
        return true;
    }
    return false;
}


void TcpClient::handleIncomingMessage(const ParsedMessage& msg) {
    // Call base class implementation
    Client::handleIncomingMessage(msg);
    
    // TCP-specific handling
    if (msg.type == MessageType::UNKNOWN) {
        std::string errMsg = "ERR FROM " + displayName + " IS Malformed message\r\n";
        sendMessage(errMsg);
    }
}

int TcpClient::run() {
    // Set up TCP connection to server using IPv4
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4 only (as per spec)
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_ADDRCONFIG;

    // Resolve server address
    std::vector<std::string> ip_addresses = resolveHostname(serverAddress, true, serverPort);
    if (ip_addresses.empty()) {
        std::cerr << "Could not resolve any address for host: " << serverAddress << std::endl;
        return EXIT_FAILURE;
    }

    // Try each address until we successfully connect
    int sockfd = -1;
    bool connected = false;
    for (const auto& ip : ip_addresses) {
        std::cout << "Trying to connect to " << ip << " on port " << serverPort << "..." << std::endl;
        
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("socket");
            continue;
        }
        
        struct sockaddr_in server_addr;
        std::memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(serverPort);
        if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
            perror("inet_pton");
            close(sockfd);
            sockfd = -1;
            continue;
        }
        
        if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) == 0) {
            std::cout << "Connected to " << ip << std::endl;
            connected = true;
            break;
        } else {
            perror("connect");
            close(sockfd);
            sockfd = -1;
        }
    }

    if (!connected) {
        std::cerr << "Could not connect to any resolved address." << std::endl;
        return EXIT_FAILURE;
    }

    socketFd = sockfd;
    setNonBlocking(sockfd); // Set socket to non-blocking mode for epoll

    // DO NOT send AUTH message immediately - wait for user input
    state = ClientState::INIT;
    
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

    // Main client loop - handle user input and server messages
    bool waitingForReply = false;
    auto replyDeadline = std::chrono::steady_clock::now();
    char buffer[1024];
    std::string stdinBuffer;
    bool running = true;

    while (running && state != ClientState::TERMINATED) {
        // Handle graceful shutdown on SIGINT
        if (terminationRequested) {
            printf_debug("Termination requested, sending BYE");
            std::string byeMsg = serializeBye(displayName);
            if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                perror("write error message");
            }
            break;
        }
        
        // Calculate timeout for epoll_wait
        int timeoutMs = 1000; // Default polling timeout: 1 second
        
        if (waitingForReply) {
            auto now = std::chrono::steady_clock::now();
            auto remainingMs = std::chrono::duration_cast<std::chrono::milliseconds>(replyDeadline - now).count();
            
            if (remainingMs <= 0) {
                std::cout << "ERROR: No REPLY received within 5 seconds.\n";
                close(epoll_fd);
                close(sockfd);
                return EXIT_FAILURE;
            }
            timeoutMs = std::min(1000, static_cast<int>(remainingMs));
        }
        
        epoll_event events[10];
        int nfds = epoll_wait(epoll_fd, events, 10, timeoutMs);
        
        if (nfds == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait failed");
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            // Handle socket events
            if (events[i].data.fd == sockfd) {
                ssize_t count = read(sockfd, buffer, sizeof(buffer) - 1);
                if (count <= 0) {
                    if (count < 0) perror("read from socket");
                    else std::cout << "Server closed the connection.\n";
                    running = false;
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
                if (msg.type == MessageType::UNKNOWN || !isValidTransition(msg.type)) {
                    std::cout << "ERROR: Protocol violation or malformed message from server.\n";
                    std::string errMsg = "ERR FROM " + displayName + " IS Protocol violation or malformed message\r\n";
                    if (write(sockfd, errMsg.c_str(), errMsg.length()) < 0) {
                        perror("write error message");
                    }
                    state = ClientState::TERMINATED;
                } else {
                    handleIncomingMessage(msg);
                }
                
                if (state == ClientState::TERMINATED) {
                    running = false;
                    break;
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
                        Client::processUserInput(line);
                    }
                }
                else if (bytes == 0) {
                    // EOF on stdin, exit gracefully
                    std::string byeMsg = serializeBye(displayName);
                    if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                        perror("write BYE message");
                    }
                    running = false;
                    break;
                }
            }
        }
    }
    
    close(epoll_fd);
    return EXIT_SUCCESS;
}