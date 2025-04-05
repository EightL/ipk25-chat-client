#include "tcp_client.h"
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

void TcpClient::processUserInput(const std::string& line) {
    if (line.empty()) return;
    
    if (line[0] == '/') { // Command
        std::istringstream iss(line.substr(1));
        std::string cmd;
        iss >> cmd;
        
        if (cmd == "join" && state == ClientState::JOINED) {
            std::string channelId;
            iss >> channelId;
            if (!channelId.empty()) {
                channelID = channelId;
                std::string joinMsg = serializeJoin(channelId, displayName);
                std::cout << "Sending JOIN message:\n" << joinMsg;
                if (!sendMessage(joinMsg)) {
                    return;
                }
                state = ClientState::JOIN_WAITING;
            } else {
                std::cout << "Error: Channel name cannot be empty\n";
                std::cout << "Usage: /join <channel>\n"; 
            }
        } 
        else if (cmd == "auth") {
            std::string newUsername, newSecret, newDisplayName;
            iss >> newUsername >> newSecret >> newDisplayName;
            if (newUsername.empty() || newSecret.empty() || newDisplayName.empty()) {
                std::cout << "Usage: /auth <username> <secret> <displayName>\n";
            } else {
                username = newUsername;
                displayName = newDisplayName;
                std::string authMsg = serializeAuth(newUsername, newDisplayName, newSecret);
                if (!sendMessage(authMsg)) {
                    return;
                }
                state = ClientState::AUTHENTICATING;
            }
        }
        else if (cmd == "rename") {
            std::string newDisplayName;
            iss >> newDisplayName;
            if (!newDisplayName.empty()) {
                displayName = newDisplayName;
                std::cout << "Display name updated to: " << newDisplayName << "\n";
            } else {
                std::cout << "Usage: /rename <displayName>\n";
            }
        } 
        else if (cmd == "bye") {
            std::string byeMsg = serializeBye(displayName);
            sendMessage(byeMsg);
        } 
        else if (cmd == "help") {
            std::cout << "Available commands:\n";
            std::cout << "  /join <channel>       - Join a channel\n";
            std::cout << "  /auth <u> <s> <d>     - Re-authenticate with new credentials\n";
            std::cout << "  /rename <displayName> - Change display name locally\n";
            std::cout << "  /bye                  - Disconnect from server\n";
            std::cout << "  /help                 - Show this help\n";
        } 
        else {
            std::cout << "Unknown command. Type /help for available commands.\n";
        }
    } 
    else if (state == ClientState::JOINED) {
        const size_t MAX_MSG_LEN = 60000;
        std::string truncatedLine = line;
        if (truncatedLine.size() > MAX_MSG_LEN) {
            std::cout << "Message truncated to " << MAX_MSG_LEN << " characters.\n";
            truncatedLine = truncatedLine.substr(0, MAX_MSG_LEN);
        }
        std::string msgContent = serializeMsg(displayName, truncatedLine);
        sendMessage(msgContent);
    } 
    else {
        std::cout << "You must join a channel before sending messages.\n";
        std::cout << "Use /join <channel> to join a channel.\n";
    }
}

bool TcpClient::waitForReply(int timeoutSec) {
    fd_set readfds;
    struct timeval tv;
    
    FD_ZERO(&readfds);
    FD_SET(socketFd, &readfds);
    
    tv.tv_sec = timeoutSec;
    tv.tv_usec = 0;
    
    int result = select(socketFd + 1, &readfds, NULL, NULL, &tv);
    
    if (result > 0 && FD_ISSET(socketFd, &readfds)) {
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
    std::string port_str = std::to_string(serverPort);
    struct addrinfo* result;
    int s = getaddrinfo(serverAddress.c_str(), port_str.c_str(), &hints, &result);
    if (s != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(s) << std::endl;
        return EXIT_FAILURE;
    }

    // Try each address until we successfully connect
    int sockfd = -1;
    struct addrinfo* rp;
    bool connected = false;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)rp->ai_addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
        std::cout << "Trying to connect to " << ip_str << " on port " << serverPort << "..." << std::endl;
        
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue;
        }
        
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            std::cout << "Connected to " << ip_str << std::endl;
            connected = true;
            break;
        } else {
            perror("connect");
            close(sockfd);
            sockfd = -1;
        }
    }
    freeaddrinfo(result);

    if (!connected) {
        std::cerr << "Could not connect to any resolved address." << std::endl;
        return EXIT_FAILURE;
    }

    socketFd = sockfd;
    setNonBlocking(sockfd); // Set socket to non-blocking mode for epoll

    // Begin protocol - Send AUTH message
    std::string authMsg = serializeAuth(username, displayName, "33df184d-207f-42a9-b331-7ecebde96416");
    std::cout << "Sending AUTH message:\n" << authMsg;
    state = ClientState::AUTHENTICATING;
    if (write(sockfd, authMsg.c_str(), authMsg.length()) < 0) {
        perror("write AUTH message");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
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
    
    // Handle auth response with 5-second timeout (required by protocol)
    {
        auto authStart = std::chrono::steady_clock::now();
        bool authReplyReceived = false;
        
        while (!authReplyReceived) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - authStart).count();
            
            if (elapsed >= 5000) {
                std::cout << "ERROR: Authentication response timeout (5 seconds).\n";
                close(epoll_fd);
                close(sockfd);
                return EXIT_FAILURE;
            }
            
            // Calculate remaining timeout
            int remainingTimeoutMs = 5000 - elapsed;
            
            epoll_event events[10];
            int nfds = epoll_wait(epoll_fd, events, 10, remainingTimeoutMs);
            
            if (nfds == -1) {
                if (errno == EINTR) continue;
                perror("epoll_wait failed");
                close(epoll_fd);
                close(sockfd);
                return EXIT_FAILURE;
            }
            
            for (int i = 0; i < nfds; i++) {
                if (events[i].data.fd == sockfd) {
                    char buffer[1024];
                    ssize_t count = read(sockfd, buffer, sizeof(buffer) - 1);
                    if (count <= 0) {
                        if (count < 0) {
                            perror("read from socket");
                        } else {
                            std::cout << "Server closed the connection.\n";
                        }
                        close(epoll_fd);
                        close(sockfd);
                        return EXIT_FAILURE;
                    }
                    
                    buffer[count] = '\0';
                    std::string received(buffer, count);
                    std::cout << "Received response:\n" << received;
                    
                    ParsedMessage msg = parseMessage(received);
                    if (msg.type == MessageType::UNKNOWN || !isValidTransition(msg.type)) {
                        std::cout << "ERROR: Protocol violation or malformed message from server.\n";
                        std::string errMsg = "ERR FROM " + displayName + " IS Protocol violation or malformed message\r\n";
                        if (write(sockfd, errMsg.c_str(), errMsg.length()) < 0) {
                            perror("write error message");
                        }
                        close(epoll_fd);
                        close(sockfd);
                        return EXIT_FAILURE;
                    } 
                    
                    handleIncomingMessage(msg);
                    if (state == ClientState::TERMINATED) {
                        close(epoll_fd);
                        close(sockfd);
                        return EXIT_FAILURE;
                    }
                    
                    authReplyReceived = true;
                    break;
                }
            }
        }
    }
    
    // Main client loop - handle user input and server messages
    bool waitingForReply = false;
    auto replyDeadline = std::chrono::steady_clock::now();
    char buffer[1024];
    std::string stdinBuffer;
    bool running = true;

    while (running) {
        // Handle graceful shutdown on SIGINT
        if (terminationRequested) {
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
                        processUserInput(line);
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