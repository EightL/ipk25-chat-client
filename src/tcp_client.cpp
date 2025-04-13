/**
 * @file tcp_client.cpp
 * @brief Implementation of the TCP client for the IPK25-CHAT protocol
 *
 * This file provides TCP-specific implementation of the Client interface
 * for the IPK25-CHAT protocol. It handles connection management, message
 * transmission, and event processing using non-blocking I/O with epoll.
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
 
 // External signal handler variable declared in main.cpp
 extern volatile sig_atomic_t terminationRequested;
 
 // Initialize TCP client with server details
 TcpClient::TcpClient(const std::string& serverIp, int port) 
     : Client(false), serverAddress(serverIp), serverPort(port) {
 }
 
 // Base destructor handles socket cleanup
 TcpClient::~TcpClient() {
 }
 
 // Send a message over the TCP socket
 bool TcpClient::sendMessage(const std::string& msg) {
     if (socketFd < 0) return false;
     
     ssize_t result = write(socketFd, msg.c_str(), msg.length());
     if (result < 0) {
         perror("write failed");
         return false;
     }
     return true;
 }
 
 // Authenticate with server - TCP implementation
 bool TcpClient::authenticate(const std::string& secret) {
     std::string authMsg = createTcpAuthMessage(username, displayName, secret);
     if (sendMessage(authMsg)) {
         // Start a 5-second timeout for authentication reply
         waitingForReply = true;
         replyDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
         return true;
     }
     return false;
 }
 
 // Join a channel - TCP implementation
 bool TcpClient::joinChannel(const std::string& channelId) {
     std::string joinMsg = createTcpJoinMessage(channelId, displayName);
     printf_debug("Sending JOIN message: %s", joinMsg.c_str());
     return sendMessage(joinMsg);
 }
 
 // Send a chat message - TCP implementation
 bool TcpClient::sendChatMessage(const std::string& message) {
     std::string msgContent = createTcpMsgMessage(displayName, message);
     return sendMessage(msgContent);
 }
 
 // Send BYE message - TCP implementation
 bool TcpClient::sendByeMessage() {
     std::string byeMsg = createTcpsByeMessage(displayName);
     if (sendMessage(byeMsg)) {
         state = ClientState::TERMINATED;
         return true;
     }
     return false;
 }
 
 // TCP-specific message handling
 void TcpClient::handleIncomingMessage(const ParsedMessage& msg) {
     // Call base class implementation
     Client::handleIncomingMessage(msg);
     
     // Handle malformed messages in TCP-specific way
     if (msg.type == MessageType::UNKNOWN) {
         std::string errMsg = "ERR FROM " + displayName + " IS Malformed message\r\n";
         sendMessage(errMsg);
     }
 }
 
 // Main TCP client execution loop
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
         std::cout << "ERROR: Could not resolve any address for host: " << serverAddress << std::endl;
         return EXIT_FAILURE;
     }
 
     // Try each address until successfully connected
     int sockfd = -1;
     bool connected = false;
     for (const auto& ip : ip_addresses) {
         std::cerr << "Trying to connect to " << ip << " on port " << serverPort << "..." << std::endl;
         
         // Create socket
         sockfd = socket(AF_INET, SOCK_STREAM, 0);
         if (sockfd == -1) {
             perror("socket");
             continue;
         }
         
         // Set up server address
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
         
         // Connect to server
         if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) == 0) {
             std::cerr << "Connected to " << ip << std::endl;
             connected = true;
             break;
         } else {
             perror("connect");
             close(sockfd);
             sockfd = -1;
         }
     }
 
     if (!connected) {
         std::cout << "ERROR: Could not connect to any resolved address." << std::endl;
         return EXIT_FAILURE;
     }
 
     socketFd = sockfd;
     setNonBlocking(sockfd); // Set socket to non-blocking mode for epoll
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
 
     // Main event loop
     bool waitingForReply = false;
     auto replyDeadline = std::chrono::steady_clock::now();
     std::string buffer; // Buffer to accumulate incoming data
     std::string stdinBuffer;
     bool running = true;
 
     while (running) {
         // Check for TERMINATED state
         if (state == ClientState::TERMINATED) {
             printf_debug("Client in TERMINATED state, exiting main loop");
             running = false;
             break;
         }
 
         // Handle graceful shutdown on SIGINT
         if (terminationRequested) {
             printf_debug("Termination requested, sending BYE");
             std::string byeMsg = createTcpsByeMessage(displayName);
             if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                 perror("write error message");
             }
             break;
         }
         
         // Calculate timeout for epoll_wait
         int timeoutMs = 1000; // Default timeout: 1 second
         
         // Adjust timeout if waiting for authentication reply
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
         
         // Wait for events
         epoll_event events[10];
         int nfds = epoll_wait(epoll_fd, events, 10, timeoutMs);
         
         if (nfds == -1) {
             if (errno == EINTR) continue;
             perror("epoll_wait failed");
             break;
         }
         
         // Process events
         for (int i = 0; i < nfds; i++) {
             // Handle socket events
             if (events[i].data.fd == sockfd) {
                 char tempBuffer[4096];
                 ssize_t bytesRead = read(sockfd, tempBuffer, sizeof(tempBuffer) - 1);
                 
                 if (bytesRead > 0) {
                     // Add new data to buffer
                     buffer.append(tempBuffer, bytesRead);
                     
                     // Process complete messages (ending with \r\n)
                     size_t pos;
                     while ((pos = buffer.find("\r\n")) != std::string::npos) {
                         // Extract complete message
                         std::string completeMessage = buffer.substr(0, pos + 2);
                         buffer.erase(0, pos + 2); // Remove processed message
                         
                         // Parse and handle the message
                         try {
                             ParsedMessage parsedMsg = parseTcpMessage(completeMessage);
                             handleIncomingMessage(parsedMsg);
                         } catch (const std::exception& e) {
                             std::cerr << "ERROR: " << e.what() << std::endl;
                             // Skip malformed messages
                         }
                     }
                 } 
                 else if (bytesRead <= 0) {
                     // Handle disconnect or error
                     if (bytesRead < 0) perror("read from socket");
                     else std::cerr << "Server closed the connection.\n";
                     running = false;
                     break;
                 }
             }
             // Handle stdin events
             else if (events[i].data.fd == STDIN_FILENO) {
                 char buf[1024];
                 ssize_t bytes = read(STDIN_FILENO, buf, sizeof(buf));
                 if (bytes > 0) {
                     // Add input to buffer
                     stdinBuffer.append(buf, bytes);
                     size_t pos;
                     
                     // Process complete lines
                     while ((pos = stdinBuffer.find('\n')) != std::string::npos) {
                         std::string line = stdinBuffer.substr(0, pos);
                         stdinBuffer.erase(0, pos + 1);
                         Client::processUserInput(line);
                     }
                 }
                 else if (bytes == 0) {
                     // Handle EOF on stdin (user closed input)
                     std::string byeMsg = createTcpsByeMessage(displayName);
                     if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                         perror("write BYE message");
                     }
                     running = false;
                     break;
                 }
             }
         }
 
         // Check state after processing events
         if (state == ClientState::TERMINATED) {
             printf_debug("Client entered TERMINATED state, breaking event loop");
             running = false;
             break;
         }
     }
     
     printf_debug("TCP client run() loop terminated, cleaning up");
     close(epoll_fd);
     return EXIT_SUCCESS;
 }