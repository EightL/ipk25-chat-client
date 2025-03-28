#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

// Helper: set a file descriptor to non-blocking mode
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        perror("fcntl(F_SETFL)");
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port>\n";
        return EXIT_FAILURE;
    }
    
    const char* server_ip = argv[1];
    int server_port = std::atoi(argv[2]);

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    
    // Set the socket to non-blocking mode
    if (set_nonblocking(sockfd) < 0) {
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Prepare the server address structure
    sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP: " << server_ip << "\n";
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Initiate non-blocking connection (might return -1 with EINPROGRESS)
    int ret = connect(sockfd, (sockaddr*)&server_addr, sizeof(server_addr));
    if (ret < 0 && errno != EINPROGRESS) {
        perror("connect");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Create an epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // Register the socket with epoll for reading and writing (edge-triggered)
    epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = sockfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        perror("epoll_ctl: sockfd");
        close(sockfd);
        close(epoll_fd);
        return EXIT_FAILURE;
    }
    
    // Also register STDIN (fd 0) to read user input
    ev.events = EPOLLIN;
    ev.data.fd = STDIN_FILENO;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0) {
        perror("epoll_ctl: STDIN");
        close(sockfd);
        close(epoll_fd);
        return EXIT_FAILURE;
    }
    
    const int MAX_EVENTS = 10;
    epoll_event events[MAX_EVENTS];
    bool running = true;
    char buffer[1024];
    
    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }
        
        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;
            if (fd == sockfd) {
                // Handle events on the network socket
                if (events[i].events & EPOLLIN) {
                    // Data available to read from server
                    while (true) {
                        ssize_t count = read(sockfd, buffer, sizeof(buffer) - 1);
                        if (count == -1) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                                break;
                            perror("read from socket");
                            running = false;
                            break;
                        } else if (count == 0) {
                            std::cout << "Server closed the connection.\n";
                            running = false;
                            break;
                        }
                        buffer[count] = '\0';
                        std::cout << "Received: " << buffer;
                    }
                }
                if (events[i].events & EPOLLOUT) {
                    // Socket ready for writing: check connection completion for non-blocking connect
                    int err = 0;
                    socklen_t len = sizeof(err);
                    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                        perror("getsockopt");
                        running = false;
                    }
                    if (err != 0) {
                        std::cerr << "Connection error: " << strerror(err) << "\n";
                        running = false;
                    }
                    // Once connected, disable EPOLLOUT to avoid unnecessary notifications
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.fd = sockfd;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sockfd, &ev) < 0) {
                        perror("epoll_ctl: modify sockfd");
                        running = false;
                    }
                }
            } else if (fd == STDIN_FILENO) {
                // Handle user input from stdin
                ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
                if (count <= 0) {
                    running = false;
                    break;
                }
                buffer[count] = '\0';
                // Send the input to the server
                ssize_t sent = write(sockfd, buffer, count);
                if (sent < 0) {
                    perror("write to socket");
                    running = false;
                }
            }
        }
    }
    
    close(sockfd);
    close(epoll_fd);
    return EXIT_SUCCESS;
}
