#include <iostream>
#include <cstring>
#include <cstdlib>
#include <getopt.h>
#include <stdexcept>
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>

// --- Helper: Extract VPN IP from a given interface (default "tun0") ---
std::string get_vpn_ip(const std::string &iface = "tun0") {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    std::string result;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET && iface == ifa->ifa_name) {
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                std::cerr << "getnameinfo() failed: " << gai_strerror(s) << std::endl;
                continue;
            }
            result = host;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return result;
}

// --- Message protocol definitions ---

enum class MessageType {
    AUTH,
    JOIN,
    MSG,
    BYE,
    REPLY,
    ERR,
    UNKNOWN
};

bool resolveHostname(const std::string& hostname, struct sockaddr_in* addr) {
    struct addrinfo hints, *results, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      
    hints.ai_socktype = SOCK_STREAM; 
    
    int status = getaddrinfo(hostname.c_str(), NULL, &hints, &results);
    if (status != 0) {
        std::cerr << "Failed to resolve hostname: " << hostname << ": " 
                  << gai_strerror(status) << std::endl;
        return false;
    }
    
    for (result = results; result != NULL; result = result->ai_next) {
        if (result->ai_family == AF_INET) {
            memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
            freeaddrinfo(results);
            return true;
        }
    }
    
    freeaddrinfo(results);
    std::cerr << "No IPv4 address found for hostname: " << hostname << std::endl;
    return false;
}

MessageType stringToMessageType(const std::string& token) {
    if (token == "AUTH") return MessageType::AUTH;
    if (token == "JOIN") return MessageType::JOIN;
    if (token == "MSG")  return MessageType::MSG;
    if (token == "BYE")  return MessageType::BYE;
    if (token == "REPLY") return MessageType::REPLY;
    if (token == "ERR")  return MessageType::ERR;
    return MessageType::UNKNOWN;
}

struct ParsedMessage {
    MessageType type = MessageType::UNKNOWN;
    std::string param1;
    std::string param2;
    std::string param3;
};

std::string serializeAuth(const std::string& username, const std::string& displayName, const std::string& secret) {
    return "AUTH " + username + " AS " + displayName + " USING " + secret + "\r\n";
}

std::string serializeJoin(const std::string& channelID, const std::string& displayName) {
    return "JOIN " + channelID + " AS " + displayName + "\r\n";
}

std::string serializeMsg(const std::string& displayName, const std::string& messageContent) {
    return "MSG FROM " + displayName + " IS " + messageContent + "\r\n";
}

std::string serializeBye(const std::string& displayName) {
    return "BYE FROM " + displayName + "\r\n";
}

ParsedMessage parseMessage(const std::string& raw) {
    ParsedMessage msg;
    std::istringstream iss(raw);
    std::string token;
    
    iss >> token;
    msg.type = stringToMessageType(token);
    
    switch (msg.type) {
        case MessageType::AUTH:
            iss >> msg.param1;          
            iss >> token;               
            iss >> msg.param2;          
            iss >> token;               
            std::getline(iss, msg.param3);
            msg.param3.erase(msg.param3.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::JOIN:
            iss >> msg.param1;          
            iss >> token;               
            iss >> msg.param2;          
            break;
        case MessageType::MSG:
            iss >> token;               
            iss >> msg.param1;          
            iss >> token;               
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::BYE:
            iss >> token;               
            iss >> msg.param1;          
            break;
        case MessageType::REPLY:
            iss >> token;               
            msg.param1 = token;
            iss >> token;               
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::ERR:
            iss >> token;               
            iss >> msg.param1;          
            iss >> token;               
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        default:
            break;
    }
    return msg;
}

enum class ClientState {
    INIT,
    AUTHENTICATED,
    JOINED,
    TERMINATED
};

struct ClientContext {
    ClientState state = ClientState::INIT;
    std::string displayName;
    std::string username;
    std::string channelID;
};

void handleIncomingMessage(const ParsedMessage& msg, ClientContext& ctx) {
    switch (msg.type) {
        case MessageType::REPLY:
            if (msg.param1 == "OK") {
                std::cout << "Action Success: " << msg.param2 << "\n";
                if (ctx.state == ClientState::INIT)
                    ctx.state = ClientState::AUTHENTICATED;
                else if (ctx.state == ClientState::AUTHENTICATED)
                    ctx.state = ClientState::JOINED;
            } else {
                std::cout << "Action Failure: " << msg.param2 << "\n";
            }
            break;
        case MessageType::MSG:
            std::cout << msg.param1 << ": " << msg.param2 << "\n";
            break;
        case MessageType::ERR:
            std::cout << "ERROR FROM " << msg.param1 << ": " << msg.param2 << "\n";
            ctx.state = ClientState::TERMINATED;
            break;
        case MessageType::BYE:
            std::cout << "Connection terminated by server.\n";
            ctx.state = ClientState::TERMINATED;
            break;
        default:
            std::cout << "Received unknown or unhandled message type.\n";
            break;
    }
}

struct ProgramArgs {
    std::string transport_protocol;  
    std::string server_address;      
    uint16_t server_port = 4567;     
    uint16_t udp_timeout = 250;      
    uint8_t udp_retransmissions = 3; 
};

void printHelp(const char* programName) {
    std::cerr << "Usage: " << programName << " -t PROTOCOL -s SERVER [-p PORT] [-d TIMEOUT] [-r RETRANSMIT] [-h]" << std::endl;
    std::cerr << "\nIPK25-CHAT client application\n" << std::endl;
    std::cerr << "Required arguments:" << std::endl;
    std::cerr << "  -t PROTOCOL       Transport protocol, either 'tcp' or 'udp'" << std::endl;
    std::cerr << "  -s SERVER         Server IP address or hostname" << std::endl;
    std::cerr << "\nOptional arguments:" << std::endl;
    std::cerr << "  -p PORT           Server port (default: 4567)" << std::endl;
    std::cerr << "  -d TIMEOUT        UDP confirmation timeout in milliseconds (default: 250)" << std::endl;
    std::cerr << "  -r RETRANSMIT     Maximum number of UDP retransmissions (default: 3)" << std::endl;
    std::cerr << "  -h                Display this help message and exit" << std::endl;
}

ProgramArgs parseArgs(int argc, char* argv[]) {
    ProgramArgs args;
    bool t_provided = false;
    bool s_provided = false;
    int opt;
    while ((opt = getopt(argc, argv, "t:s:p:d:r:h")) != -1) {
        switch (opt) {
            case 't':
                args.transport_protocol = optarg;
                t_provided = true;
                break;
            case 's':
                args.server_address = optarg;
                s_provided = true;
                break;
            case 'p': {
                try {
                    int port = std::stoi(optarg);
                    if (port <= 0 || port > 65535)
                        throw std::range_error("Port must be between 1 and 65535");
                    args.server_port = static_cast<uint16_t>(port);
                } catch (const std::exception& e) {
                    throw std::runtime_error("Error: Invalid port number");
                }
                break;
            }
            case 'd':
                args.udp_timeout = static_cast<uint16_t>(std::stoi(optarg));
                break;
            case 'r':
                args.udp_retransmissions = static_cast<uint8_t>(std::stoi(optarg));
                break;
            case 'h':
                printHelp(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            default:
                printHelp(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!t_provided)
        throw std::runtime_error("Error: Transport protocol (-t) must be specified");
    if (!s_provided)
        throw std::runtime_error("Error: Server address (-s) must be specified");
    if (args.transport_protocol != "tcp" && args.transport_protocol != "udp")
        throw std::runtime_error("Error: Transport protocol (-t) must be either 'tcp' or 'udp'");
    return args;
}

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

// TCP Client implementation with message protocol integration
int run_tcp_client(const std::string& server_ip, int server_port) {
    // Initialize client context
    ClientContext ctx;
    std::cout << "Enter username: ";
    std::getline(std::cin, ctx.username);
    std::cout << "Enter display name: ";
    std::getline(std::cin, ctx.displayName);
    std::string secret;
    std::cout << "Enter secret: ";
    std::getline(std::cin, secret);
    
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
    
    // Automatically extract VPN IP from interface "tun0"
    std::string vpn_ip = get_vpn_ip("tun0");
    if (vpn_ip.empty()) {
        std::cerr << "No VPN IP found on interface tun0. Using default binding." << std::endl;
    } else {
        std::cout << "Automatically detected VPN IP: " << vpn_ip << std::endl;
        sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = 0; // OS selects ephemeral port
        if (inet_pton(AF_INET, vpn_ip.c_str(), &local_addr.sin_addr) <= 0) {
            perror("inet_pton (local bind IP)");
            close(sockfd);
            return EXIT_FAILURE;
        }
        if (bind(sockfd, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
            perror("bind (local VPN IP)");
            close(sockfd);
            return EXIT_FAILURE;
        }
    }
    
    // Prepare the server address structure
    sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) > 0) {
        std::cout << "Using direct IP address" << std::endl;
    } else if (!resolveHostname(server_ip, &server_addr)) {
        std::cerr << "Could not resolve server address: " << server_ip << std::endl;
        close(sockfd);
        return EXIT_FAILURE;
    } else {
        std::cout << "Successfully resolved hostname" << std::endl;
    }
    
    std::cout << "Connecting to " << server_ip << " (" 
              << inet_ntoa(server_addr.sin_addr) << "):" << server_port << std::endl;
    
    int ret = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
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
    
    epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = sockfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        perror("epoll_ctl: sockfd");
        close(sockfd);
        close(epoll_fd);
        return EXIT_FAILURE;
    }
    
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
    bool connected = false;
    bool auth_sent = false;
    
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
                if (events[i].events & EPOLLIN) {
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
                        std::string received(buffer, count);
                        ParsedMessage msg = parseMessage(received);
                        handleIncomingMessage(msg, ctx);
                        if (ctx.state == ClientState::TERMINATED) {
                            running = false;
                            break;
                        }
                    }
                }
                if (events[i].events & EPOLLOUT) {
                    if (!connected) {
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
                        if (!auth_sent) {
                            std::string authMsg = serializeAuth(ctx.username, ctx.displayName, secret);
                            if (write(sockfd, authMsg.c_str(), authMsg.length()) < 0) {
                                perror("write AUTH message");
                                running = false;
                            }
                            auth_sent = true;
                        }
                        connected = true;
                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.fd = sockfd;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sockfd, &ev) < 0) {
                            perror("epoll_ctl: modify sockfd");
                            running = false;
                        }
                    }
                }
            } else if (fd == STDIN_FILENO) {
                std::string input;
                if (!std::getline(std::cin, input)) {
                    running = false;
                    break;
                }
                if (input.empty()) continue;
                if (input[0] == '/') {
                    std::istringstream iss(input.substr(1));
                    std::string cmd;
                    iss >> cmd;
                    if (cmd == "join" && ctx.state == ClientState::AUTHENTICATED) {
                        std::string channelID;
                        iss >> channelID;
                        if (!channelID.empty()) {
                            ctx.channelID = channelID;
                            std::string joinMsg = serializeJoin(channelID, ctx.displayName);
                            if (write(sockfd, joinMsg.c_str(), joinMsg.length()) < 0) {
                                perror("write JOIN message");
                                running = false;
                            }
                        }
                    } else if (cmd == "bye") {
                        std::string byeMsg = serializeBye(ctx.displayName);
                        if (write(sockfd, byeMsg.c_str(), byeMsg.length()) < 0) {
                            perror("write BYE message");
                        }
                        running = false;
                    } else if (cmd == "help") {
                        std::cout << "Available commands:\n";
                        std::cout << "  /join <channel> - Join a channel\n";
                        std::cout << "  /bye - Disconnect from server\n";
                        std::cout << "  /help - Show this help\n";
                    } else {
                        std::cout << "Unknown command. Type /help for available commands.\n";
                    }
                } else if (ctx.state == ClientState::JOINED) {
                    std::string msgContent = serializeMsg(ctx.displayName, input);
                    if (write(sockfd, msgContent.c_str(), msgContent.length()) < 0) {
                        perror("write MSG message");
                        running = false;
                    }
                } else {
                    std::cout << "You must join a channel before sending messages.\n";
                    std::cout << "Use /join <channel> to join a channel.\n";
                }
            }
        }
    }
    
    close(sockfd);
    close(epoll_fd);
    return EXIT_SUCCESS;
}

int run_udp_client(const std::string& server_ip, int server_port, 
                   uint16_t timeout, uint8_t retransmissions) {
    std::cout << "UDP client not yet implemented. Using server: " << server_ip 
              << ":" << server_port << " with timeout: " << timeout 
              << "ms and " << (int)retransmissions << " retransmissions." << std::endl;
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    try {
        ProgramArgs args = parseArgs(argc, argv);
        std::cout << "Transport protocol: " << args.transport_protocol << std::endl;
        std::cout << "Server address: " << args.server_address << std::endl;
        std::cout << "Server port: " << args.server_port << std::endl;
        if (args.transport_protocol == "udp") {
            std::cout << "UDP timeout: " << args.udp_timeout << " ms" << std::endl;
            std::cout << "UDP retransmissions: " << (int)args.udp_retransmissions << std::endl;
            return run_udp_client(args.server_address, args.server_port, 
                                  args.udp_timeout, args.udp_retransmissions);
        } else {
            return run_tcp_client(args.server_address, args.server_port);
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
