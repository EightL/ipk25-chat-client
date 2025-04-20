/**
 * @file client.cpp
 * @brief Implementation of the base Client class for the IPK25-CHAT protocol
 *
 * This file implements the base Client class, which has the core functionality for both
 * TCP and UDP clients, which they can build on. It handles user input processing,
 * message validation and state management.
 * 
 * @author xsevcim00
 */

#include "client.h"
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <netdb.h>
#include "debug.h"
#include <regex>

static constexpr size_t MAX_MSG_CONTENT = 60000;   // max message body size
static constexpr size_t MAX_DISPLAY_NAME = 20;     // max length for display name



// ===================================== Validation helper functions =================================== //

// Ceneric helper: checks length and regex match for various fields
bool validateString(const std::string& str, const std::regex& pattern, size_t maxLength) {
    // quick check: string shouldn't be too long and must match pattern
    return str.length() <= maxLength && std::regex_match(str, pattern);
}

// Global validation regex patterns
const std::regex ALPHANUMERIC_PATTERN("^[a-zA-Z0-9_-]+$");
const std::regex DISPLAYNAME_PATTERN("^[\x21-\x7E]+$");
const std::regex MESSAGE_PATTERN("^[\x0A\x20-\x7E]+$");

// check if username is valid (allowed chars, length <= 20)
bool isValidUsername(const std::string& username) {
    return validateString(username, ALPHANUMERIC_PATTERN, 20);
}

// Check if channel ID is valid (allowed chars, length <= 20)
bool isValidChannelID(const std::string& channelID) {
    return validateString(channelID, ALPHANUMERIC_PATTERN, 20);
}

// Check if secret is valid (allowed chars, length <= 128)
bool isValidSecret(const std::string& secret) {
    return validateString(secret, ALPHANUMERIC_PATTERN, 128);
}

// Check if display name is valid (printable ascii, length <= 20)
bool isValidDisplayName(const std::string& displayName) {
    return validateString(displayName, DISPLAYNAME_PATTERN, 20);
}

// Check if chat message content is valid (allowed chars, within size limit)
bool isValidMessageContent(const std::string& messageContent) {
    return validateString(messageContent, MESSAGE_PATTERN, MAX_MSG_CONTENT);
}

// ===================================== Client implementation ======================================== //

// Constructor: pick udp or tcp and start in INIT state
Client::Client(bool isUdpClient) : isUdp(isUdpClient) {
    state = ClientState::INIT;
}

// Destructor: close socket if it's still open
Client::~Client() {
    if (socketFd != -1) {
        close(socketFd);
        socketFd = -1;
    }
}

// Set client identity parameters (user, display) before auth
void Client::setIdentity(const std::string& user, const std::string& display) {
    username = user;
    displayName = display;
}

// Make a socket non-blocking so epoll/select won't hang
void Client::setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "error getting flags for fd " << fd << ": " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "error setting non-blocking mode for fd " << fd << ": " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
}

// Ensure incoming message fields don't exceed protocol limits
bool Client::validateInbound(const ParsedMessage& msg) const {
    switch (msg.type) {
        case MessageType::MSG:
            // heads-up: too-long names or content are invalid
            if (msg.param1.size() > MAX_DISPLAY_NAME) {
                printf_debug("Inbound MSG has display name too long: %zu bytes", msg.param1.size());
                return false;
            }
            if (msg.param2.size() > MAX_MSG_CONTENT) {
                printf_debug("Inbound MSG has content too long: %zu bytes", msg.param2.size());
                return false;
            }
            break;
        
        case MessageType::ERR:
            // err messages come with a source name and an error text
            if (msg.param1.size() > MAX_DISPLAY_NAME) {
                printf_debug("Inbound ERR has source name too long: %zu bytes", msg.param1.size());
                return false;
            }
            if (msg.param2.size() > MAX_MSG_CONTENT) {
                printf_debug("Inbound ERR has content too long: %zu bytes", msg.param2.size());
                return false;
            }
            break;

        case MessageType::REPLY:
            // replies only have a message body to check
            if (msg.param2.size() > MAX_MSG_CONTENT) {
                printf_debug("Inbound REPLY has content too long: %zu bytes", msg.param2.size());
                return false;
            }
            break;

        case MessageType::BYE:
            // bye just carries a display name
            if (msg.param1.size() > MAX_DISPLAY_NAME) {
                printf_debug("Inbound BYE has display name too long: %zu bytes", msg.param1.size());
                return false;
            }
            break;

        default:
            // all other types are fine
            break;
    }
    return true;
}

// Convert hostname to ipv4 addresses (or returns empty on error)
std::vector<std::string> Client::resolveHostname(const std::string& hostname) {
    addrinfo hints{}, *result;
    hints.ai_family   = AF_INET;       // just ipv4
    hints.ai_socktype = 0;             // tcp or udp
    hints.ai_flags    = AI_ADDRCONFIG; // skip unusable families

    int err = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (err) {
        std::cerr << "getaddrinfo: " << gai_strerror(err) << "\n";
        return {};
    }

    std::vector<std::string> addrs;
    for (auto rp = result; rp; rp = rp->ai_next) {
        auto* sa = reinterpret_cast<sockaddr_in*>(rp->ai_addr);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
        addrs.emplace_back(buf);
    }

    freeaddrinfo(result);
    return addrs;
}

// Handle the /auth command: parse args and send auth message
void Client::handleAuth(std::istringstream& iss) {
    if (state == ClientState::JOINED || state == ClientState::JOIN_WAITING) {
        std::cout << "ERROR: Already authenticated. Start a new client instance to authenticate with different credentials.\n";
        return;
    }

    // parse username, secret, displayName
    std::string u, s, d;
    iss >> u >> s >> d;
    if (u.empty() || s.empty() || d.empty()) {
        std::cout << "ERROR: Invalid authentication parameters\n";
        std::cout << "Usage: /auth <username> <secret> <displayName>\n";
        return;
    }

    // validate locally before sending
    if (!isValidUsername(u)) {
        std::cout << "ERROR: Invalid username. Must be max 20 characters and contain only [a-zA-Z0-9_-]\n";
        return;
    }
    if (!isValidSecret(s)) {
        std::cout << "ERROR: Secret truncated to 128 characters.\n";
        s = s.substr(0, 128);
    }
    if (!isValidDisplayName(d)) {
        std::cout << "ERROR: Invalid display name. Must be max 20 characters and contain only printable ASCII characters\n";
        return;
    }

    // stash credentials and switch to authenticating
    username = u;
    displayName = d;
    state = ClientState::AUTHENTICATING;

    // send auth; roll back on fail
    if (!authenticate(s)) {
        state = ClientState::INIT;
    }
}

// Handle the /join command: request to join a channel
void Client::handleJoin(std::istringstream& iss) {
    if (state != ClientState::JOINED) {
        std::cout << "ERROR: You must authenticate first.\n";
        return;
    }

    std::string channel;
    iss >> channel;
    if (channel.empty()) {
        std::cout << "ERROR: Channel name cannot be empty\n";
        std::cout << "Usage: /join <channel>\n";
        return;
    }
    if (!isValidChannelID(channel)) {
        std::cout << "ERROR: Invalid channel ID. Must be max 20 characters and contain only [a-zA-Z0-9_-]\n";
        return;
    }

    // remember channel and switch state
    channelID = channel;
    state = ClientState::JOIN_WAITING;

    // send join; back out if it fails
    if (!joinChannel(channel)) {
        state = ClientState::JOINED;
    }
}

// Handle the /rename command: change displayName locally
void Client::handleRename(std::istringstream& iss) {
    std::string d;
    iss >> d;
    if (d.empty()) {
        std::cout << "Usage: /rename <displayName>\n";
        return;
    }
    if (!isValidDisplayName(d)) {
        std::cout << "ERROR: Invalid display name. Must be max 20 characters and contain only printable ASCII characters\n";
        return;
    }
    // update name for future messages
    displayName = d;
    std::cout << "display name updated to: " << d << "\n";
}

// Show the friend-next-door list of commands
void Client::handleHelp() {
    std::cout << "available commands:\n"
                "  /auth <username> <secret> <displayName>\n"
                "  /join <channel>\n"
                "  /rename <displayName>\n"
                "  /bye\n"
                "  /help\n";
}

// Handle normal chat messages
void Client::handleChat(const std::string& message) {
    if (state != ClientState::JOINED) {
        // can't chat until we're in a channel
        std::cout << (state == ClientState::INIT ? "ERROR: You must authenticate first.\n" : "ERROR: You must join a channel before sending messages.\n");
        return;
    }

    // validate and maybe truncate
    if (!isValidMessageContent(message)) {
        std::cout << "ERROR: Message contains invalid characters. Only printable ASCII, spaces and line feeds allowed.\n";
        return;
    }
    const size_t MAX = MAX_MSG_CONTENT;
    std::string m = message.size() > MAX ? message.substr(0, MAX) : message;
    if (message.size() > MAX) {
        std::cout << "ERROR: Message truncated to " << MAX << " characters.\n";
    }

    // send it off
    sendChatMessage(m);
}

// Read user input, route slash-commands or chat
void Client::processUserInput(const std::string& input) {
    if (input.empty()) return;

    if (input[0] == '/') {
        std::istringstream iss(input.substr(1));
        std::string cmd;
        iss >> cmd;

        if (cmd == "auth") handleAuth(iss);
        else if (cmd == "join") handleJoin(iss);
        else if (cmd == "rename") handleRename(iss);
        else if (cmd == "bye")   sendByeMessage();
        else if (cmd == "help")  handleHelp();
        else {
            std::cout << "ERROR: Unknown command. Type /help for available commands.\n";
        }
    }
    else {
        // otherwise, just chat
        handleChat(input);
    }
}

// ===================================== State management ======================================== //

// Check if a received message type is allowed in the current state
bool Client::isValidTransition(MessageType msgType) {
    switch (state) {
    case ClientState::INIT:
    case ClientState::TERMINATED:
        // init or after end, nothing should come in
        return false;

    case ClientState::AUTHENTICATING:
        // during auth, expect only reply, err, or bye
        return msgType == MessageType::REPLY || msgType == MessageType::ERR || msgType == MessageType::BYE;

    case ClientState::JOINED:
    case ClientState::JOIN_WAITING:
        // once in a channel, chat, replies, errors, or bye
        return msgType == MessageType::MSG || msgType == MessageType::REPLY || msgType == MessageType::ERR || msgType == MessageType::BYE;
    }
    return false; // shouldn't reach here
}

// Process messages from server, update state or display
void Client::handleIncomingMessage(const ParsedMessage& msg) {
    // first, drop stuff that breaks size rules
    if (!validateInbound(msg)) {
        std::cout << "ERROR: Received message exceeds allowed length limits\n";
        sendProtocolError("Message exceeds allowed length limits");
        state = ClientState::TERMINATED;
        return;
    }

    // then dispatch based on message type
    switch (msg.type) {
        case MessageType::REPLY: {
            // show success/failure chatty text
            std::cout  << (msg.success ? "Action Success: " : "Action Failure: ") << msg.param2 << "\n";

            // if we were authenticating, move to joined on OK
            if (state == ClientState::AUTHENTICATING) {
                state = msg.success ? ClientState::JOINED : ClientState::INIT;
            }
            else if (state == ClientState::JOIN_WAITING) {
                state = ClientState::JOINED;
            }
            break;
        }

        case MessageType::MSG:
            // print incoming chat as friendlier format
            std::cout << msg.param1 << ": " << msg.param2 << "\n";
            break;

        case MessageType::ERR:
            // server sent an error, so we close
            std::cout << "ERROR FROM " << msg.param1 << ": " << msg.param2 << "\n";
            state = ClientState::TERMINATED;
            break;

        case MessageType::BYE:
            // server asked to end, say bye back
            std::cerr << "connection terminated by server.\n";
            state = ClientState::TERMINATED;
            break;

        case MessageType::PING:
            // ping, ignore it
            break;

        default:
            // anything else is unexpected
            std::cout << "ERROR: Received invalid message from server.\n";
            state = ClientState::TERMINATED;
            break;
    }
}


