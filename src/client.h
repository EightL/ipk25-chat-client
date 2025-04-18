/**
 * @file client.h
 * @brief Base class for IPK25-CHAT protocol clients (TCP and UDP)
 *
 * This file sets up the basics for our chat client.
 * It handles simple user commands (/auth, /join, /rename, /help), does message checking, and keeps track of state.
 *
 * Author: xsevcim00
 */
#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <sstream>
#include <vector>
#include "message.h"

// FSM states for client
enum class ClientState {
    INIT,                // before any action
    AUTHENTICATING,      // sent credentials, awaiting REPLY
    JOIN_WAITING,        // sent join, awaiting REPLY
    JOINED,              // in channel
    TERMINATED           // connection closed or error
};

/**
 * @brief Core interface for chat clients over TCP or UDP
 *
 * Maintains session state, processes input/output, and enforces
 * protocol rules defined by IPK25-CHAT.
 */
class Client {
protected:
    ClientState state = ClientState::INIT;  // current state
    std::string displayName; 
    std::string username; 
    std::string channelID; 

    int  socketFd; // socket descriptor
    bool isUdp; // true for UDP, false for TCP

    /**
     * @brief Configure a descriptor for non-blocking I/O
     * @param fd file descriptor to set
     */
    void setNonBlocking(int fd);

    /**
     * @brief Check inbound message fits length/content rules
     * @param msg parsed message to validate
     * @return true if valid
     */
    bool validateInbound(const ParsedMessage& msg) const;

    /**
     * @brief Verify if a message type is allowed now
     * @param msgType type to check
     * @return true if transition permitted
     */
    bool isValidTransition(MessageType msgType);

    /**
     * @brief Handle messages received from server
     * @param msg parsed server message
     */
    virtual void handleIncomingMessage(const ParsedMessage& msg);

    /**
     * @brief Resolve a hostname to IPv4 addresses
     * @param hostname name or IP string
     * @return list of IPv4 addresses
     */
    std::vector<std::string> resolveHostname(const std::string& hostname);

    /**
     * @brief Dispatch raw stdin input as commands or chat
     * @param input raw line (no newline)
     */
    void processUserInput(const std::string& input);

    // command handlers
    /**
     * @brief Parse and execute /auth command
     * @param iss stream of parameters
     */
    void handleAuth(std::istringstream& iss);

    /**
     * @brief Parse and execute /join command
     * @param iss stream of parameters
     */
    void handleJoin(std::istringstream& iss);

    /**
     * @brief Parse and execute /rename command
     * @param iss stream of parameters
     */
    void handleRename(std::istringstream& iss);

    /**
     * @brief Show available commands
     */
    void handleHelp();

    /**
     * @brief Send plain text as a chat MSG
     * @param message chat content
     */
    void handleChat(const std::string& message);

    // network operations (TCP/UDP specific)
    /**
     * @brief Send AUTH request
     * @param secret authentication token
     * @return true if dispatch succeeded
     */
    virtual bool authenticate(const std::string& secret) = 0;

    /**
     * @brief Send JOIN request
     * @param channelId channel name
     * @return true if dispatch succeeded
     */
    virtual bool joinChannel(const std::string& channelId) = 0;

    /**
     * @brief Send chat MSG
     * @param message content to send
     * @return true if dispatch succeeded
     */
    virtual bool sendChatMessage(const std::string& message) = 0;

    /**
     * @brief Send BYE to terminate session
     * @return true if dispatch succeeded
     */
    virtual bool sendByeMessage() = 0;

    /**
     * @brief Send protocol ERR to server
     * @param errorMessage description of error
     */
    virtual void sendProtocolError(const std::string& errorMessage) = 0;

public:
    /**
     * @brief Construct a client specifying transport mode
     * @param isUdpClient true for UDP, false for TCP
     */
    Client(bool isUdpClient);

    /**
     * @brief Destructor closes socket if open
     */
    virtual ~Client();

    /**
     * @brief Run the client: connect, loop, cleanup
     * @return EXIT_SUCCESS or EXIT_FAILURE
     */
    virtual int run() = 0;

    /**
     * @brief Set user identity for auth
     * @param user login name
     * @param display friendly display name
     */
    void setIdentity(const std::string& user, const std::string& display);
};

#endif // CLIENT_H
