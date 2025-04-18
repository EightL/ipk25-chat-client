/**
 * @file tcp_client.h
 * @brief TCP-specific implementation of the Client interface for IPK25-CHAT
 *
 * Defines TcpClient for connection-oriented TCP communication with the
 * IPK25-CHAT protocol, using non-blocking I/O and epoll for event handling.
 *
 * @author xsevcim00
 */
#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <chrono>
#include "client.h"

/**
 * @brief TCP client implementation for the IPK25-CHAT protocol
 *
 * Handles connection establishment, text-based framing (CRLF‑terminated messages),
 * reliable delivery via built‑in TCP mechanisms, and an event‑driven loop.
 */
class TcpClient : public Client {
private:
    // server connection parameters
    std::string serverAddress; // server hostname or IP address
    int serverPort; // server port number

    // graceful shutdown tracking
    std::chrono::steady_clock::time_point terminationStartTime;
    bool isWaitingForTermination = false; // waiting for BYE to confirm

    // reply timeout tracking
    bool waitingForReply = false;  // awaiting REPLY from server
    std::chrono::steady_clock::time_point replyDeadline; // when REPLY deadline expires

    /**
     * @brief Send a raw string over the TCP socket
     * @param msg The complete message (including "\r\n")
     * @return true if write succeeded, false on error
     */
    bool sendMessage(const std::string& msg);

    /**
     * @brief Read available socket data, extract complete CRLF‑terminated messages
     * @param buffer Accumulates partial reads between calls
     */
    void processSocketInput(std::string& buffer);

protected:
    /**
     * @brief Handle a parsed incoming message
     * @param msg The ParsedMessage to process
     */
    virtual void handleIncomingMessage(const ParsedMessage& msg) override;

    /**
     * @brief Send AUTH request to the server
     * @param secret The authentication secret
     * @return true if AUTH was sent and timeout started
     */
    virtual bool authenticate(const std::string& secret) override;

    /**
     * @brief Send JOIN request to the server
     * @param channelId Identifier of the channel to join
     * @return true if JOIN was sent and timeout started
     */
    virtual bool joinChannel(const std::string& channelId) override;

    /**
     * @brief Send a chat message
     * @param message The message content to send
     * @return true if MSG was sent successfully
     */
    virtual bool sendChatMessage(const std::string& message) override;

    /**
     * @brief Send a BYE message and mark termination
     * @return true if BYE was sent successfully
     */
    virtual bool sendByeMessage() override;

    /**
     * @brief Send a protocol error message
     * @param errorMessage Description of the error
     */
    virtual void sendProtocolError(const std::string& errorMessage) override;

public:
    /**
     * @brief Construct a TCP client instance
     * @param serverIp Hostname or IP address of the server
     * @param port TCP port to connect to
     */
    TcpClient(const std::string& serverIp, int port);

    /**
     * @brief Destructor for TcpClient
     *
     * Cleans up any resources not handled by base destructor.
     */
    virtual ~TcpClient();

    /**
     * @brief Run the TCP client's main event loop
     *
     * Resolves the server address, connects, sets up epoll on socket and stdin,
     * and dispatches events until termination.
     *
     * @return EXIT_SUCCESS on clean termination, EXIT_FAILURE on error
     */
    virtual int run() override;
};

#endif // TCP_CLIENT_H
