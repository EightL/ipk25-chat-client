/**
 * @file udp_client.h
 * @brief UDP-specific implementation of the Client interface for IPK25-CHAT
 *
 * Defines UdpClient for connectionless UDP communication with reliable
 * delivery, retransmissions, and dynamic server port handling.
 *
 * @author xsevcim00
 */
#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include <netinet/in.h>
#include <chrono>
#include <unordered_set>
#include "client.h"

class UdpClient : public Client {
    private:
        std::string serverAddress;               // server hostname or IP
        int         serverPort;                  // UDP port number
        uint16_t    timeoutMs;                   // per-message timeout (ms)
        uint8_t     maxRetransmissions;          // maximum retry count
        uint16_t    nextMsgId = 1;               // next unique message ID
        int         epollFd     = -1;            // epoll file descriptor
        sockaddr_in serverAddr{};                // resolved server address
        bool        fatalError  = false;         // indicates a fatal error
        std::unordered_set<uint16_t> seenMsgIds; // processed message IDs

        /**
         * @brief Generate the next unique message ID
         * @return next message ID
         */
        uint16_t getNextMsgId();

        /**
         * @brief Update server port if peer port has changed
         * @param peerAddr peer sockaddr_in from recvfrom
         */
        void checkAndUpdateServerPort(const sockaddr_in& peerAddr);

        /**
         * @brief Send a UDP message, optionally requiring confirmation
         * @param msg byte vector containing the packet
         * @param requireConfirm true to wait for a CONFIRM response
         * @return true if send (and confirm if required) succeeded
         */
        bool sendUdpMessage(const std::vector<char>& msg, bool requireConfirm);

        /**
         * @brief Wait for a REPLY matching the expected message ID
         * @param expectedRefId reference ID to match in incoming REPLY
         * @return true if a positive REPLY was received
         */
        bool awaitReply(uint16_t expectedRefId);

        /**
         * @brief Handle available stdin data in the event loop
         * @param buf buffer to accumulate and parse input lines
         * @return EXIT_SUCCESS on normal processing, EXIT_FAILURE on error
         */
        int handleStdinEvent(std::string& buf);

        /**
         * @brief Handle an incoming UDP packet event
         * @param buf buffer to receive packet data
         */
        void handleSocketEvent(char* buf);

        /**
         * @brief Initialize UDP socket, bind and resolve server address
         * @return true on successful socket setup
         */
        bool initSocket();

        /**
         * @brief Configure epoll to watch socket and stdin
         * @return true if epoll setup succeeded
         */
        bool setupEpoll();

        /**
         * @brief Run the epoll-based event loop
         * @return EXIT_SUCCESS on clean exit, EXIT_FAILURE on error
         */
        int eventLoop();

        /**
         * @brief Send a CONFIRM message for a received packet
         * @param msgId message ID to confirm
         */
        void sendConfirm(uint16_t msgId);

        /**
         * @brief Check if a message ID has already been processed
         * @param msgId message ID to check
         * @return true if the ID was seen before
         */
        bool isDuplicate(uint16_t msgId);

        /**
         * @brief Send a BYE message and wait for its CONFIRM
         */
        void sendByeAndWaitConfirm();

        /**
         * @brief Clean up resources and close socket
         */
        void cleanup();

    protected:
        /**
         * @brief Handle parsed incoming UDP messages
         * @param msg the ParsedMessage to process
         */
        virtual void handleIncomingMessage(const ParsedMessage& msg) override;

        /**
         * @brief Perform UDP-specific authentication
         * @param secret authentication secret
         * @return true if AUTH succeeded
         */
        virtual bool authenticate(const std::string& secret) override;

        /**
         * @brief Perform UDP-specific channel join
         * @param channelId identifier of channel to join
         * @return true if JOIN succeeded
         */
        virtual bool joinChannel(const std::string& channelId) override;

        /**
         * @brief Send a chat message over UDP
         * @param message content to send
         * @return true if MSG succeeded
         */
        virtual bool sendChatMessage(const std::string& message) override;

        /**
         * @brief Send BYE message over UDP
         * @return true if BYE succeeded
         */
        virtual bool sendByeMessage() override;

        /**
         * @brief Send a protocol ERR message without confirmation
         * @param err error text to send
         */
        virtual void sendProtocolError(const std::string& err) override;

    public:
        /**
         * @brief Construct a UDP client
         * @param serverIp server hostname or IP
         * @param port server UDP port
         * @param timeout per-message confirmation timeout (ms)
         * @param retransmissions max number of retries per message
         */
        UdpClient(const std::string& serverIp, int port, uint16_t timeout, uint8_t retransmissions);

        /**
         * @brief Destructor for UDP client
         */
        virtual ~UdpClient();

        /**
         * @brief Run the UDP client: init, event loop, cleanup
         * @return EXIT_SUCCESS on success, EXIT_FAILURE on error
         */
        virtual int run() override;
};

#endif // UDP_CLIENT_H
