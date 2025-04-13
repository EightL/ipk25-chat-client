/**
 * @file udp_client.h
 * @brief UDP-specific implementation of the Client interface for IPK25-CHAT
 *
 * This file defines the UDP client class that implements the Client interface
 * with connectionless UDP communication, reliable message delivery through
 * retransmissions, and message confirmation according to the IPK25-CHAT protocol.
 *
 * @author xsevcim00
 */

 #ifndef UDP_CLIENT_H
 #define UDP_CLIENT_H
 
 #include <netinet/in.h>
 #include <chrono>
 #include "client.h"
 
 /**
  * @brief UDP client implementation for the IPK25-CHAT protocol
  *
  * The UdpClient class provides UDP-specific implementation of the Client interface.
  * It handles reliability over the connectionless UDP protocol through message IDs,
  * retransmissions, and confirmation messages. It also manages dynamic server port
  * changes that may occur with UDP servers.
  */
 class UdpClient : public Client {
 private:
     std::string serverAddress;              ///< Server hostname or IP address
     int serverPort;                         ///< Server port number
     uint16_t timeoutMs;                     ///< Timeout for message retransmissions in milliseconds
     uint8_t maxRetransmissions;             ///< Maximum number of retransmission attempts
     
     uint16_t nextMsgId = 0;                 ///< Next message ID to use
     std::set<uint16_t> seenMsgIds;          ///< Set of already processed message IDs to avoid duplicates
     sockaddr_in serverAddr;                 ///< Server socket address structure
     
     std::chrono::steady_clock::time_point terminationStartTime; ///< Timestamp when graceful termination began
     bool isWaitingForTermination = false;   ///< Whether client is waiting for termination to complete
     
     /**
      * @brief Generates the next unique message ID
      *
      * @return Next sequential message ID
      */
     uint16_t getNextMsgId();
     
     /**
      * @brief Updates server address if response comes from a different port
      *
      * UDP servers may respond from a different port than the one initially used.
      * This method detects that and updates the stored server address.
      *
      * @param peerAddr The address from which a response was received
      */
     void checkAndUpdateServerPort(const sockaddr_in& peerAddr);
     
     /**
      * @brief Authenticates with retries and timeout handling
      *
      * Sends authentication request and handles the complete authentication flow
      * including retransmissions and waiting for the server's reply.
      *
      * @param secret The authentication secret
      * @return true if authentication succeeded, false otherwise
      */
     bool authenticateWithRetries(const std::string& secret);
     
     /**
      * @brief Sends a UDP message with optional reliability
      *
      * Sends a binary message over UDP, with optional confirmation requirement.
      * When confirmation is required, implements retransmission logic.
      *
      * @param msg The binary message to send
      * @param requireConfirm Whether to wait for confirmation (true by default)
      * @return true if message was sent successfully (and confirmed if required), false otherwise
      */
     bool sendUdpMessage(const std::vector<char>& msg, bool requireConfirm = true);
     
     /**
      * @brief Initiates graceful termination process
      *
      * Starts the process of cleanly disconnecting from the server,
      * setting up state and timers for BYE message transmission.
      */
     void startGracefulTermination();
     
 protected:
     /**
      * @brief Handles incoming UDP messages
      *
      * Processes received messages according to protocol specification, with
      * UDP-specific behavior like handling CONFIRM messages and tracking message IDs.
      *
      * @param msg The parsed message to handle
      */
     virtual void handleIncomingMessage(const ParsedMessage& msg) override;
     
     /**
      * @brief Implements UDP-specific authentication
      *
      * @param secret The authentication secret
      * @return true if authentication was initiated successfully, false otherwise
      */
     virtual bool authenticate(const std::string& secret) override;
     
     /**
      * @brief Implements UDP-specific channel join request
      *
      * @param channelId The ID of the channel to join
      * @return true if the join request was sent successfully, false otherwise
      */
     virtual bool joinChannel(const std::string& channelId) override;
     
     /**
      * @brief Implements UDP-specific chat message transmission
      *
      * @param message The message content to send
      * @return true if the message was sent successfully, false otherwise
      */
     virtual bool sendChatMessage(const std::string& message) override;
     
     /**
      * @brief Implements UDP-specific disconnect message
      *
      * @return true if the BYE message was sent and confirmed, false otherwise
      */
     virtual bool sendByeMessage() override;
     
 public:
     /**
      * @brief Constructs a UDP client
      *
      * @param serverIp Server hostname or IP address
      * @param port Server port number
      * @param timeout Timeout between retransmissions in milliseconds
      * @param retransmissions Maximum number of retransmission attempts
      */
     UdpClient(const std::string& serverIp, int port, 
               uint16_t timeout, uint8_t retransmissions);
     
     /**
      * @brief Destructor for UDP client
      *
      * Cleans up any resources not handled by the base class destructor.
      */
     virtual ~UdpClient();
     
     /**
      * @brief Main execution loop for the UDP client
      *
      * Sets up the UDP socket, handles events, processes messages,
      * and implements the event-driven client logic.
      *
      * @return EXIT_SUCCESS on successful termination, EXIT_FAILURE on error
      */
     virtual int run() override;
 };
 
 #endif // UDP_CLIENT_H