/**
 * @file tcp_client.h
 * @brief TCP-specific implementation of the Client interface for IPK25-CHAT
 *
 * This file defines the TCP client class that implements the Client interface
 * with connection-oriented TCP communication according to the IPK25-CHAT protocol.
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
  * The TcpClient class provides TCP-specific implementation of the Client interface.
  * It handles connection establishment, text-based protocol communication, and
  * reliable message delivery through the built-in TCP reliability mechanisms.
  */
 class TcpClient : public Client {
 private:
     std::string serverAddress;              ///< Server hostname or IP address
     int serverPort;                         ///< Server port number
     std::chrono::steady_clock::time_point terminationStartTime; ///< Timestamp when graceful termination began
     bool isWaitingForTermination = false;   ///< Whether client is waiting for termination to complete
     bool waitingForReply = false;           ///< Whether client is waiting for a server reply
     std::chrono::steady_clock::time_point replyDeadline; ///< Deadline for receiving a reply
     
     /**
      * @brief Sends a text message to the server
      *
      * Transmits a message over the established TCP connection.
      *
      * @param msg The text message to send
      * @return true if the message was sent successfully, false otherwise
      */
     bool sendMessage(const std::string& msg);
     
 protected:
     /**
      * @brief Handles incoming TCP messages
      *
      * Processes received messages according to protocol specification,
      * with TCP-specific behavior like handling malformed messages.
      *
      * @param msg The parsed message to handle
      */
     virtual void handleIncomingMessage(const ParsedMessage& msg) override;
     
     /**
      * @brief Implements TCP-specific authentication
      *
      * @param secret The authentication secret
      * @return true if authentication was initiated successfully, false otherwise
      */
     virtual bool authenticate(const std::string& secret) override;
     
     /**
      * @brief Implements TCP-specific channel join request
      *
      * @param channelId The ID of the channel to join
      * @return true if the join request was sent successfully, false otherwise
      */
     virtual bool joinChannel(const std::string& channelId) override;
     
     /**
      * @brief Implements TCP-specific chat message transmission
      *
      * @param message The message content to send
      * @return true if the message was sent successfully, false otherwise
      */
     virtual bool sendChatMessage(const std::string& message) override;
     
     /**
      * @brief Implements TCP-specific disconnect message
      *
      * @return true if the BYE message was sent successfully, false otherwise
      */
     virtual bool sendByeMessage() override;

     /**
      * @brief Sends a protocol error message to the server
      *
      * Transmits an error message over the established TCP connection.
      *
      * @param errorMessage The error message to send
      */
     virtual void sendProtocolError(const std::string& errorMessage) override;
     
 public:
     /**
      * @brief Constructs a TCP client
      *
      * @param serverIp Server hostname or IP address
      * @param port Server port number
      */
     TcpClient(const std::string& serverIp, int port);
     
     /**
      * @brief Destructor for TCP client
      *
      * Cleans up any resources not handled by the base class destructor.
      */
     virtual ~TcpClient();
     
     /**
      * @brief Main execution loop for the TCP client
      *
      * Sets up the TCP connection, handles events, processes messages,
      * and implements the event-driven client logic.
      *
      * @return EXIT_SUCCESS on successful termination, EXIT_FAILURE on error
      */
     virtual int run() override;
 };
 
 #endif // TCP_CLIENT_H