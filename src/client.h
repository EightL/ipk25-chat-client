/**
 * @file client.h
 * @brief Abstract base class for IPK25-CHAT protocol clients
 *
 * This file defines the Client abstract base class that provides common
 * functionality for both TCP and UDP client implementations. It implements
 * the client state machine, common message handling, and user input processing.
 *
 * @author xsevcim00
 */

 #ifndef CLIENT_H
 #define CLIENT_H
 
 #include <string>
 #include <set>
 #include <sstream>
 #include <vector>
 #include "message.h"
 
 /**
  * @brief Client state machine states
  *
  * These states define the possible states of the client according to the
  * Finite State Machine (FSM) specification. The client transitions between
  * these states based on user actions and received messages.
  */
 enum class ClientState {
     INIT,           ///< Initial state (corresponds to "start" in FSM)
     AUTHENTICATING, ///< Authentication in progress (corresponds to "auth" in FSM)
     JOINED,         ///< Authentication successful, can send messages (corresponds to "open" in FSM)
     JOIN_WAITING,   ///< JOIN request sent, awaiting server response (corresponds to "join" in FSM) 
     TERMINATED      ///< Connection terminated (corresponds to "end" in FSM)
 };
 
 /**
  * @brief Abstract base class for IPK25-CHAT protocol clients
  *
  * The Client class provides a common interface and implementation for both
  * TCP and UDP client variants. It implements the state machine logic, common
  * input handling, and defines abstract methods that protocol-specific subclasses
  * must implement.
  */
 class Client {
 protected:
     // State and identification
     ClientState state = ClientState::INIT;  ///< Current client state
     std::string displayName;                ///< User's display name
     std::string username;                   ///< User's login name
     std::string channelID;                  ///< Current channel identifier
     
     // Connection details
     int socketFd = -1;                      ///< Socket file descriptor
     bool isUdp;                             ///< Whether this is a UDP client
     
     /**
      * @brief Sets a file descriptor to non-blocking mode
      *
      * Configures the specified file descriptor to use non-blocking I/O.
      * This is used for both the socket and stdin to enable epoll-based event handling.
      *
      * @param fd File descriptor to set to non-blocking mode
      */
     void setNonBlocking(int fd);
     
     /**
      * @brief Verifies if a message type is valid for the current state
      *
      * Implements state machine transition validation based on received message types.
      *
      * @param msgType The message type to validate
      * @return true if the message type is valid in the current state, false otherwise
      */
     bool isValidTransition(MessageType msgType);
     
     /**
      * @brief Processes an incoming message according to the state machine
      *
      * Handles state transitions based on received messages and updates client state.
      * This is a template method that can be extended by subclasses for protocol-specific behavior.
      *
      * @param msg The parsed message to process
      */
     virtual void handleIncomingMessage(const ParsedMessage& msg);
     
     /**
      * @brief Resolves a hostname to one or more IP addresses
      *
      * Resolves a hostname using DNS and returns the list of IP addresses.
      * For TCP, it automatically filters for valid IPv4 addresses on the specified port.
      *
      * @param hostname The hostname to resolve
      * @param isTcp Whether to use TCP-specific resolution
      * @param port The port number (used only for TCP)
      * @return A vector of resolved IP addresses as strings
      */
     std::vector<std::string> resolveHostname(const std::string& hostname, bool isTcp, int port = 0);
 
     /**
      * @brief Processes user input commands
      *
      * Parses and executes user commands based on the current client state.
      * This is a template method that delegates to protocol-specific implementations
      * for actions like authentication, joining channels, and sending messages.
      *
      * @param input The user input string to process
      */
     void processUserInput(const std::string& input);
     
     // Protocol-specific abstract methods to be implemented by subclasses
     
     /**
      * @brief Authenticates with the server
      *
      * Sends authentication credentials to the server and handles the authentication process.
      *
      * @param secret The authentication secret/password
      * @return true if authentication was initiated successfully, false on immediate failure
      */
     virtual bool authenticate(const std::string& secret) = 0;
     
     /**
      * @brief Requests to join a channel
      *
      * Sends a request to join the specified channel to the server.
      *
      * @param channelId The ID of the channel to join
      * @return true if the join request was sent successfully, false otherwise
      */
     virtual bool joinChannel(const std::string& channelId) = 0;
     
     /**
      * @brief Sends a chat message
      *
      * Transmits a text message to the current channel.
      *
      * @param message The message content to send
      * @return true if the message was sent successfully, false otherwise
      */
     virtual bool sendChatMessage(const std::string& message) = 0;
     
     /**
      * @brief Sends a disconnect message
      *
      * Sends a BYE message to the server to indicate a graceful disconnection.
      *
      * @return true if the disconnect message was sent successfully, false otherwise
      */
     virtual bool sendByeMessage() = 0;
     
 public:
     /**
      * @brief Constructor for the Client class
      *
      * Initializes basic client properties.
      *
      * @param isUdpClient Whether this client uses UDP (true) or TCP (false)
      */
     Client(bool isUdpClient);
     
     /**
      * @brief Virtual destructor
      *
      * Ensures proper cleanup of resources by derived classes.
      */
     virtual ~Client();
     
     /**
      * @brief Main client execution loop
      *
      * Implements the main client execution flow including connection setup,
      * event handling, and message processing. This method must be implemented
      * by protocol-specific subclasses.
      *
      * @return EXIT_SUCCESS on successful termination, EXIT_FAILURE on error
      */
     virtual int run() = 0;
     
     /**
      * @brief Sets the client's username and display name
      *
      * Configures the client's identity for authentication and messaging.
      *
      * @param user The username for authentication
      * @param display The display name for messages
      */
     void setIdentity(const std::string& user, const std::string& display);
 };
 
 #endif // CLIENT_H