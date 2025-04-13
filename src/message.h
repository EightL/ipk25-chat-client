/**
 * @file message.h
 * @brief Message types and utilities for the IPK25-CHAT protocol
 *
 * This file defines the message types, constants, and functions for creating
 * and parsing protocol messages in both TCP (text-based) and UDP (binary) formats.
 *
 * @author xsevcim00
 */

 #ifndef MESSAGE_H
 #define MESSAGE_H
 
 #include <string>
 #include <vector>
 #include <cstdint>
 
 /**
  * @brief Message type constants for UDP binary protocol
  * 
  * These constants define the binary type values used in the UDP version
  * of the IPK25-CHAT protocol as the first byte of each message.
  */
 const uint8_t AUTH_TYPE    = 0x02;  ///< Authentication request
 const uint8_t CONFIRM_TYPE = 0x00;  ///< Message confirmation
 const uint8_t REPLY_TYPE   = 0x01;  ///< Server reply
 const uint8_t JOIN_TYPE    = 0x03;  ///< Channel join request
 const uint8_t MSG_TYPE     = 0x04;  ///< Chat message
 const uint8_t PING_TYPE    = 0xFD;  ///< Ping message (keepalive)
 const uint8_t ERR_TYPE     = 0xFE;  ///< Error message
 const uint8_t BYE_TYPE     = 0xFF;  ///< Disconnect message
 
 /**
  * @brief Message type enumeration for the IPK25-CHAT protocol
  *
  * This enum defines the message types used in both TCP and UDP
  * implementations of the protocol, in a protocol-agnostic way.
  */
 enum class MessageType {
     AUTH,     ///< Authentication request
     JOIN,     ///< Channel join request
     MSG,      ///< Chat message
     BYE,      ///< Connection termination
     REPLY,    ///< Server reply to request 
     ERR,      ///< Error message
     CONFIRM,  ///< UDP message confirmation
     PING,     ///< UDP ping message
     UNKNOWN   ///< Unrecognized message
 };
 
 /**
  * @brief Structure for parsed protocol messages
  *
  * This structure contains a parsed representation of a protocol message,
  * usable by both TCP and UDP implementations. It stores all possible
  * fields that may be present in various message types.
  */
 struct ParsedMessage {
     MessageType type = MessageType::UNKNOWN;  ///< Message type
     std::string param1;     ///< First parameter (varies by message type)
     std::string param2;     ///< Second parameter (varies by message type)
     std::string param3;     ///< Third parameter (only used in AUTH)
     uint16_t msgId = 0;     ///< Message ID for UDP
     uint16_t refMsgId = 0;  ///< Referenced message ID for UDP REPLY/CONFIRM
     bool success = false;   ///< For REPLY messages, indicates OK vs NOK
 };
 
 /**
  * @brief Converts a string token to a MessageType enum
  *
  * @param token String representation of a message type
  * @return Corresponding MessageType enum value
  */
 MessageType stringToMessageType(const std::string& token);
 
 /**
  * @brief Creates an AUTH message in TCP format
  *
  * @param username User's login name
  * @param displayName User's display name
  * @param secret Authentication secret
  * @return Formatted AUTH message string
  */
 std::string createTcpAuthMessage(const std::string& username, const std::string& displayName, const std::string& secret);
 
 /**
  * @brief Creates a JOIN message in TCP format
  *
  * @param channelID Channel identifier
  * @param displayName User's display name
  * @return Formatted JOIN message string
  */
 std::string createTcpJoinMessage(const std::string& channelID, const std::string& displayName);
 
 /**
  * @brief Creates a MSG message in TCP format
  *
  * @param displayName User's display name
  * @param messageContent Message text content
  * @return Formatted MSG message string
  */
 std::string createTcpMsgMessage(const std::string& displayName, const std::string& messageContent);
 
 /**
  * @brief Creates a BYE message in TCP format
  *
  * @param displayName User's display name
  * @return Formatted BYE message string
  */
 std::string createTcpsByeMessage(const std::string& displayName);
 
 /**
  * @brief Parses a TCP message string into a structured format
  *
  * @param raw Raw message string
  * @return Parsed message structure
  */
 ParsedMessage parseTcpMessage(const std::string& raw);
 
 /**
  * @brief Creates an AUTH message in UDP binary format
  *
  * @param msgId Message identifier
  * @param username User's login name
  * @param displayName User's display name
  * @param secret Authentication secret
  * @return Binary message as a vector of bytes
  */
 std::vector<char> createUdpAuthMessage(uint16_t msgId, const std::string& username, 
                                     const std::string& displayName, const std::string& secret);
 
 /**
  * @brief Creates a JOIN message in UDP binary format
  *
  * @param msgId Message identifier
  * @param channelID Channel identifier
  * @param displayName User's display name
  * @return Binary message as a vector of bytes
  */
 std::vector<char> createUdpJoinMessage(uint16_t msgId, const std::string& channelID, 
                                     const std::string& displayName);
 
 /**
  * @brief Creates a MSG message in UDP binary format
  *
  * @param msgId Message identifier
  * @param displayName User's display name
  * @param msgContent Message text content
  * @return Binary message as a vector of bytes
  */
 std::vector<char> createUdpMsgMessage(uint16_t msgId, const std::string& displayName, 
                                    const std::string& msgContent);
 
 /**
  * @brief Creates a BYE message in UDP binary format
  *
  * @param msgId Message identifier
  * @param displayName User's display name
  * @return Binary message as a vector of bytes
  */
 std::vector<char> createUdpByeMessage(uint16_t msgId, const std::string& displayName);
 
 /**
  * @brief Creates a CONFIRM message in UDP binary format
  *
  * @param refMsgId Message ID being confirmed
  * @return Binary message as a vector of bytes
  */
 std::vector<char> createUdpConfirmMessage(uint16_t refMsgId);
 
 /**
  * @brief Parses a UDP binary message into a structured format
  *
  * @param buffer Binary message buffer
  * @param length Buffer length in bytes
  * @return Parsed message structure
  */
 ParsedMessage parseUdpMessage(const char* buffer, size_t length);
 
 #endif // MESSAGE_H