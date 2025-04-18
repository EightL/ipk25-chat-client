/**
 * @file message.h
 * @brief Message types and utilities for the IPK25-CHAT protocol
 *
 * Defines binary type values, protocol‑agnostic enums, parsing structures,
 * and functions to serialize/deserialize messages for both TCP and UDP.
 *
 * @author xsevcim00
 */

#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <vector>
#include <cstdint>

// UDP binary type constants
const uint8_t AUTH_TYPE    = 0x02;
const uint8_t CONFIRM_TYPE = 0x00;
const uint8_t REPLY_TYPE   = 0x01;
const uint8_t JOIN_TYPE    = 0x03;
const uint8_t MSG_TYPE     = 0x04;
const uint8_t PING_TYPE    = 0xFD;
const uint8_t ERR_TYPE     = 0xFE;
const uint8_t BYE_TYPE     = 0xFF;

/**
 * @brief Message type enumeration for IPK25-CHAT
 *
 * Protocol‑agnostic representation of all message kinds.
 */
enum class MessageType {
    AUTH, 
    JOIN, 
    MSG, 
    BYE, 
    REPLY,  
    ERR,
    CONFIRM,
    PING,
    UNKNOWN  // unrecognized type
};

/**
 * @brief Parsed representation of a protocol message
 *
 * Holds all parameters that may appear in TCP or UDP messages.
 */
struct ParsedMessage {
    MessageType type = MessageType::UNKNOWN;
    std::string param1;
    std::string param2;
    std::string param3;
    uint16_t    msgId    = 0;
    uint16_t    refMsgId = 0;
    bool        success  = false;
};

/**
 * @brief Convert a TCP token to MessageType
 * @param token text token (e.g. "MSG", "ERR")
 * @return corresponding MessageType or UNKNOWN
 */
MessageType stringToMessageType(const std::string& token);

/**
 * @brief Create a TCP AUTH command string
 * @param username login name
 * @param displayName user display name
 * @param secret authentication secret
 * @return "AUTH <user> AS <display> USING <secret>\r\n"
 */
std::string createTcpAuthMessage(const std::string& username, const std::string& displayName, const std::string& secret);

/**
 * @brief Create a TCP JOIN command string
 * @param channelID channel identifier
 * @param displayName user display name
 * @return "JOIN <channel> AS <display>\r\n"
 */
std::string createTcpJoinMessage(const std::string& channelID, const std::string& displayName);

/**
 * @brief Create a TCP MSG command string
 * @param displayName user display name
 * @param messageContent chat text
 * @return "MSG FROM <display> IS <content>\r\n"
 */
std::string createTcpMsgMessage(const std::string& displayName, const std::string& messageContent);

/**
 * @brief Create a TCP BYE command string
 * @param displayName user display name
 * @return "BYE FROM <display>\r\n"
 */
std::string createTcpByeMessage(const std::string& displayName);

/**
 * @brief Parse a TCP message into a structure
 * @param raw raw CRLF‑terminated message
 * @return parsed message
 */
ParsedMessage parseTcpMessage(const std::string& raw);

/**
 * @brief Create a UDP AUTH packet
 * @param msgId UDP message ID
 * @param username login name
 * @param displayName user display name
 * @param secret authentication secret
 * @return binary packet vector
 */
std::vector<char> createUdpAuthMessage(uint16_t msgId, const std::string& username, const std::string& displayName, const std::string& secret);

/**
 * @brief Create a UDP JOIN packet
 * @param msgId UDP message ID
 * @param channelID channel identifier
 * @param displayName user display name
 * @return binary packet vector
 */
std::vector<char> createUdpJoinMessage(uint16_t msgId, const std::string& channelID, const std::string& displayName);

/**
 * @brief Create a UDP MSG packet
 * @param msgId UDP message ID
 * @param displayName user display name
 * @param msgContent chat text
 * @return binary packet vector
 */
std::vector<char> createUdpMsgMessage(uint16_t msgId, const std::string& displayName, const std::string& msgContent);

/**
 * @brief Create a UDP BYE packet
 * @param msgId UDP message ID
 * @param displayName user display name
 * @return binary packet vector
 */
std::vector<char> createUdpByeMessage(uint16_t msgId, const std::string& displayName);

/**
 * @brief Create a UDP CONFIRM packet
 * @param refMsgId message ID to confirm
 * @return binary packet vector
 */
std::vector<char> createUdpConfirmMessage(uint16_t refMsgId);

/**
 * @brief Create a UDP ERR packet
 * @param msgId UDP message ID
 * @param displayName user display name
 * @param text error description
 * @return binary packet vector
 */
std::vector<char> createUdpErrMessage(uint16_t msgId, const std::string& displayName, const std::string& text);

/**
 * @brief Parse a UDP packet into a structure
 * @param buffer binary packet buffer
 * @param length buffer length
 * @return parsed message
 */
ParsedMessage parseUdpMessage(const char* buffer, size_t length);

#endif // MESSAGE_H
