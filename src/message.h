#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <vector>
#include <cstdint>

// UDP protocol constants
const uint8_t AUTH_TYPE    = 0x02;
const uint8_t CONFIRM_TYPE = 0x00;
const uint8_t REPLY_TYPE   = 0x01;
const uint8_t JOIN_TYPE    = 0x03;
const uint8_t MSG_TYPE     = 0x04;
const uint8_t PING_TYPE    = 0xFD;
const uint8_t ERR_TYPE     = 0xFE;
const uint8_t BYE_TYPE     = 0xFF;

enum class MessageType {
    AUTH,     // Authentication request
    JOIN,     // Channel join request
    MSG,      // Chat message
    BYE,      // Connection termination
    REPLY,    // Server reply to request 
    ERR,      // Error message
    CONFIRM,  // UDP message confirmation
    PING,     // UDP ping message
    UNKNOWN   // Unrecognized message
};

// Structure for parsed protocol messages
struct ParsedMessage {
    MessageType type = MessageType::UNKNOWN;
    std::string param1;  // First parameter (varies by message type)
    std::string param2;  // Second parameter (varies by message type)
    std::string param3;  // Third parameter (only used in AUTH)
    uint16_t msgId = 0;  // Message ID for UDP
    uint16_t refMsgId = 0; // Referenced message ID for UDP REPLY/CONFIRM
    bool success = false; // For REPLY messages, indicates OK vs NOK
};

// Message parsing and serialization functions
MessageType stringToMessageType(const std::string& token);

// TCP message serialization
std::string serializeAuth(const std::string& username, const std::string& displayName, const std::string& secret);
std::string serializeJoin(const std::string& channelID, const std::string& displayName);
std::string serializeMsg(const std::string& displayName, const std::string& messageContent);
std::string serializeBye(const std::string& displayName);
ParsedMessage parseMessage(const std::string& raw);

// UDP message building
std::vector<char> buildUdpAuthMessage(uint16_t msgId, const std::string& username, 
                                    const std::string& displayName, const std::string& secret);
std::vector<char> buildUdpJoinMessage(uint16_t msgId, const std::string& channelId, 
                                    const std::string& displayName);
std::vector<char> buildUdpMsgMessage(uint16_t msgId, const std::string& displayName, 
                                    const std::string& msgContent);
std::vector<char> buildUdpByeMessage(uint16_t msgId, const std::string& displayName);
std::vector<char> buildConfirmMessage(uint16_t refMsgId);
ParsedMessage parseUdpMessage(const char* buffer, size_t length);

#endif // MESSAGE_H