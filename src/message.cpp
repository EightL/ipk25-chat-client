/**
 * @file message.cpp
 * @brief Implementation of message parsing and serialization for the IPK25-CHAT protocol
 *
 * Provides functions to convert between raw TCP/UDP data and ParsedMessage objects,
 * handling both text-based (TCP) and binary (UDP) formats.
 *
 * @author xsevcim00
 */

#include "message.h"
#include <cstring>
#include <sstream>
#include <iostream>
#include <arpa/inet.h>
#include <netdb.h>
#include <regex>

// Map a text token to its MessageType enum
MessageType stringToMessageType(const std::string& token) {
    if (token == "AUTH")  return MessageType::AUTH;
    if (token == "JOIN")  return MessageType::JOIN;
    if (token == "MSG")   return MessageType::MSG;
    if (token == "BYE")   return MessageType::BYE;
    if (token == "REPLY") return MessageType::REPLY;
    if (token == "ERR")   return MessageType::ERR;
    // Fallback when unrecognized
    return MessageType::UNKNOWN;
}

// Build a TCP AUTH command string
std::string createTcpAuthMessage(const std::string& username, const std::string& displayName, const std::string& secret) {
    // AUTH <user> AS <display> USING <secret>\r\n
    return "AUTH " + username + " AS " + displayName + " USING " + secret + "\r\n";
}

// Build a TCP JOIN command string
std::string createTcpJoinMessage(const std::string& channelID, const std::string& displayName) {
    // JOIN <channel> AS <display>\r\n
    return "JOIN " + channelID + " AS " + displayName + "\r\n";
}

// Build a TCP MSG command string
std::string createTcpMsgMessage(const std::string& displayName, const std::string& messageContent) {
    // MSG FROM <display> IS <content>\r\n
    return "MSG FROM " + displayName + " IS " + messageContent + "\r\n";
}

// Build a TCP BYE command string
std::string createTcpByeMessage(const std::string& displayName) {
    // BYE FROM <display>\r\n
    return "BYE FROM " + displayName + "\r\n";
}

// Helper fucntion for parseTcpMessage - expect a specific literal token from an istringstream
static bool expectToken(std::istringstream& iss, const std::string& lit) {
    std::string t;
    // read next token and compare
    return (iss >> t) && t == lit;
}

// Trim leading/trailing spaces and newlines from a string
static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \r\n");
    if (start == std::string::npos) return ""; // all whitespace
    auto end   = s.find_last_not_of(" \r\n");
    return s.substr(start, end - start + 1);
}

// Parse a raw TCP line into a ParsedMessage
ParsedMessage parseTcpMessage(const std::string& raw) {
    ParsedMessage msg;
    msg.success = false;
    std::istringstream iss(raw);
    std::string token;

    // read message type token
    if (!(iss >> token)) {
        msg.type = MessageType::UNKNOWN;
        return msg;
    }
    // convert to enum
    msg.type = stringToMessageType(token);

    // handle each protocol command
    switch (msg.type) {
        case MessageType::AUTH:
            // AUTH <user> AS <display> USING <secret>
            if (!(iss >> msg.param1)          // username
            || !expectToken(iss, "AS")      // literal AS
            || !(iss >> msg.param2)         // displayName
            || !expectToken(iss, "USING"))  // literal USING
            {
                msg.type = MessageType::UNKNOWN;
                break;
            }
            std::getline(iss, msg.param3);   // secret + trailing
            msg.param3 = trim(msg.param3);
            break;

        case MessageType::JOIN:
            // JOIN <channel> AS <display>
            if (!(iss >> msg.param1)          // channelID
            || !expectToken(iss, "AS")      // literal AS
            || !(iss >> msg.param2))        // displayName
            {
                msg.type = MessageType::UNKNOWN;
            }
            break;

        case MessageType::MSG:
            // MSG FROM <display> IS <content>
            if (!expectToken(iss, "FROM")    // literal FROM
            || !(iss >> msg.param1)         // displayName
            || !expectToken(iss, "IS"))     // literal IS
            {
                msg.type = MessageType::UNKNOWN;
                break;
            }
            std::getline(iss, msg.param2);   // messageContent
            msg.param2 = trim(msg.param2);
            break;

        case MessageType::BYE:
            // BYE FROM <display>
            if (!expectToken(iss, "FROM")    // literal FROM
            || !(iss >> msg.param1))        // displayName
            {
                msg.type = MessageType::UNKNOWN;
            }
            break;

        case MessageType::REPLY:
            // REPLY <OK|NOK> IS <content>
            if (!(iss >> token)) {           // OK/NOK
                msg.type = MessageType::UNKNOWN;
                break;
            }
            msg.success = (token == "OK");
            if (!expectToken(iss, "IS")) {   // literal IS
                msg.type = MessageType::UNKNOWN;
                break;
            }
            std::getline(iss, msg.param2);   // messageContent
            msg.param2 = trim(msg.param2);
            break;

        case MessageType::ERR:
            // ERR FROM <display> IS <content>
            if (!expectToken(iss, "FROM")    // literal FROM
            || !(iss >> msg.param1)         // displayName
            || !expectToken(iss, "IS"))     // literal IS
            {
                msg.type = MessageType::UNKNOWN;
                break;
            }
            std::getline(iss, msg.param2);   // error text
            msg.param2 = trim(msg.param2);
            break;

        default:
            // unknown type
            msg.type = MessageType::UNKNOWN;
    }

    return msg;
}

// Parse a raw UDP packet buffer into a ParsedMessage
ParsedMessage parseUdpMessage(const char* buffer, size_t length) {
    ParsedMessage msg;
    msg.type = MessageType::UNKNOWN;

    // must be at least 3 bytes for header (type + msgId)
    if (length < 3) return msg;

    uint8_t type = static_cast<uint8_t>(buffer[0]);
    uint16_t netMsgId;
    std::memcpy(&netMsgId, buffer + 1, sizeof(netMsgId));
    msg.msgId = ntohs(netMsgId);         // convert network order

    const char* ptr = buffer + 3;        // start of payload
    const char* end = buffer + length;

    switch (type) {
        case CONFIRM_TYPE:
            msg.type     = MessageType::CONFIRM;
            msg.refMsgId = msg.msgId;      // reference own ID
            break;

        case REPLY_TYPE:
            // REPLY format: [type][msgId][result][refId][text]\0
            if (length < 6) break;         // need at least result + refId
            msg.type    = MessageType::REPLY;
            msg.success = (buffer[3] == 1); // 1 = OK, 0 = NOK

            uint16_t netRef;
            std::memcpy(&netRef, buffer + 4, 2);
            msg.refMsgId = ntohs(netRef); // Ref to original msg

            ptr = buffer + 6;
            // copy remaining bytes up to null terminator
            if (ptr < end) {
                size_t n = strnlen(ptr, end - ptr);
                msg.param2.assign(ptr, n);
            }
            break;

        case MSG_TYPE:
            // MSG: [type][msgId][display]\0[content]\0
            msg.type = MessageType::MSG;
            if (ptr < end) {
                size_t n = strnlen(ptr, end - ptr);
                msg.param1.assign(ptr, n);     // displayName
                ptr += n + 1;                  // skip over null
                if (ptr < end) {
                    size_t m = strnlen(ptr, end - ptr);
                    msg.param2.assign(ptr, m); // messageContent
                }
            }
            break;

        case BYE_TYPE:
            // BYE: [type][msgId][display]\0
            msg.type = MessageType::BYE;
            if (ptr < end) {
                size_t n = strnlen(ptr, end - ptr);
                msg.param1.assign(ptr, n);     // displayName
            }
            break;

        case ERR_TYPE:
            // ERR: [type][msgId][display]\0[text]\0
            msg.type = MessageType::ERR;
            if (ptr < end) {
                size_t n = strnlen(ptr, end - ptr);
                msg.param1.assign(ptr, n);     // source display
                ptr += n + 1;
                if (ptr < end) {
                    size_t m = strnlen(ptr, end - ptr);
                    msg.param2.assign(ptr, m); // error message
                }
            }
            break;

        case PING_TYPE:
            // PING only contains header
            msg.type = MessageType::PING;
            break;

        default:
            // else UNKNOWN
            break;
    }

    return msg;
}

// Helper to push a 16-bit network-order ID into a vector
static void pushNet16(std::vector<char>& v, uint16_t value) {
    uint16_t net = htons(value);
    v.push_back(reinterpret_cast<char*>(&net)[0]);
    v.push_back(reinterpret_cast<char*>(&net)[1]);
}

// Serialize an AUTH message into UDP binary form
std::vector<char> createUdpAuthMessage(uint16_t msgId, const std::string& username, const std::string& displayName, const std::string& secret) {
    std::vector<char> m;
    m.push_back(AUTH_TYPE);
    pushNet16(m, msgId);
    // we append nul-terminated fields in order
    m.insert(m.end(), username.begin(), username.end());   m.push_back('\0');
    m.insert(m.end(), displayName.begin(), displayName.end()); m.push_back('\0');
    m.insert(m.end(), secret.begin(), secret.end());       m.push_back('\0');
    return m;
}

// Serialize a JOIN message into UDP binary form
std::vector<char> createUdpJoinMessage(uint16_t msgId, const std::string& channelID, const std::string& displayName) {
    std::vector<char> m;
    m.push_back(JOIN_TYPE);
    pushNet16(m, msgId);
    m.insert(m.end(), channelID.begin(), channelID.end());    m.push_back('\0');
    m.insert(m.end(), displayName.begin(), displayName.end()); m.push_back('\0');
    return m;
}

// Serialize a MSG into UDP binary form
std::vector<char> createUdpMsgMessage(uint16_t msgId, const std::string& displayName, const std::string& msgContent) {
    std::vector<char> m;
    m.push_back(MSG_TYPE);
    pushNet16(m, msgId);
    m.insert(m.end(), displayName.begin(), displayName.end()); m.push_back('\0');
    m.insert(m.end(), msgContent.begin(), msgContent.end());  m.push_back('\0');
    return m;
}

// Serialize a BYE into UDP binary form
std::vector<char> createUdpByeMessage(uint16_t msgId, const std::string& displayName) {
    std::vector<char> m;
    m.push_back(BYE_TYPE);
    pushNet16(m, msgId);
    m.insert(m.end(), displayName.begin(), displayName.end()); m.push_back('\0');
    return m;
}

// Serialize an ERR into UDP binary form
std::vector<char> createUdpErrMessage(uint16_t msgId, const std::string& displayName, const std::string& text) {
    std::vector<char> m;
    m.push_back(ERR_TYPE);
    pushNet16(m, msgId);
    m.insert(m.end(), displayName.begin(), displayName.end()); m.push_back('\0');
    m.insert(m.end(), text.begin(), text.end());              m.push_back('\0');
    return m;
}

// Serialize a CONFIRM message referencing a prior UDP packet
std::vector<char> createUdpConfirmMessage(uint16_t refMsgId) {
    std::vector<char> m;
    m.push_back(CONFIRM_TYPE);
    pushNet16(m, refMsgId);   // only header needed
    return m;
}
