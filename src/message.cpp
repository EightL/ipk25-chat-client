#include "message.h"
#include <cstring>
#include <sstream>
#include <iostream>
#include <arpa/inet.h>
#include <netdb.h>

/**
 * Converts a string token to a MessageType enum
 */
MessageType stringToMessageType(const std::string& token) {
    if (token == "AUTH")  return MessageType::AUTH;
    if (token == "JOIN")  return MessageType::JOIN;
    if (token == "MSG")   return MessageType::MSG;
    if (token == "BYE")   return MessageType::BYE;
    if (token == "REPLY") return MessageType::REPLY;
    if (token == "ERR")   return MessageType::ERR;
    return MessageType::UNKNOWN;
}

/**
 * Message serialization functions for outgoing TCP messages
 */
std::string serializeAuth(const std::string& username, const std::string& displayName, const std::string& secret) {
    return "AUTH " + username + " AS " + displayName + " USING " + secret + "\r\n";
}

std::string serializeJoin(const std::string& channelID, const std::string& displayName) {
    return "JOIN " + channelID + " AS " + displayName + "\r\n";
}

std::string serializeMsg(const std::string& displayName, const std::string& messageContent) {
    return "MSG FROM " + displayName + " IS " + messageContent + "\r\n";
}

std::string serializeBye(const std::string& displayName) {
    return "BYE FROM " + displayName + "\r\n";
}

ParsedMessage parseMessage(const std::string& raw) {
    ParsedMessage msg;
    std::istringstream iss(raw);
    std::string token;
    
    // Attempt to read the first token to identify message type
    if (!(iss >> token)) { 
        // no token => malformed
        msg.type = MessageType::UNKNOWN;
        return msg;
    }
    msg.type = stringToMessageType(token);
    
    switch (msg.type) {
        case MessageType::AUTH:
            // Expect: AUTH <username> AS <displayName> USING <secret>
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> msg.param2)) { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            std::getline(iss, msg.param3);
            msg.param3.erase(0, msg.param3.find_first_not_of(" "));
            msg.param3.erase(msg.param3.find_last_not_of(" \r\n") + 1);
            break;

        case MessageType::JOIN:
            // Expect: JOIN <channelID> AS <displayName>
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> msg.param2)) { msg.type = MessageType::UNKNOWN; break; }
            break;

        case MessageType::MSG:
            // Expect: MSG FROM <displayName> IS <messageContent>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip FROM
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // displayName
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip IS
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;

        case MessageType::BYE:
            // Expect: BYE FROM <displayName>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; }
            break;

        case MessageType::REPLY:
            // Expect: REPLY <OK|NOK> IS <some content>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; }
            msg.param1 = token; // e.g., "OK" or "NOK"
            msg.success = (token == "OK");
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip "IS"
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;

        case MessageType::ERR:
            // Expect: ERR FROM <displayName> IS <errorMessage>
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip FROM
            if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // displayName
            if (!(iss >> token))      { msg.type = MessageType::UNKNOWN; break; } // skip IS
            std::getline(iss, msg.param2);
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;

        default:
            // If the token isn't recognized, mark the message as malformed.
            msg.type = MessageType::UNKNOWN;
            break;
    }
    return msg;
}


ParsedMessage parseUdpMessage(const char* buffer, size_t length) {
    ParsedMessage msg;
    
    if (length < 3) { // All messages have at least type + msgId (3 bytes)
        msg.type = MessageType::UNKNOWN;
        return msg;
    }
    
    uint8_t msgType = buffer[0];
    uint16_t msgId;
    memcpy(&msgId, &buffer[1], 2);
    msg.msgId = ntohs(msgId);
    
    switch (msgType) {
        case CONFIRM_TYPE:
            msg.type = MessageType::CONFIRM;
            msg.refMsgId = msg.msgId; // In CONFIRM, msgId is actually refMsgId
            break;
            
        case REPLY_TYPE:
            msg.type = MessageType::REPLY;
            if (length >= 6) {
                msg.success = (buffer[3] == 1);
                uint16_t refId;
                memcpy(&refId, &buffer[4], 2);
                msg.refMsgId = ntohs(refId);
                
                // Extract message content if present
                if (length > 6) {
                    msg.param2 = std::string(&buffer[6]);
                }
            }
            break;
            
        case MSG_TYPE:
            msg.type = MessageType::MSG;
            if (length > 3) {
                // Extract displayName
                const char* displayName = &buffer[3];
                msg.param1 = std::string(displayName);
                
                // Find the message content (after the first null terminator)
                const char* content = displayName + msg.param1.length() + 1;
                if (content < buffer + length) {
                    msg.param2 = std::string(content);
                }
            }
            break;
            
        case BYE_TYPE:
            msg.type = MessageType::BYE;
            if (length > 3) {
                const char* displayName = &buffer[3];
                msg.param1 = std::string(displayName);
            }
            break;
            
        case ERR_TYPE:
            msg.type = MessageType::ERR;
            if (length > 3) {
                // Extract displayName
                const char* displayName = &buffer[3];
                msg.param1 = std::string(displayName);
                
                // Find error message (after the first null terminator)
                const char* errMsg = displayName + msg.param1.length() + 1;
                if (errMsg < buffer + length) {
                    msg.param2 = std::string(errMsg);
                }
            }
            break;
            
        case PING_TYPE:
            msg.type = MessageType::PING;
            break;
            
        default:
            msg.type = MessageType::UNKNOWN;
    }
    
    return msg;
}


/**
 * UDP Binary Message Building Functions
 */
std::vector<char> buildUdpAuthMessage(uint16_t msgId, const std::string& username, 
                                   const std::string& displayName, const std::string& secret) {
    std::vector<char> message;
    message.push_back(AUTH_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), username.begin(), username.end());
    message.push_back('\0');
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    message.insert(message.end(), secret.begin(), secret.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildUdpJoinMessage(uint16_t msgId, const std::string& channelId, const std::string& displayName) {
    std::vector<char> message;
    message.push_back(JOIN_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), channelId.begin(), channelId.end());
    message.push_back('\0');
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildUdpMsgMessage(uint16_t msgId, const std::string& displayName, const std::string& msgContent) {
    std::vector<char> message;
    message.push_back(MSG_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    message.insert(message.end(), msgContent.begin(), msgContent.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildUdpByeMessage(uint16_t msgId, const std::string& displayName) {
    std::vector<char> message;
    message.push_back(BYE_TYPE);
    uint16_t netMsgId = htons(msgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    message.insert(message.end(), displayName.begin(), displayName.end());
    message.push_back('\0');
    return message;
}

std::vector<char> buildConfirmMessage(uint16_t refMsgId) {
    std::vector<char> message;
    message.push_back(CONFIRM_TYPE);
    uint16_t netMsgId = htons(refMsgId);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
    message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
    return message;
}