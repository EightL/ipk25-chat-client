/**
 * @file message.cpp
 * @brief Implementation of message parsing and serialization for the IPK25-CHAT protocol
 *
 * This file provides functions for creating and parsing protocol messages in both
 * TCP (text-based) and UDP (binary) formats. It handles message serialization,
 * deserialization, and conversion between raw data and structured message objects.
 *
 * @author xsevcim00
 */

 #include "message.h"
 #include <cstring>
 #include <sstream>
 #include <iostream>
 #include <arpa/inet.h>
 #include <netdb.h>
 
 // Convert string token to corresponding MessageType enum
 MessageType stringToMessageType(const std::string& token) {
     if (token == "AUTH")  return MessageType::AUTH;
     if (token == "JOIN")  return MessageType::JOIN;
     if (token == "MSG")   return MessageType::MSG;
     if (token == "BYE")   return MessageType::BYE;
     if (token == "REPLY") return MessageType::REPLY;
     if (token == "ERR")   return MessageType::ERR;
     return MessageType::UNKNOWN;
 }
 
 // Create AUTH message in TCP format: "AUTH <username> AS <displayName> USING <secret>\r\n"
 std::string createTcpAuthMessage(const std::string& username, const std::string& displayName, const std::string& secret) {
     return "AUTH " + username + " AS " + displayName + " USING " + secret + "\r\n";
 }
 
 // Create JOIN message in TCP format: "JOIN <channelID> AS <displayName>\r\n"
 std::string createTcpJoinMessage(const std::string& channelID, const std::string& displayName) {
     return "JOIN " + channelID + " AS " + displayName + "\r\n";
 }
 
 // Create MSG message in TCP format: "MSG FROM <displayName> IS <messageContent>\r\n"
 std::string createTcpMsgMessage(const std::string& displayName, const std::string& messageContent) {
     return "MSG FROM " + displayName + " IS " + messageContent + "\r\n";
 }
 
 // Create BYE message in TCP format: "BYE FROM <displayName>\r\n"
 std::string createTcpsByeMessage(const std::string& displayName) {
     return "BYE FROM " + displayName + "\r\n";
 }
 
 // Parse raw TCP message into structured ParsedMessage object
 ParsedMessage parseTcpMessage(const std::string& raw) {
     ParsedMessage msg;
     std::istringstream iss(raw);
     std::string token;
     
     // Parse first token to identify message type
     if (!(iss >> token)) { 
         msg.type = MessageType::UNKNOWN;
         return msg;
     }
     msg.type = stringToMessageType(token);
     
     // Parse remaining tokens based on message type
     switch (msg.type) {
         case MessageType::AUTH:
             // Format: AUTH <username> AS <displayName> USING <secret>
             if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // username
             if (!(iss >> token) || token != "AS") { msg.type = MessageType::UNKNOWN; break; } // AS keyword
             if (!(iss >> msg.param2)) { msg.type = MessageType::UNKNOWN; break; } // displayName
             if (!(iss >> token) || token != "USING") { msg.type = MessageType::UNKNOWN; break; } // USING keyword
             
             // Get remaining content as secret (param3)
             std::getline(iss, msg.param3);
             // Trim whitespace and CRLF
             msg.param3.erase(0, msg.param3.find_first_not_of(" "));
             msg.param3.erase(msg.param3.find_last_not_of(" \r\n") + 1);
             break;
 
         case MessageType::JOIN:
             // Format: JOIN <channelID> AS <displayName>
             if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // channelID
             if (!(iss >> token) || token != "AS") { msg.type = MessageType::UNKNOWN; break; } // AS keyword
             if (!(iss >> msg.param2)) { msg.type = MessageType::UNKNOWN; break; } // displayName
             break;
 
         case MessageType::MSG:
             // Format: MSG FROM <displayName> IS <messageContent>
             if (!(iss >> token) || token != "FROM") { msg.type = MessageType::UNKNOWN; break; } // FROM keyword
             if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // displayName
             if (!(iss >> token) || token != "IS") { msg.type = MessageType::UNKNOWN; break; } // IS keyword
             
             // Get remaining content as message (param2)
             std::getline(iss, msg.param2);
             // Trim whitespace and CRLF
             msg.param2.erase(0, msg.param2.find_first_not_of(" "));
             msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
             break;
 
         case MessageType::BYE:
             // Format: BYE FROM <displayName>
             if (!(iss >> token) || token != "FROM") { msg.type = MessageType::UNKNOWN; break; } // FROM keyword
             if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // displayName
             break;
 
         case MessageType::REPLY:
             // Format: REPLY <OK|NOK> IS <content>
             if (!(iss >> token)) { msg.type = MessageType::UNKNOWN; break; } // OK or NOK
             msg.param1 = token;
             msg.success = (token == "OK");
             if (!(iss >> token) || token != "IS") { msg.type = MessageType::UNKNOWN; break; } // IS keyword
             
             // Get remaining content as reply message (param2)
             std::getline(iss, msg.param2);
             // Trim whitespace and CRLF
             msg.param2.erase(0, msg.param2.find_first_not_of(" "));
             msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
             break;
 
         case MessageType::ERR:
             // Format: ERR FROM <source> IS <errorMessage>
             if (!(iss >> token) || token != "FROM") { msg.type = MessageType::UNKNOWN; break; } // FROM keyword
             if (!(iss >> msg.param1)) { msg.type = MessageType::UNKNOWN; break; } // source name
             if (!(iss >> token) || token != "IS") { msg.type = MessageType::UNKNOWN; break; } // IS keyword
             
             // Get remaining content as error message (param2)
             std::getline(iss, msg.param2);
             // Trim whitespace and CRLF
             msg.param2.erase(0, msg.param2.find_first_not_of(" "));
             msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
             break;
 
         default:
             // Unrecognized message type
             msg.type = MessageType::UNKNOWN;
             break;
     }
     return msg;
 }
 
 // Parse UDP binary message into structured ParsedMessage object
 ParsedMessage parseUdpMessage(const char* buffer, size_t length) {
     ParsedMessage msg;
     
     // Check minimum length (type + msgId = 3 bytes)
     if (length < 3) {
         msg.type = MessageType::UNKNOWN;
         return msg;
     }
     
     // Extract message type and ID
     uint8_t msgType = buffer[0];
     uint16_t msgId;
     memcpy(&msgId, &buffer[1], 2);
     msg.msgId = ntohs(msgId);  // Convert from network to host byte order
     
     // Process based on message type
     switch (msgType) {
         case CONFIRM_TYPE:
             msg.type = MessageType::CONFIRM;
             // In CONFIRM, msgId field contains the reference message ID
             msg.refMsgId = msg.msgId;
             break;
             
         case REPLY_TYPE:
             msg.type = MessageType::REPLY;
             // REPLY: type(1) + msgId(2) + success(1) + refMsgId(2) + [content]
             if (length >= 6) {
                 msg.success = (buffer[3] == 1);  // 1 = success, 0 = failure
                 
                 // Extract reference message ID
                 uint16_t refId;
                 memcpy(&refId, &buffer[4], 2);
                 msg.refMsgId = ntohs(refId);
                 
                 // Extract optional message content if present
                 if (length > 6) {
                     msg.param2 = std::string(&buffer[6]);
                 }
             }
             break;
             
         case MSG_TYPE:
             msg.type = MessageType::MSG;
             if (length > 3) {
                 // Extract sender's display name from null-terminated string
                 const char* displayName = &buffer[3];
                 msg.param1 = std::string(displayName);
                 
                 // Find message content after the null terminator of display name
                 const char* content = displayName + msg.param1.length() + 1;
                 if (content < buffer + length) {
                     msg.param2 = std::string(content);
                 }
             }
             break;
             
         case BYE_TYPE:
             msg.type = MessageType::BYE;
             if (length > 3) {
                 // Extract display name from null-terminated string
                 const char* displayName = &buffer[3];
                 msg.param1 = std::string(displayName);
             }
             break;
             
         case ERR_TYPE:
             msg.type = MessageType::ERR;
             if (length > 3) {
                 // Extract source name from null-terminated string
                 const char* sourceName = &buffer[3];
                 msg.param1 = std::string(sourceName);
                 
                 // Find error message after the null terminator of source name
                 const char* errMsg = sourceName + msg.param1.length() + 1;
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
 
 // Create AUTH message in UDP binary format
 std::vector<char> createUdpAuthMessage(uint16_t msgId, const std::string& username, 
                                    const std::string& displayName, const std::string& secret) {
     std::vector<char> message;
     
     // Add message type
     message.push_back(AUTH_TYPE);
     
     // Add message ID (convert to network byte order)
     uint16_t netMsgId = htons(msgId);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
     
     // Add username, displayName, and secret as null-terminated strings
     message.insert(message.end(), username.begin(), username.end());
     message.push_back('\0');
     message.insert(message.end(), displayName.begin(), displayName.end());
     message.push_back('\0');
     message.insert(message.end(), secret.begin(), secret.end());
     message.push_back('\0');
     
     return message;
 }
 
 // Create JOIN message in UDP binary format
 std::vector<char> createUdpJoinMessage(uint16_t msgId, const std::string& channelID, const std::string& displayName) {
     std::vector<char> message;
     
     // Add message type
     message.push_back(JOIN_TYPE);
     
     // Add message ID (convert to network byte order)
     uint16_t netMsgId = htons(msgId);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
     
     // Add channelID and displayName as null-terminated strings
     message.insert(message.end(), channelID.begin(), channelID.end());
     message.push_back('\0');
     message.insert(message.end(), displayName.begin(), displayName.end());
     message.push_back('\0');
     
     return message;
 }
 
 // Create MSG message in UDP binary format
 std::vector<char> createUdpMsgMessage(uint16_t msgId, const std::string& displayName, const std::string& msgContent) {
     std::vector<char> message;
     
     // Add message type
     message.push_back(MSG_TYPE);
     
     // Add message ID (convert to network byte order)
     uint16_t netMsgId = htons(msgId);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
     
     // Add displayName and message content as null-terminated strings
     message.insert(message.end(), displayName.begin(), displayName.end());
     message.push_back('\0');
     message.insert(message.end(), msgContent.begin(), msgContent.end());
     message.push_back('\0');
     
     return message;
 }
 
 // Create BYE message in UDP binary format
 std::vector<char> createUdpByeMessage(uint16_t msgId, const std::string& displayName) {
     std::vector<char> message;
     
     // Add message type
     message.push_back(BYE_TYPE);
     
     // Add message ID (convert to network byte order)
     uint16_t netMsgId = htons(msgId);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
     
     // Add displayName as a null-terminated string
     message.insert(message.end(), displayName.begin(), displayName.end());
     message.push_back('\0');
     
     return message;
 }
 
 // Create CONFIRM message in UDP binary format
 std::vector<char> createUdpConfirmMessage(uint16_t refMsgId) {
     std::vector<char> message;
     
     // Add message type
     message.push_back(CONFIRM_TYPE);
     
     // Add reference message ID (convert to network byte order)
     uint16_t netMsgId = htons(refMsgId);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[0]);
     message.push_back(reinterpret_cast<char*>(&netMsgId)[1]);
     
     return message;
 }