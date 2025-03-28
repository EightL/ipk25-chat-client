#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cctype>

// --- Serialization functions ---
// These functions create protocol-compliant messages ending with "\r\n"

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

// --- Parsing functions ---
// We define an enum to represent message types.
enum class MessageType {
    AUTH,
    JOIN,
    MSG,
    BYE,
    REPLY,
    ERR,
    UNKNOWN
};

// Helper to convert token to message type.
MessageType stringToMessageType(const std::string& token) {
    if (token == "AUTH") return MessageType::AUTH;
    if (token == "JOIN") return MessageType::JOIN;
    if (token == "MSG") return MessageType::MSG;
    if (token == "BYE") return MessageType::BYE;
    if (token == "REPLY") return MessageType::REPLY;
    if (token == "ERR") return MessageType::ERR;
    return MessageType::UNKNOWN;
}

// Structure to hold the parsed message components.
struct ParsedMessage {
    MessageType type = MessageType::UNKNOWN;
    std::string param1; // For AUTH: username; JOIN: channelID; MSG: displayName; BYE: displayName; REPLY/ERR: first parameter (e.g. OK/NOK or displayName)
    std::string param2; // For AUTH: displayName; JOIN: displayName; MSG: message content; REPLY/ERR: message content
    std::string param3; // For AUTH only: secret
};

// A naive parser that works with our text-based protocol formats.
ParsedMessage parseMessage(const std::string& raw) {
    ParsedMessage msg;
    std::istringstream iss(raw);
    std::string token;
    
    // Get the message type token.
    iss >> token;
    msg.type = stringToMessageType(token);
    
    switch (msg.type) {
        case MessageType::AUTH:
            // Format: AUTH {Username} AS {DisplayName} USING {Secret}\r\n
            iss >> msg.param1;          // username
            iss >> token;               // Expect "AS"
            iss >> msg.param2;          // displayName
            iss >> token;               // Expect "USING"
            std::getline(iss, msg.param3); // secret (rest of the line)
            // Trim trailing whitespace and CRLF.
            msg.param3.erase(msg.param3.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::JOIN:
            // Format: JOIN {ChannelID} AS {DisplayName}\r\n
            iss >> msg.param1;          // channelID
            iss >> token;               // Expect "AS"
            iss >> msg.param2;          // displayName
            break;
        case MessageType::MSG:
            // Format: MSG FROM {DisplayName} IS {MessageContent}\r\n
            iss >> token;               // Expect "FROM"
            iss >> msg.param1;          // displayName
            iss >> token;               // Expect "IS"
            std::getline(iss, msg.param2); // message content
            // Trim leading spaces and trailing CRLF.
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::BYE:
            // Format: BYE FROM {DisplayName}\r\n
            iss >> token;               // Expect "FROM"
            iss >> msg.param1;          // displayName
            break;
        case MessageType::REPLY:
            // Format: REPLY {"OK"|"NOK"} IS {MessageContent}\r\n
            iss >> token;               // Should be "OK" or "NOK"
            msg.param1 = token;
            iss >> token;               // Expect "IS"
            std::getline(iss, msg.param2); // message content
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        case MessageType::ERR:
            // Format: ERR FROM {DisplayName} IS {MessageContent}\r\n
            iss >> token;               // Expect "FROM"
            iss >> msg.param1;          // displayName
            iss >> token;               // Expect "IS"
            std::getline(iss, msg.param2); // message content
            msg.param2.erase(0, msg.param2.find_first_not_of(" "));
            msg.param2.erase(msg.param2.find_last_not_of(" \r\n") + 1);
            break;
        default:
            break;
    }
    return msg;
}

// --- Finite State Machine (FSM) ---
// Define the possible client states.
enum class ClientState {
    INIT,
    AUTHENTICATED,
    JOINED,
    TERMINATED
};

// Context to store the client's current state and display name.
struct ClientContext {
    ClientState state = ClientState::INIT;
    std::string displayName;
};

// A simple handler that processes incoming messages and updates the client context.
void handleIncomingMessage(const ParsedMessage& msg, ClientContext& ctx) {
    switch (msg.type) {
        case MessageType::REPLY:
            if (msg.param1 == "OK") {
                std::cout << "Action Success: " << msg.param2 << "\n";
                if (ctx.state == ClientState::INIT)
                    ctx.state = ClientState::AUTHENTICATED;
            } else {
                std::cout << "Action Failure: " << msg.param2 << "\n";
            }
            break;
        case MessageType::MSG:
            std::cout << msg.param1 << ": " << msg.param2 << "\n";
            break;
        case MessageType::ERR:
            std::cout << "ERROR FROM " << msg.param1 << ": " << msg.param2 << "\n";
            ctx.state = ClientState::TERMINATED;
            break;
        case MessageType::BYE:
            std::cout << "Connection terminated by server.\n";
            ctx.state = ClientState::TERMINATED;
            break;
        default:
            std::cout << "Received unknown or unhandled message type.\n";
            break;
    }
}


// --- Main function for testing the protocol layer ---
int main() {
    // Test serialization routines.
    std::string authMsg = serializeAuth("user123", "User123", "secretpass");
    std::cout << "Serialized AUTH:\n" << authMsg;
    
    std::string joinMsg = serializeJoin("channel1", "User123");
    std::cout << "Serialized JOIN:\n" << joinMsg;
    
    std::string msgMsg = serializeMsg("User123", "Hello, world!");
    std::cout << "Serialized MSG:\n" << msgMsg;
    
    std::string byeMsg = serializeBye("User123");
    std::cout << "Serialized BYE:\n" << byeMsg;
    
    // Test parsing routines.
    {
        std::string rawAuth = "AUTH user123 AS User123 USING secretpass\r\n";
        ParsedMessage pAuth = parseMessage(rawAuth);
        std::cout << "\nParsed AUTH: username=" << pAuth.param1 
                  << ", displayName=" << pAuth.param2 
                  << ", secret=" << pAuth.param3 << "\n";
    }
    
    {
        std::string rawJoin = "JOIN channel1 AS User123\r\n";
        ParsedMessage pJoin = parseMessage(rawJoin);
        std::cout << "Parsed JOIN: channelID=" << pJoin.param1 
                  << ", displayName=" << pJoin.param2 << "\n";
    }
    
    {
        std::string rawMsg = "MSG FROM User123 IS Hello, world!\r\n";
        ParsedMessage pMsg = parseMessage(rawMsg);
        std::cout << "Parsed MSG: displayName=" << pMsg.param1 
                  << ", content=" << pMsg.param2 << "\n";
    }
    
    {
        std::string rawBye = "BYE FROM User123\r\n";
        ParsedMessage pBye = parseMessage(rawBye);
        std::cout << "Parsed BYE: displayName=" << pBye.param1 << "\n";
    }
    
    // Test FSM integration:
    ClientContext clientCtx;
    clientCtx.displayName = "User123";
    
    std::string rawReply = "REPLY OK IS Auth success.\r\n";
    ParsedMessage pReply = parseMessage(rawReply);
    handleIncomingMessage(pReply, clientCtx);
    std::cout << "Client state after REPLY: " 
              << (clientCtx.state == ClientState::AUTHENTICATED ? "AUTHENTICATED" : "OTHER") 
              << "\n";
    
    return 0;
}
