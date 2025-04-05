#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <set>
#include "message.h"

// Client states - aligned with Finite State Machine diagram
enum class ClientState {
    INIT,           // "start" in FSM - initial state
    AUTHENTICATING, // "auth" in FSM - sending AUTH and waiting for REPLY
    JOINED,         // "open" in FSM - authenticated and ready to send messages 
    JOIN_WAITING,   // "join" in FSM - sent JOIN, waiting for REPLY
    TERMINATED      // "end" in FSM - connection terminated
};

class Client {
protected:
    ClientState state = ClientState::INIT;
    std::string displayName;
    std::string username;
    std::string channelID;
    int socketFd = -1;
    bool isUdp;
    
    // Set socket to non-blocking mode
    void setNonBlocking(int fd);
    
    // Check if message type is valid in current state
    bool isValidTransition(MessageType msgType);
    
    // Handle incoming messages according to FSM
    virtual void handleIncomingMessage(const ParsedMessage& msg);
    
public:
    Client(bool isUdpClient);
    virtual ~Client();
    
    // Set user credentials
    void setCredentials(const std::string& user, const std::string& display, const std::string& secret);
    
    // Main client loop
    virtual int run() = 0;
};

#endif // CLIENT_H