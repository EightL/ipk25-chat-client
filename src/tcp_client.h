#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <chrono>
#include "client.h"

class TcpClient : public Client {
private:
    std::string serverAddress;
    int serverPort;
    
    // Wait for reply with timeout
    bool waitForReply(int timeoutSec = 5);
    
    // Process user commands and input
    void processUserInput(const std::string& input);
    
    // Send a string message to server
    bool sendMessage(const std::string& msg);
    
protected:
    virtual void handleIncomingMessage(const ParsedMessage& msg) override;
    
public:
    TcpClient(const std::string& serverIp, int port);
    virtual ~TcpClient();
    
    virtual int run() override;
};

#endif // TCP_CLIENT_H