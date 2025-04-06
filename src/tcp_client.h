#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <chrono>
#include "client.h"

class TcpClient : public Client {
private:
    std::string serverAddress;
    int serverPort;
    std::chrono::steady_clock::time_point terminationStartTime;
    bool isWaitingForTermination = false;
    
    // Send a string message to server
    bool sendMessage(const std::string& msg);
    
protected:
    virtual void handleIncomingMessage(const ParsedMessage& msg) override;
    // Implement protocol-specific methods
    virtual bool authenticate(const std::string& secret) override;
    virtual bool joinChannel(const std::string& channelId) override;
    virtual bool sendChatMessage(const std::string& message) override;
    virtual bool sendByeMessage() override;
    
public:
    TcpClient(const std::string& serverIp, int port);
    virtual ~TcpClient();
    
    virtual int run() override;
};

#endif // TCP_CLIENT_H