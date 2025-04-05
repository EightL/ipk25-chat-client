#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include <netinet/in.h>
#include <chrono>
#include "client.h"

class UdpClient : public Client {
private:
    std::string serverAddress;
    int serverPort;
    uint16_t timeoutMs;
    uint8_t maxRetransmissions;
    
    uint16_t nextMsgId = 0;
    std::set<uint16_t> seenMsgIds;
    sockaddr_in serverAddr;
    
    // Get next message ID
    uint16_t getNextMsgId();
    
    // Update server address if needed
    void checkAndUpdateServerPort(const sockaddr_in& peerAddr);
    
    // Handle AUTH flow
    bool authenticateWithRetries(const std::string& secret);
    
    // Process user commands and input
    void processUserInput(const std::string& input);
    
    // Send a UDP message with retries if needed
    bool sendUdpMessage(const std::vector<char>& msg, bool requireConfirm = true);
    
protected:
    virtual void handleIncomingMessage(const ParsedMessage& msg) override;
    
public:
    UdpClient(const std::string& serverIp, int port, 
              uint16_t timeout, uint8_t retransmissions);
    virtual ~UdpClient();
    
    virtual int run() override;
};

#endif // UDP_CLIENT_H