# IPK 2024/2025 – Project 2

## Chat‑client for the **IPK25‑CHAT** protocol

- **Author**: Martin Ševčík
- **login**: `xsevcim00`
- **Institute**: VUT FIT 2024/2025


## Motivation

With the first project done, still exhausted from it, I went right onto this second one. The key is to deeply understand whats really happening, especially with the diagrams provided by the specification. Since I had to implement both TCP and UDP variants, I had to understand certain tradeoffs between those two (connetion-oriented vs connectionless, reliability concerns, packet handling, message sending and so on..).

## Overview

This project implements a CLI chat client, that includes both TCP and UDP versions. It makes use of an event-driven loop that maintains the responsiveness and realibility and graceful handling for network issues.

### Key choices:

- `epoll` for low‑overhead I/O.
- A single finite‑state machine in an abstract `Client` class, with separate `TcpClient` and `UdpClient` subclasses.
- Pure **C++20**, no outside dependencies
- **std::regex** for cleaner input validations

---

## How it works

1. **Initialization**: `main.cpp` parses command‑line arguments with the help of `parseArgs` function, inits `signalHandler` for graceful termination and then uses `createClient()` to build either `TcpClient` or `UdpClient` depending on which we chose with `-t`.
2. **Setup**: 
    - **TCP**: In `TcpClient::run()`, after a successful connection, we set the socket to non-blocking (`STDFILENO`) and then register them with `epoll`.
    - **UDP**: In `UdpClient::initSocket()` we get ephemeral port also make the socket non-blocking, and add the socket with `STDIN_FILENO` to `epoll`.
3. **Event loop**:
   - **Stdin events**: The main loop listens for input lines. If they start with `/` -> they're  parsed into `/auth`, `/join`, `/rename`, `/bye`, or `/help` commands; else they are sent as chat messages.
   - **Socket events**:
     - **TCP**: Bytes are read into a buffer, complete `\r\n`‑terminated frames are extracted, and `parseTcpMessage()` is handled with `handleIncomingMessage()`.
     - **UDP**: Packets are received via `recvfrom()`, parsed with `parseUdpMessage()`, we check for duplicit ID's, and a **CONFIRM** is sent for each valid packet, then we dispatch it to `handleIncomingMessage()`.
4. **State machine & reliability**: 
     - **Valid transitions** (INIT -> AUTHENITCATING -> ...) are handled by `ClientState`. 
     - **UDP reliability**: every outbound packet is tagged by `getNextMsgId()`, sent via `sendUdpMessage()` which loops (initial send + up to N retries) until it sees a matching **CONFIRM**, then `awaitReply()` waits up to 5 s for a positive **REPLY** before giving up ​


---

### Control Flow / FSM

![Client State Machine](/diagrams/client.svg)


While designinng this finite state machine, i was mainly following the FSM in the specification and enhanced it with some tweaks. This FSM is implemented in `client.cpp` and both TCP and UDP follow this. The client starts in `INIT`, transitions to `AUTHENTICATING` on /auth, and if successful reaches `JOINED` state. From there, it can either send messages in the current channel or enter `JOIN_WAITING` to switch channels. The `TERMINATED` state is a one-way exit - once we're there, we close the socket & exit. All error paths should be providing graceful fallbacks.

## Chosen Programming Language

This project is implemented in **C++20**, mainly for features like `enum class`, `<chrono>` utilities, and stronger constexpr. But also uses stuff like  `std::string`/`std::vector` for resource and buffer management, which goes back to C++11.

I stuck with C++ because I’m taking a C++ course this semester, so it aligned nicely. Plus, having done the first project in C++, I was able to reuse and improve patterns I learned in the first project.

---

## Compiling the Project

```bash
make        # release build
make debug  # with debug prints
```
---

## Usage

```bash
./ipk25chat-client -t <tcp|udp> -s <server> [options]
```

### Command‑line Options
```
-t <tcp|udp>        Transport protocol (tcp or udp)
-s <server>         Server IP or hostname
-p <port>           Server port (default 4567)
-d <timeout>        UDP confirm timeout in ms (default 250)
-r <retries>        UDP max retransmissions (default 3)
-h                  Show help and exit
```

### Chat Commands

| Command   | Parameters                      | Action                           |
| --------- | ------------------------------- | -------------------------------- |
| `/auth`   | `<username> <secret> <display>` | Authenticate (first step)        |
| `/join`   | `<channel>`                     | Switch channels                  |
| `/rename` | `<new display name>`            | Change my display name           |
| `/bye`    | –                               | Say goodbye and close the client |
| `/help`   | –                               | List available commands          |

#### Example chat usage

```shell
/auth xmartin00 heslo1234 marta
/join general
my name is marta
/rename Martin
now its Martin
/bye
```

---

## Project Architecture

```text
main.cpp           Entry point: args, signal, TCP/UDP client factory
client.h/.cpp      Base class: FSM, input parsing, validation
message.h/.cpp     Parser/serializer for TCP & UDP formats
tcp_client.h/.cpp  TcpClient: CRLF framing, reply timeouts
udp_client.h/.cpp  UdpClient: reliable sends, dynamic port handling
debug.h            Debug print macro (make debug)
```

![Main Project Structure](/diagrams/main.svg)

The class diagram shows how I structured the codebase. The abstract `Client` class defines the FSM and common operations. `TcpClient/UdpClient` classes, which inherit from Client, implement the methods with their specific details. Everything is nicely in once place, while the tranport details for each client vary. The `MessageType` enum and the `ParsedMessage` struct provide a clean way to handle both text-based TCP frames and binary UDP datagrams.

---

## Key Implementation Points

### Client base class (`client.h` / `client.cpp`)

- **State & Identity**: Tracks `ClientState`, `username`, `displayName`, and `channelID`.  
- **Non‑blocking I/O**: `setNonBlocking(fd)` wraps `fcntl` so neither socket nor stdin ever block.  
- **DNS**: `resolveHostname()` uses `getaddrinfo()` + `inet_ntop()` to turn names into IPv4 strings.  
- **FSM guard**: `isValidTransition()` rejects out‑of‑order messages.  
- **Validation**: I use helpers like `isValidUsername()` and `isValidMessageContent()` rely on things like `std::regex` for validation.  
- **Input dispatch**: `processUserInput()` splits slash‑commands to `handleAuth()`, `handleJoin()`, `handleRename()`, `handleChat()`, or prints an error for anything unknown.

### Message utilities (`message.h` / `message.cpp`)


- **ParsedMessage**: Carries `type`, up to three `param` strings, plus `msgId`/`refMsgId` and a `success` flag.  
- **TCP**: `createTcpMessage()` build CRLF‑terminated commands; `parseTcpMessage()` uses an `istringstream` + `expectToken()` for robust parsing.  
- **UDP**: `createUdpMessage()` pushes a `uint8_t` type, `pushNet16()` for the ID, then null‑terminated fields into a `std::vector<char>`.  
- **Parsing**: `parseUdpMessage()` peels off the 3‑byte header, switches on `type`, and uses `strnlen()` to locate each string.

### TcpClient (`tcp_client.h` / `tcp_client.cpp`)

![TCP Client](/diagrams/tcp2.svg)

This diagram shows how the TCP client extends the base FSM with some specific substates for message framing and timeout tracking etc. It's a bit simpler than UDP since TCP already handles reliable delivery.

- **Connection**: Resolves the server IP and tries each `addrinfo` until `connect()` succeeds.
- **Epoll**: Calls `epoll_create1()`, adds `socketFd` and `STDIN_FILENO`, then loops on `epoll_wait()`.
- **Sending**: `sendMessage()` handles partial writes until the entire string is sent.
- **Receiving**: `processSocketInput(buffer)` reads into `buffer`, splits complete messages, then `parseTcpMessage()`.
- **Timeouts**: On `authenticate()` and `joinChannel()`, sets `waitingForReply = true` with a `replyDeadline` 5 s later. On each epoll cycle, the timeout value shrinks, and missing a reply triggers `ERR` + BYE.
- **Clean exit**: On user Ctrl+C (`terminationRequested`), calls `sendByeMessage()`, then lets TCP’s FIN/ACK handle the graceful close.

### UdpClient (`udp_client.h` / `udp_client.cpp`)

![UDP Client](/diagrams/udp.svg)

This diagram shows the UDP client implementation. It has the same high-level states but adds reliable delivery via a custom confirm/retry protocol. Every outbound message gets a unique ID, and we use `select()` with timeouts to wait for confirmations. We handle duplicates and out-of-order messages aswell(dotted parts). We bind the port to 0 and update the server port after the first **CONFIRM**. We also have explicit handling for dropped packets with retransmissions.

- **Socket & bind**: `initSocket()` picks an ephemeral port so multiple clients don't collide.  
- **Port dance**: `checkAndUpdateServerPort()` adjusts to the server’s dynamic port once we get the first CONFIRM.  
- **Message IDs**: `getNextMsgId()` hands out unique 16‑bit IDs.  
- **Reliable send**: `sendUdpMessage(msg, true)` loops on `select()` with `timeoutMs` until it sees a matching CONFIRM or exhausts `maxRetransmissions`.  
- **REPLY wait**: `awaitReply(refId)` waits upto 5s, ACKs any non‑CONFIRM messages along the way, and returns the `success` flag.  
- **Dup suppression**: `seenMsgIds` drops repeats immediately.

---

## Tools & APIs

- **Sockets**: BSD `socket()`, `connect()`, `sendto()`, `recvfrom()`
- **Async I/O**: Linux `epoll`
- **DNS**: `getaddrinfo()`
- **Timing**: `std::chrono`, `select()` for UDP timeouts
- **Signals**: POSIX `signal()`

---

## References

- **Wireshark**
  https://www.wireshark.org/

- **tcpdump / libpcap**
  https://www.tcpdump.org/

- **Netcat (nc)** – 
  https://nc110.sourceforge.io/

- **RFC 768** – User Datagram Protocol.  
  https://datatracker.ietf.org/doc/html/rfc768

- **RFC 791** – Internet Protocol (IPv4).  
  https://datatracker.ietf.org/doc/html/rfc791

- **RFC 894** – Standard Ethernet “Ethernet II” framing.  
  https://datatracker.ietf.org/doc/html/rfc894

- **RFC 9293** – Transmission Control Protocol.  
  https://datatracker.ietf.org/doc/html/rfc9293

- **epoll(7)** – Linux man page for epoll.  
  https://man7.org/linux/man-pages/man7/epoll.7.html

## License

This project is licensed under the [GNU GPL v3.0](LICENSE).

## Testing

### Testing environments

I tested this both on my WSL aswell as the refference VM.

### A Testing with my custom server
For this part, I created a custom python server that simulates the IPK25-CHAT protocol for TCP and UDP. It handles all message types from specification and provides debug logs to see if everything went well. And it echoes back my messages with the correct display name.
- You can find this server implementation in my github in `project_utils` directory.

**Running the server**
On another terminal:
```bash
python3 server.py -t [tcp/udp] -p [port]
```

#### A.1 Basic CLI Behavior

I'm testing this to ensure that the help output and argument validation works even before any network interactions.

##### A.1.1 Print help
- **Input:**  
```bash
./ipk25chat-client -h
```
- **Expected:**  
  Prints usage info, with exit code 0
- **Actual:**
```bash
Usage: ./ipk25chat-client -t PROTOCOL -s SERVER [-p PORT] [-d TIMEOUT] [-r RETRANSMIT] [-h] 

IPK25-CHAT client application

Required arguments:
-t PROTOCOL       Transport protocol, either 'tcp' or 'udp'
-s SERVER         Server IP address or hostname

Optional arguments:
-p PORT           Server port (default: 4567)
-d TIMEOUT        UDP confirmation timeout in milliseconds (default: 250)
-r RETRANSMIT     Maximum number of UDP retransmissions (default: 3)
-h                Display this help message and exit
```

##### A.1.2 Missing required arguments
**Input:**  
  ```bash
  ./ipk25-chat -t tcp
  ```
**Expected:**  
`Some error message that other parameters must be specified` + error code `1`

**Actual:**  
```bash
 Error: Server address (-s) must be specified
```

---

#### A.2 TCP Functional Tests

Im testing this to verify the complete TCP handshake, the message exchanging and graceful shutting down.

##### A.2.1 Successful authentication
**Input:**  
```bash
./ipk25chat-client -t tcp -s 127.0.0.1 -p 4567
```
then
```bash
/auth xsevcim00 secret martin
```
**Expected:**  
```bash
Action Success: Auth success.
Server: martin has joined default.
```
**Actual:**  
```bash
Action Success: Auth success.
Server: martin has joined default.
```

##### A.2.2 Graceful termination
**Input:**  
Same as above, then:
- do `ctr+d`
- or `ctr+c`
- or (custom /bye implementation)
```bash
/bye
```
**Expected:**  
Client sends BYE and exits without errors (exit 0).  
**Actual:**  
- **server debug**:
```bash
2025-04-18 18:24:49 [DEBUG] [TCP] chunk: b'BYE FROM martin\r\n'
2025-04-18 18:24:49 [INFO] [TCP] ('127.0.0.1', 53116) disconnected
2025-04-18 18:24:49 [INFO] [TCP] Handler closed ('127.0.0.1', 53116)
```
- on user side, nothing else gets outputted
---

##### A.2.3 Chat help commands
**Input:**  
Same as above, then:
```bash
/help
```
**Expected:**
Help message contaning all chat commands
**Actual:**  
```bash
available commands:
  /auth <username> <secret> <displayName>
  /join <channel>
  /rename <displayName>
  /bye
  /help
```


##### A.2.4 Renaming
**Input:**  
Same as above + write some messages, then:
```bash
/rename NewName
```
And write more messages
**Example:**
```bash
hello
/rename newMartin
hello
```
**Expected:**
```bash
martin: hello
newMartin: hello
```
**Actual:**  
```bash
hello
martin: hello
/rename newMartin
display name updated to: newMartin
hello
martin: hello
```

##### A.2.4 Joining another server
**Input:**  
Same as above, then
```bash
/join channel2
```
**Expected:**
```bash
Server: martin has joined channel2.
Action Success: Join success.
```
**Actual:**  
```bash
Server: martin has joined channel2.
Action Success: Join success.
```

##### A.2.4 Malformed message handling

Testing this to ensure that the client detects and reports protocol errors

**Precondition:**
I altered my server to write `"FOO BAR\r\n"` after the user AUTHs

**Input:**  
Same as above, then
```bash
/auth sevcim secret martin
```
**Expected:**
```bash
Action Success: Auth success.
Server: martin has joined default.
ERROR: Received invalid message from server.
```
**Actual:**  
```bash
Action Success: Auth success.
Server: martin has joined default.
ERROR: Received invalid message from server.
```
Debug output from server:
```bash
2025-04-18 19:14:38 [INFO] [TCP TEST] Injecting malformed line → b'FOO BAR\r\n'
2025-04-18 19:14:38 [DEBUG] [TCP] chunk: b'ERR FROM martin IS Malformed message\r\n'
2025-04-18 19:14:38 [DEBUG] [TCP] line parts: ['ERR', 'FROM', 'martin', 'IS', 'Malformed', 'message']
```
---


#### A.3 UDP Functional Tests

Testing this to validate the UDP workflow, retransmissions and confirms.

##### A.3.1 Successful authentication
**Input:**  
```bash
./ipk25chat-client -t udp -s 127.0.0.1 -p 4567
```
then
```bash
/auth xsevcim00 secret martin
```
**Expected:**  
```bash
Action Success: Auth success.
Server: martin has joined default.
```
**Actual:**  
```bash
Action Success: Auth success.
Server: martin has joined default.
```

##### A.3.2 Graceful termination
**Input:**  
Same as above, then:
- do `ctr+d`
- or `ctr+c`
- or (custom /bye implementation)
```bash
/bye
```
**Expected:**  
Client sends BYE and exits without errors (exit 0).  
**Actual:**  
- **server debug**:
```bash
2025-04-18 18:45:28 [DEBUG] [PARSE] type=0xFF id=2 payload_len=7
2025-04-18 18:45:28 [DEBUG]   Fields: ['martin']
2025-04-18 18:45:28 [DEBUG] [UDP] pkt type=0xFF id=2 params=['martin']
2025-04-18 18:45:28 [DEBUG] [BUILD] CONFIRM refMsgId=2
2025-04-18 18:45:28 [DEBUG] [PACK16] 2 -> b'\x00\x02'
2025-04-18 18:45:28 [DEBUG] [BYTES] b'\x00\x00\x02'
2025-04-18 18:45:28 [INFO] [UDP] BYE from martin, closing
```
- on user side, nothing else gets outputted
---

##### A.3.3 Chat help commands
**Input:**  
Same as above, then:
```bash
/help
```
**Expected:**
Help message contaning all chat commands
**Actual:**  
```bash
available commands:
  /auth <username> <secret> <displayName>
  /join <channel>
  /rename <displayName>
  /bye
  /help
```


##### A.3.4 Renaming
**Input:**  
Same as above + write some messages, then:
```bash
/rename NewName
```
And write more messages
**Example:**
```bash
hello
/rename newMartin
hello
```
**Expected:**
```bash
martin: hello
newMartin: hello
```
**Actual:**  
```bash
hello
martin: hello
/rename newMartin
display name updated to: newMartin
hello
martin: hello
```

##### A.3.5 Joining another server
**Input:**  
Same as above, then
```bash
/join channel2
```
**Expected:**
```bash
Server: martin has joined channel2.
Action Success: Join success.
```
**Actual:**  
```bash
Server: martin has joined channel2.
Action Success: Join success.
```

##### A.3.6 Malformed message handling
**Precondition:**
I altered my server send `b'\x04\x00'` after the user AUTHs

**Input:**  
Same as above, then
```bash
/auth sevcim secret martin
```
**Expected:**
```bash
Action Success: Auth success.
Server: martin has joined default.
ERROR: Received invalid message from server.
```
**Actual:**  
```bash
ERROR: Received malformed message, closing.
Action Success: Auth success.
```
Debug output from server:
```bash
2025-04-18 19:15:11 [DEBUG] [PARSE] type=0xFE id=2 payload_len=25
2025-04-18 19:15:11 [DEBUG] [ID_GEN] -> 0
2025-04-18 19:15:11 [DEBUG] Fields: ['martin', 'Malformed message']
```

---

### B. Testing Using Netcat
To make sure the client is robust, I'm also trying some tests on Netcat.

#### B.1 Basic Functionality

#### B.2 TCP Malformed message
**First:**
Open a server on other terminal:
```bash
nc -lk 4567
```
**Input:**  
```bash
./ipk25chat-client -t tcp -s 127.0.0.1 -p 4567
/auth xsevcim secret martin
```
**Then:**
On the server terminal do:
```bash
REPLY OK IS Auth success.
FOO BAR
```
And close the server
**Expected:**  
```bash
Action Success: Auth success.
ERROR: Received invalid message from server.
```
- **Actual:**  
```bash
Action Success: Auth success.
ERROR: Received invalid message from server.
```

#### B.2 TCP/UDP No Reply
**First:**
Open a server on other terminal:
```bash
nc -lk 4567
```
**Input:**  
```bash
./ipk25chat-client -t tcp -s 127.0.0.1 -p 4567
/auth xsevcim secret martin
```
**Then:**
On server terminal, wait 5 seconds
**Expected:**  
```bash
ERR FROM martin IS No REPLY in time
BYE FROM martin
```
- **Actual:**  
```bash
ERR FROM martin IS No REPLY in time
BYE FROM martin
```
```bash
ERROR: No REPLY in 5s
```
---


### C. Testing with tcpdump

Testing this to ensure on‑the‑wire packets match the protocol framing and content.

#### C.1 TCP Capture
**Precondition:**
On one terminal:
```bash
sudo tcpdump -i lo -nn port 4567 -w tcp_chat.pcap
```
On another terminal (ill be using my python server):
```bash
nc -lk 4567
```
**Input:**  
```bash
./ipk25chat-client -t tcp -s 127.0.0.1 -p 4567
/auth sevcim secret martin
hello
/bye
```
**Then:**
On the tcpdump terminal:
```bash
tcpdump -nn -r tcp_chat.pcap
```
**Expected:** 
Lines indicating packets
- **Actual:**  
```bash
...
19:37:41.399619 IP 127.0.0.1.60980 > 127.0.0.1.4567: Flags [.], ack 1, win 512, options [nop,nop,TS val 2889499070 ecr 2889499070], length 0
19:37:47.210284 IP 127.0.0.1.60980 > 127.0.0.1.4567: Flags [P.], seq 1:37, ack 1, win 512, options [nop,nop,TS val 2889504881 ecr 2889499070], length 36
19:37:47.210312 IP 127.0.0.1.4567 > 127.0.0.1.60980: Flags [.], ack 37, win 512, options [nop,nop,TS val 2889504881 ecr 2889504881], length 0
19:37:47.210702 IP 127.0.0.1.4567 > 127.0.0.1.60980: Flags [P.], seq 1:28, ack 37, win 512, options [nop,nop,TS val 2889504881 ecr 2889504881], length 27
19:37:47.210723 IP 127.0.0.1.60980 > 127.0.0.1.4567: Flags [.], ack 28, win 512, options [nop,nop,TS val 2889504881 ecr 2889504881], length 0\
...

```
#### C.2 UDP Capture
**Precondition:**
On one terminal:
```bash
sudo tcpdump -i lo -nn '(udp port 4567) or (udp port 60913) or (udp port 42985)' -w udp_full.pcap
```
On another terminal (ill be using my python server):
```bash
nc -lk 4567
```
**Input:**  
```bash
./ipk25chat-client -t udp -s 127.0.0.1 -p 4567
/auth sevcim secret martin
hello
/bye
```
**Then:**
On the tcpdump terminal:
```bash
tcpdump -nn -r udp_all.pcap
```
**Expected:** 
Lines indicating packets
- **Actual:**  
```bash
19:48:16.460684 IP 127.0.0.1.4567 > 127.0.0.1.32913: UDP, length 3
19:48:16.461088 IP 127.0.0.1.33964 > 127.0.0.1.32913: UDP, length 20
19:48:16.461132 IP 127.0.0.1.32913 > 127.0.0.1.33964: UDP, length 3
19:48:16.461467 IP 127.0.0.1.33964 > 127.0.0.1.32913: UDP, length 3
19:48:17.973506 IP 127.0.0.1.32913 > 127.0.0.1.33964: UDP, length 9
19:48:17.973964 IP 127.0.0.1.33964 > 127.0.0.1.32913: UDP, length 3
19:48:17.974390 IP 127.0.0.1.33964 > 127.0.0.1.32913: UDP, length 9
19:48:17.974440 IP 127.0.0.1.32913 > 127.0.0.1.33964: UDP, length 3
19:48:17.974820 IP 127.0.0.1.33964 > 127.0.0.1.32913: UDP, length 3
19:48:18.873575 IP 127.0.0.1.32913 > 127.0.0.1.33964: UDP, length 5
19:48:18.873982 IP 127.0.0.1.33964 > 127.0.0.1.32913: UDP, length 3
...
```

### D. Checking on Wireshark

For visually validating the packet sequences, headers and so on.

I did:
```bash
./ipk25chat-client -t udp/tcp -s 127.0.0.1 -p 4567
/auth sevcim secret martin
/join general
hello everyone
/bye
```

Then checked if im recieving the packets and yes:

**TCP**

![TCP Wireshark](/diagrams/wiresharktcp.png)

**UDP**

![UDP Wireshark](/diagrams/wiresharkudp.png)


### E. Testing via Discord Reference server

During my implementation of this project, I mainly used the discord server `anton5.fit.vutbr.cz` which worked really well for testing. Here's a screenshot that to see that TCP works (dont wanna bloat this with even more screenshots of everything):

![UDP Wireshark](/diagrams/discord.png)


---

### Additional Notes:
All diagrams were created with PlantUML

- **PlantUML** – Open‑source tool to draw UML and other diagrams from plain text.  
  https://plantuml.com/