Below is a version of the specification document with all the UDP-specific details intact and the TCP variant sections removed. All the original UDP details—including message types, parameter rules, header structure, dynamic port allocation, reliability mechanisms, and sample diagrams—are preserved.

---

# IPK Project 2: Client for a chat server using the `IPK25-CHAT` protocol

## Specification
The `IPK25-CHAT` protocol defines a high-level behaviour, which can then be implemented on top of one of the well-known transport protocols such as UDP [RFC768].  
Each of these options comes with its challenges.  
As for the network layer protocol requirements, only IPv4 must be supported by your implementation.

| Protocol property       | Value     |
| ----------------------- | --------- |
| Default server port     | `4567`    |
| Network protocols       | `IPv4`    |
| Transport protocols     | `UDP`     |
| Supported charset       | `us-ascii`|

### Message types

The protocol defines the following message types to correctly represent the behaviour of each party communicating with this protocol:

| Type name | Notes                        | Description                                                                 |
| --------- | ---------------------------- | --------------------------------------------------------------------------- |
| `AUTH`    | This is a _request message_  | Used for client authentication (signing in) using a user-provided username, display name and password |
| `BYE`     |                              | Either party can send this message to indicate that the conversation/connection is to be terminated |
| `CONFIRM` | `UDP` only                   | Only leveraged in specific protocol variants (UDP) to explicitly confirm the successful delivery of the message to the other party on the application level |
| `ERR`     |                              | Indicates that an error has occurred while processing the other party's last message; this directly results in a graceful termination of the communication |
| `JOIN`    | This is a _request message_  | Represents the client's request to join a chat channel by its identifier      |
| `MSG`     |                              | Contains user display name and a message designated for the channel they're joined in |
| `PING`    | `UDP` only                   | Periodically sent by a server to all its clients who are using the UDP variant of this protocol as an aliveness check mechanism |
| `REPLY`   |                              | Some messages (requests) require a positive/negative confirmation from the other side; this message contains such data |

The following table shows the mandatory parameters of given message types.  
Their names (identifiers) will be used further in the document to signify the placement of their values in the protocol messages.

| FSM name | Mandatory message parameters         |
| -------- | -------------------------------------- |
| `AUTH`   | `Username`, `DisplayName`, `Secret`    |
| `JOIN`   | `ChannelID`, `DisplayName`             |
| `ERR`    | `DisplayName`, `MessageContent`        |
| `BYE`    | `DisplayName`                          |
| `MSG`    | `DisplayName`, `MessageContent`        |
| `REPLY`  | `true`, `MessageContent`               |
| `!REPLY` | `false`, `MessageContent`              |

The values for the message contents defined above will be extracted from the provided user input.  
Handling user-provided input is discussed at a [later point](#client-behaviour-input-and-commands).

| Message parameter | Max. length | Characters                                                        |
| ----------------- | ----------- | ----------------------------------------------------------------- |
| `MessageID`       | `uint16`    |                                                                   |
| `Username`        | `20`        | [`[a-zA-Z0-9_-]`](https://regexr.com/8b6ou) (e.g., `Abc_00-7`)       |
| `ChannelID`       | `20`        | [`[a-zA-Z0-9_-]`](https://regexr.com/8b6ou) (e.g., `Abc_00-7`)       |
| `Secret`          | `128`       | [`[a-zA-Z0-9_-]`](https://regexr.com/8b6ou) (e.g., `Abc_00-7`)       |
| `DisplayName`     | `20`        | *Printable characters* (`0x21-7E`)                                 |
| `MessageContent`  | `60000`     | *Printable characters with space and line feed* (`0x0A,0x20-7E`)    |

These parameter identifiers will be used in the following sections to denote their locations within the protocol messages or program output.  
The notation with braces (`{}`) is used for required parameters, e.g., `{Username}`.  
Optional parameters are specified in square brackets (`[]`).  
Both braces and brackets must not be a part of the resulting string after the interpolation.  
The vertical bar denotes a choice of one of the options available.  
Quoted values in braces or brackets are to be interpreted as constants, e.g., `{"Ahoj" | "Hello"}` means either `Ahoj` or `Hello`.

Based on the parameter content limitations defined above, there may be issues with IP fragmentation [RFC791, section 3.2] caused by exceeding the default Ethernet MTU of `1500` octets, as determined by [RFC894].  
The program behaviour will be tested in a controlled environment where such a state will not matter.  
However, there may be negative real-world consequences when IP fragmentation is allowed to occur in a networking application.

### Client behaviour

The following Mealy machine (a finite state machine) describes the client's behaviour.  
<span style="color:red">Red values</span> indicate server-sent messages (input) to the client.  
<span style="color:blue">Blue values</span> correspond to the client-sent messages (output) to the server.  
There are a few important notes for the schema interpretation:

- The underscore (`_`) value represents *no message* (i.e., no input is received / no output is sent).
- The star (`*`) value represents *all possible messages* (i.e., any input is received).
- When multiple values are specified on the input/output positions and separated by a comma, they are to be interpreted as "any one of".
- `REPLY` and `!REPLY` correspond to the same message type (`REPLY`); the exclamation mark (`!`) represents a negative version of the reply, `*REPLY` stands for any reply (either positive or negative), and `REPLY` in itself represents a positive outcome.
- `CONFIRM` and `PING` messages are not shown in the FSM as this is an ideal model of possible communication.

![Client FSM](diagrams/protocol_fsm_client.svg)

Request messages (`AUTH` and `JOIN`) initiate an asynchronous process on the remote server.  
That always leads to the server sending a `REPLY` message when this process finishes.  
Such behaviour can be seen in the `auth` and `join` states, where the client is waiting for a `REPLY` message to be received.  
The `REPLY` messages inform the client whether the request has been fulfilled correctly or has failed.

By inspecting the client state machine, you can notice that no `JOIN` message is necessary after a successful authentication—the server must join you in a default channel immediately.  
The `JOIN` message is then only used when switching between channels.

Negative replies (`!REPLY`) to any potential messages that were sent to the server must not negatively impact the functionality of the client program.  
Joining channels or user authentication is sometimes expected to fail.  
This should be apparent from the state machine.

The client must truncate messages longer than the protocol-allowed maximum before sending them to the remote server.  
If such an event occurs, a local error message must also inform the client.  
The local error output format is further specified in the [client output section](#client-output).

Both `ERR` and `BYE` messages must result in graceful connection termination.  
Receiving either one means that the current connection has been finalized by the sender of the corresponding message.  
`BYE` and `ERR` are the final messages sent/received in a conversation (except their potential confirmations in the UDP variant).

The program might receive additional messages from the networking layer after transitioning to the `end` state.  
However, according to the FSM, the transition to the `end` state also means that the client cannot process any other messages.  
Behaviour of the program in such a state is undefined.  
The client program is neither required to process nor required to prevent the processing of such messages; only graceful connection termination is required.

### UDP variant
The first variant of the `IPK25-CHAT` protocol is built on top of UDP [RFC768].  
As the UDP is connection-less and the delivery is unreliable, using it as a transport layer protocol poses particular challenges that must be addressed at the application layer.  
These challenges include, but are not limited to, datagram loss, duplication, and reordering.  
Furthermore, this protocol variant leverages dynamic port allocation to separate communication with each client after receiving the initial message.

That simplifies identification and client message handling on the server side and does not particularly complicate things for the client.  
After the initial message (`AUTH`) is sent to the server, the client must anticipate the response to originate from a different transport protocol source port.

The equivalent behaviour is also used by other protocols, such as TFTP [RFC1350] (you can read details about this mechanism in [section 4 of the RFC](https://datatracker.ietf.org/doc/html/rfc1350#autoid-4)).  
The behaviour described above can be seen in the snippet below.  
The `dyn1` and `dyn2` values represent the dynamic ports assigned when binding the sockets.  
You can disregard the message contents; the aim is to illustrate the port-switching mechanism.

```
 port  | client                                          server | port  | type
-------+--------------------------------------------------------+-------+-------
 :dyn1 | |2|0|username|0|Nick_Name|0|Secret|0|  -->             | :4567 | AUTH
 :dyn1 |                                             <--  |0|0| | :4567 | CONFIRM
 :dyn1 |                   <--  |1|0|1|Authentication success.| | :dyn2 | REPLY
 :dyn1 | |0|0|  -->                                             | :dyn2 | CONFIRM
 :dyn1 |               ...                    ...               | :dyn2 |
```

The diagram below shows the order of protocol headers sent at the beginning of each protocol message:
```
+----------------+------------+------------+--------------+
|  Local Medium  |     IP     |     UDP    |  IPK25-CHAT  |
+----------------+------------+------------+--------------+
```

The following snippet shows what the UDP header looks like:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|          Source Port          |       Destination Port        |
+---------------+---------------+---------------+---------------+
|            Length             |           Checksum            |
+---------------+---------------+---------------+---------------+
```

> <span style="color:orange">If the client is used behind NAT, it will most probably not receive any communication from server-allocated dynamic port.
</span>

> <span style="color:gray">Food for thought: Can you identify what kind of security issues there are for this protocol if the dynamic server port is used as the sole identifier of the user connection?
</span>

#### Solving Transport Protocol Issues
Since message delivery is inherently unreliable, handling message transport issues at the application level is necessary.

> <span style="color:orange">All incoming server messages must be processed by the client.  
Unsuitable messages (when waiting for a specific message type, such as a `CONFIRM` or a `REPLY` message) must not be discarded or ignored by the client.
</span>

**Packet loss** can be detected using mandatory message confirmation with timeouts.  
Once a message is sent, the other party must confirm its successful delivery to the sender.  
The confirmation should be sent immediately after receiving the message, regardless of any potential higher-level processing issues—unless the connection has already been successfully terminated; in such a case, it is valid not to respond to the message at all.  
The message is considered lost in transit when the original sender does not receive the confirmation within a given timespan.  
Messages lost in transit are re-transmitted until the confirmation is successfully received or an internal re-try condition is triggered.  
Only the original sender performs message re-transmit, not the receiver (confirmation messages are never re-transmitted or explicitly confirmed).

| Variable             | Recommended value | Notes              |
| -------------------- | ----------------: | ------------------ |
| Confirmation timeout | `250ms`           |                    |
| Retry count          | `3`               | 1 initial + 3 retries |

**Packet delay/duplication** can be detected by keeping track of processed unique MessageIDs.  
Once a message is received, its unique ID is compared to a list of already-seen MessageIDs.  
Afterwards, there are two options: either the MessageID was not previously seen (the message is then processed typically), or the MessageID is contained within the list, meaning it has already been processed.  
In the latter's case, only the delivery confirmation is sent to the message sender.  
No additional action is taken otherwise.

The transport protocol issues and their solutions described above can be seen visualised in the following diagrams.

| Packet loss                        | Packet delay/duplication             |
| :--------------------------------: | :----------------------------------: |
| ![UDP Loss](diagrams/udp_loss.svg) | ![UDP Delay](diagrams/udp_delay.svg) |

> <span style="color:gray">Food for thought: What would be the maximum message size for this protocol variant?  
> What would happen on the network layer if the specification allowed messages of such size?
</span>

#### Message Header
The following snippet presents the general structure of any application message sent via this protocol variant.  
You can notice a uniform header of 3 bytes, which will be present at the beginning of each message (both sent and received).  
There are two distinct fields, `Type` and `MessageID` (more details are in the table below the snippet).  
The fields comprise 1B for the message type and 2B for the MessageID.  
The following content is variable in length and depends on the message type.  
Some messages may not have any additional content at all.
```
 0      7 8     15 16    23 24
+--------+--------+--------+---~~---+
|  Type  |    MessageID    |  ....  |
+--------+--------+--------+---~~---+
```

| Field name  | Value     | Notes                                   |
| :---------- | --------: | --------------------------------------- |
| `Type`      | `uint8`   |                                         |
| `MessageID` | `uint16`  | Sent in network byte order              |

##### Message `Type`
The table below shows the mapping of the protocol message types (as defined above) to the values in the first field (`Type`) of the application datagram header for this protocol variant.  
This unique number is used to identify which message has been received.

| Message type | Field value |
| ------------ | ----------- |
| `CONFIRM`    | `0x00`      |
| `REPLY`      | `0x01`      |
| `AUTH`       | `0x02`      |
| `JOIN`       | `0x03`      |
| `MSG`        | `0x04`      |
| `PING`       | `0xFD`      |
| `ERR`        | `0xFE`      |
| `BYE`        | `0xFF`      |

##### `MessageID`
MessageID is a 2-byte number for a unique identification of a particular message.  
The value must never appear as a message identifier of a different message in the communication once it has been used.  
Each side of the communication has its identifier sequence.  
Your implementation must use values starting from `0`, incremented by `1` for each message _sent_, **not received**.

#### Message Contents
This section describes the messages used in this protocol variant.  
The following snippets describe different message field notations.

This snippet shows two fields, one byte each:
```
+--------+---+
|  0x00  | 0 |
+--------+---+
```

This snippet represents a variable length data field terminated by a zero byte:
```
+----------~~----------+---+
| Variable length data | 0 |
+----------~~----------+---+
```

The particular message type specifications follow based on the previous snippets.  
Datagram examples always show the whole application-level message, including the uniform message header with concrete values where appropriate.

##### `CONFIRM`
```
  1 byte       2 bytes      
+--------+--------+--------+
|  0x00  |  Ref_MessageID  |
+--------+--------+--------+
```

| Field name      | Value     | Notes                                               |
| :-------------- | --------: | --------------------------------------------------- |
| `Ref_MessageID` | `uint16`  | The MessageID value of the message being confirmed  |

##### `REPLY`
```
  1 byte       2 bytes       1 byte       2 bytes      
+--------+--------+--------+--------+--------+--------+--------~~---------+---+
|  0x01  |    MessageID    | Result |  Ref_MessageID  |  MessageContents  | 0 |
+--------+--------+--------+--------+--------+--------+--------~~---------+---+
```

| Field name        | Value      | Notes                                                             |
| :---------------- | ---------: | ----------------------------------------------------------------- |
| `Result`          | `0` or `1` | `0` indicates failure, `1` indicates success                      |
| `Ref_MessageID`   | `uint16`   | The MessageID value of the message replying to                    |
| `MessageContents` | `string`   | Contains only non‑`0` bytes, always followed by a zero byte         |

##### `AUTH`
```
  1 byte       2 bytes      
+--------+--------+--------+-----~~-----+---+-------~~------+---+----~~----+---+
|  0x02  |    MessageID    |  Username  | 0 |  DisplayName  | 0 |  Secret  | 0 |
+--------+--------+--------+-----~~-----+---+-------~~------+---+----~~----+---+
```

| Field name    | Value    | Notes                                                                         |
| :------------ | -------: | ----------------------------------------------------------------------------- |
| `Username`    | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |
| `DisplayName` | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |
| `Secret`      | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |

##### `JOIN`
```
  1 byte       2 bytes      
+--------+--------+--------+-----~~-----+---+-------~~------+---+
|  0x03  |    MessageID    |  ChannelID | 0 |  DisplayName  | 0 |
+--------+--------+--------+-----~~-----+---+-------~~------+---+
```

| Field name    | Value    | Notes                                                                         |
| :------------ | -------: | ----------------------------------------------------------------------------- |
| `ChannelID`   | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |
| `DisplayName` | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |

##### `MSG`
```
  1 byte       2 bytes      
+--------+--------+--------+-------~~------+---+--------~~---------+---+
|  0x04  |    MessageID    |  DisplayName  | 0 |  MessageContents  | 0 |
+--------+--------+--------+-------~~------+---+--------~~---------+---+
```

| Field name        | Value    | Notes                                                                         |
| :---------------- | -------: | ----------------------------------------------------------------------------- |
| `DisplayName`     | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |
| `MessageContents` | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |

##### `ERR`
```
  1 byte       2 bytes
+--------+--------+--------+-------~~------+---+--------~~---------+---+
|  0xFE  |    MessageID    |  DisplayName  | 0 |  MessageContents  | 0 |
+--------+--------+--------+-------~~------+---+--------~~---------+---+
```

*The structure is identical to the `MSG` message.*

##### `BYE`
```
  1 byte       2 bytes
+--------+--------+--------+-------~~------+---+
|  0xFF  |    MessageID    |  DisplayName  | 0 |
+--------+--------+--------+-------~~------+---+
```

| Field name        | Value    | Notes                                                                         |
| :---------------- | -------: | ----------------------------------------------------------------------------- |
| `DisplayName`     | `string` | Contains only non‑`0` bytes, always followed by a zero byte                    |

##### `PING`
```
  1 byte       2 bytes
+--------+--------+--------+
|  0xFD  |    MessageID    |
+--------+--------+--------+
```

---

#### UDP transport summarised

The following diagrams show the protocol's behaviour in different transport conditions:

| Packet loss                        | Packet delay/duplication             |
| :--------------------------------: | :----------------------------------: |
| ![UDP Loss](diagrams/udp_loss.svg) | ![UDP Delay](diagrams/udp_delay.svg) |

| Session initialization                    | Session termination (Client)                      | Session termination (Server)                      |
| :---------------------------------------: | :-----------------------------------------------: | :-----------------------------------------------: |
| ![UDP Client INIT](diagrams/udp_open.svg) | ![UDP Client TERM](diagrams/udp_close_client.svg) | ![UDP Server TERM](diagrams/udp_close_server.svg) |

#### Message Content Parameter Mapping
The following table shows a mapping of message content rules of the content grammar above to the message types and parameters available in the `IPK25-CHAT` protocol.  
Note that the message of type `CONFIRM` is used in the UDP variant to ensure correct delivery.

| Message type | Message parameter template                                          |
| ------------ | ------------------------------------------------------------------- |
| `ERR`        | `ERR FROM {DisplayName} IS {MessageContent}\r\n`                     |
| `REPLY`      | `REPLY {"OK"|"NOK"} IS {MessageContent}\r\n`                         |
| `AUTH`       | `AUTH {Username} AS {DisplayName} USING {Secret}\r\n`                |
| `JOIN`       | `JOIN {ChannelID} AS {DisplayName}\r\n`                              |
| `MSG`        | `MSG FROM {DisplayName} IS {MessageContent}\r\n`                     |
| `BYE`        | `BYE FROM {DisplayName}\r\n`                                         |
| `CONFIRM`    | *(Contains only a reference MessageID)*                             |
| `PING`       | *(No additional content)*                                            |

Remember that values for variables in the templates above further conform to rules defined by the message grammar.

> <span style="color:gray">Food for thought: Why is the message termination string `\r\n` necessary?  
> How does it compare to processing messages sent over the UDP?
</span>

---

## Program Execution

### CLI arguments
The implemented program must support the following command line arguments:

| Argument | Value                                           | Possible values        | Meaning or expected behaviour                         |
| -------- | ----------------------------------------------- | ---------------------- | ----------------------------------------------------- |
| `-t`     | <span style="color:orange">User provided</span> | `tcp` or `udp`         | Transport protocol used for connection              |
| `-s`     | <span style="color:orange">User provided</span> | IP address or hostname | Server IP or hostname                                |
| `-p`     | `4567`                                          | `uint16`               | Server port                                          |
| `-d`     | `250`                                           | `uint16`               | UDP confirmation timeout (in milliseconds)         |
| `-r`     | `3`                                             | `uint8`                | Maximum number of UDP retransmissions              |
| `-h`     |                                                 |                        | Prints program help output and exits               |

> <span style="color:orange">Edge cases of argument processing will not be a part of evaluation.  
Application behaviour is undefined in such cases.
</span>

### Client behaviour, input and commands
- All user input from `stdin` is either a local command or a chat message.
- Valid commands are prefixed with a `/` and followed by parameters in the specified order.
- Supported commands include:  
  - `/auth {Username} {Secret} {DisplayName}` – sends an `AUTH` message and locally sets the DisplayName.
  - `/join {ChannelID}` – sends a `JOIN` message.
  - `/rename {DisplayName}` – locally changes the display name.
  - `/help` – prints supported commands.
- Input not prefixed by `/` is treated as a chat message and sent as a `MSG`.
- Only one user input is processed at a time until its action (including message confirmation and REPLY, if applicable) is completed.

> <span style="color:orange">Edge cases of input processing will not be part of evaluation.
</span>

### Client program and connection termination
- The client must gracefully exit on receiving an interrupt signal (`C-c`), processing a `BYE` message as necessary.
- If the client receives a `BYE` or an `ERR` from the server, it should respond appropriately with a CONFIRM and then terminate.
- For UDP, if a CONFIRM message is lost, retransmissions are triggered per the reliability rules.

### Client exception handling
- On receiving a malformed message: display a local error, send an `ERR` (if possible), and terminate gracefully.
- If a UDP confirmation times out or no `REPLY` is received within 5 seconds, the client should display an error and terminate with an error code.

### Client output
- Incoming `MSG`:  
  ```
  {DisplayName}: {MessageContent}\n
  ```
- Incoming `ERR`:  
  ```
  ERROR FROM {DisplayName}: {MessageContent}\n
  ```
- Incoming `REPLY`:  
  - Success:  
    ```
    Action Success: {MessageContent}\n
    ```
  - Failure:  
    ```
    Action Failure: {MessageContent}\n
    ```
- Local errors:  
  ```
  ERROR: {MessageContent}\n
  ```

> <span style="color:deepskyblue">The default output format must remain as specified, though custom formatting may be toggleable.
</span>

### Client logging
- All logging should be sent to `stderr` (recommended using a variadic print macro in C/C++).
- Example macro:
  ```c
  #ifdef DEBUG_PRINT
  #define printf_debug(format, ...) fprintf(stderr, "%s:%-4d | %15s | " format "\n", __FILE__, __LINE__, __func__, __VA_ARGS__)
  #else
  #define printf_debug(format, ...) (0)
  #endif
  ```

---

## Functionality Illustration

### Client run examples
- **Help output:**  
  ```shell
  ./ipk25-chat -h
  ```

- **UDP variant examples:**
  ```shell
  ./ipk25-chat -t udp -s ipk.fit.vutbr.cz -p 10000
  ./ipk25-chat -t udp -s 127.0.0.1 -p 3000 -d 100 -r 1
  ```

### Client I/O examples
- **Example 1:** Authenticating, joining a channel, and sending a message:
  <pre>
  <span style="color:turquoise">/auth username Abc-123-BCa Display_Name</span>
  Action Success: Auth success.
  Server: Display_Name has joined default.
  <span style="color:turquoise">/join channel1</span>
  Action Success: Join success.
  Server: Display_Name has joined channel1.
  <span style="color:turquoise">Hello, this is a message to the current channel.</span>
  </pre>

- **Example 2:** Receiving messages from other users:
  <pre>
  <span style="color:turquoise">/auth username Abc-123-BCa Display_Name</span>
  Action Success: Auth success.
  Server: Display_Name has joined default.
  User_1: Lorem ipsum dolor sit amet, consectetuer adipiscing elit.
  User_2: Donec ipsum massa, ullamcorper in, auctor et, scelerisque sed, est. Quisque porta.
  <span style="color:turquoise">Et harum quidem rerum facilis est et expedita distinctio. Nullam dapibus fermentum ipsum.</span>
  User_1: Duis ante orci, molestie vitae vehicula venenatis, tincidunt ac pede.
  </pre>

> <span style="color:orange">Note: The server does not send your own messages back to you.
</span>

#### Implementation limitations
- The evaluation suite will simulate interactive user input.  
Your solution should read complete lines (terminated by `\n`) and process them as a whole.  
Avoid interactive menus, real-time character processing, or behavior changes based on input type.

> <span style="color:orange">Deviating from these recommendations may lead to unexpected behaviour during evaluation.
</span>
