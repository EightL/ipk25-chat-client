# IPK Project 2: Client for a chat server using the `IPK25-CHAT` protocol

> The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 [RFC2119].

This project's task is to design and implement a client application that can communicate with a remote server using the `IPK25-CHAT` protocol.
The protocol has two variants - each built on a different transport protocol.
**You are required to implement both variants.**

> <span style="color:deepskyblue">Please focus on the networking aspects of this project as much as possible.
Do not start with input edge cases, validation, or idiot-proofing your application.
The networking capabilities will be the main focus of the functional testing when grading your application.
</span>


## Table of Contents

- [IPK Project 2: Client for a chat server using the `IPK25-CHAT` protocol](#ipk-project-2-client-for-a-chat-server-using-the-ipk25-chat-protocol)
  - [Table of Contents](#table-of-contents)
  - [Specification](#specification)
    - [Message types](#message-types)
    - [Client behaviour](#client-behaviour)
    - [UDP variant](#udp-variant)
      - [Solving Transport Protocol Issues](#solving-transport-protocol-issues)
      - [Message Header](#message-header)
        - [Message `Type`](#message-type)
        - [`MessageID`](#messageid)
      - [Message Contents](#message-contents)
        - [`CONFIRM`](#confirm)
        - [`REPLY`](#reply)
        - [`AUTH`](#auth)
        - [`JOIN`](#join)
        - [`MSG`](#msg)
        - [`ERR`](#err)
        - [`BYE`](#bye)
        - [`PING`](#ping)
      - [UDP transport summarised](#udp-transport-summarised)
    - [TCP variant](#tcp-variant)
      - [Message Grammar](#message-grammar)
      - [Message Content Parameter Mapping](#message-content-parameter-mapping)
  - [Program Execution](#program-execution)
    - [CLI arguments](#cli-arguments)
    - [Client behaviour, input and commands](#client-behaviour-input-and-commands)
    - [Client program and connection termination](#client-program-and-connection-termination)
    - [Client exception handling](#client-exception-handling)
    - [Client output](#client-output)
    - [Client logging](#client-logging)
  - [Functionality Illustration](#functionality-illustration)
    - [Client run examples](#client-run-examples)
    - [Client I/O examples](#client-io-examples)
      - [Implementation limitations](#implementation-limitations)
    - [Network Transport](#network-transport)
      - [Using Captured PCAPs](#using-captured-pcaps)
      - [UDP protocol variant](#udp-protocol-variant)
      - [TCP protocol variant](#tcp-protocol-variant)
    - [Reference Resources](#reference-resources)
      - [Using Public Reference Server](#using-public-reference-server)
      - [Using Wireshark Protocol Dissector](#using-wireshark-protocol-dissector)
      - [Using netcat](#using-netcat)
        - [UDP communication](#udp-communication)
        - [TCP communication](#tcp-communication)
      - [Using tcpdump](#using-tcpdump)
  - [Submission](#submission)
  - [Evaluation](#evaluation)
  - [Contributing](#contributing)
  - [Bibliography](#bibliography)


## Specification
The `IPK25-CHAT` protocol defines a high-level behaviour, which can then be implemented on top of one of the well-known transport protocols such as TCP [RFC9293] or UDP [RFC768].
Each of these options comes with its challenges.
As for the network layer protocol requirements, only IPv4 must be supported by your implementation.

| Protocol property       | Value
| ----------------------- | -----
| Default server port     | `4567`
| Network protocols       | `IPv4`
| Transport protocols     | `TCP`, `UDP`
| Supported charset       | `us-ascii`

### Message types

The protocol defines the following message types to correctly represent the behaviour of each party communicating with this protocol:

| Type name | Notes                       | Description
| --------- | --------------------------- | -----------
| `AUTH`    | This is a _request message_ | Used for client authentication (signing in) using a user-provided username, display name and password
| `BYE`     |                             | Either party can send this message to indicate that the conversation/connection is to be terminated
| `CONFIRM` | `UDP`&nbsp;only | Only leveraged in specific protocol variants (UDP) to explicitly confirm the successful delivery of the message to the other party on the application level
| `ERR`     |                             | Indicates that an error has occurred while processing the other party's last message; this directly results in a graceful termination of the communication
| `JOIN`    | This is a _request message_ | Represents the client's request to join a chat channel by its identifier
| `MSG`     |                             | Contains user display name and a message designated for the channel they're joined in
| `PING`    | `UDP`&nbsp;only             | Periodically sent by a server to all its clients who are using the UDP variant of this protocol as an aliveness check mechanism
| `REPLY`   |                             | Some messages (requests) require a positive/negative confirmation from the other side; this message contains such data

The following table shows the mandatory parameters of given message types.
Their names (identifiers) will be used further in the document to signify the placement of their values in the protocol messages.

| FSM name | Mandatory message parameters
| -------- | ----------------------------
| `AUTH`   | `Username`, `DisplayName`, `Secret`
| `JOIN`   | `ChannelID`, `DisplayName`
| `ERR`    | `DisplayName`, `MessageContent`
| `BYE`    | `DisplayName`
| `MSG`    | `DisplayName`, `MessageContent`
| `REPLY`  | `true`, `MessageContent`
| `!REPLY` | `false`, `MessageContent`

The values for the message contents defined above will be extracted from the provided user input.
Handling user-provided input is discussed at a [later point](#client-behaviour-input-and-commands).

| Message parameter | Max. length | Characters
| ----------------- | ----------- | ----------
| `MessageID`       | `uint16`    | 
| `Username`        | `20`        | [`[a-zA-Z0-9_-]`](https://regexr.com/8b6ou) (e.g., `Abc_00-7`)
| `ChannelID`       | `20`        | [`[a-zA-Z0-9_-]`](https://regexr.com/8b6ou) (e.g., `Abc_00-7`)
| `Secret`          | `128`       | [`[a-zA-Z0-9_-]`](https://regexr.com/8b6ou) (e.g., `Abc_00-7`)
| `DisplayName`     | `20`        | *Printable characters* (`0x21-7E`)
| `MessageContent`  | `60000`     | *Printable characters with space and line feed* (`0x0A,0x20-7E`)

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
<span style=" color:blue">Blue values</span> correspond to the client-sent messages (output) to the server.
There are a few important notes for the schema interpretation:

- the underscore (`_`) value represents *no message* (i.e., no input is received / no output is sent),
- the star (`*`) value represents *all possible messages* (i.e., any input is received),
- when multiple values are specified on the input/output positions and separated by a comma, they are to be interpreted as "any one of",
- `REPLY` and `!REPLY` correspond to the same message type (`REPLY`), the exclamation mark (`!`) represents a negative version of the reply, `*REPLY` stands for any reply (either positive or negative) and `REPLY` in itself represents a positive outcome,
- `CONFIRM` and `PING` messages are not shown in the FSM as this is an ideal model of possible communication,

![Client FSM](diagrams/protocol_fsm_client.svg)

Request messages (`AUTH` and `JOIN`) initiate an asynchronous process on the remote server.
That always leads to the server sending a `REPLY` message when this process finishes.
Such behaviour can be seen in the `auth` and `join` states, where the client is waiting for a `REPLY` message to be received.
The `REPLY` messages inform the client whether the request has been fulfilled correctly or has failed.

By inspecting the client state machine, you can notice that no `JOIN` message is necessary after a successful authentication - the server must join you in a default channel immediately.
The `JOIN` message is then only used when switching between channels.

Negative replies (`!REPLY`) to any potential messages that were sent to the server must not negatively impact the functionality of the client program.
Joining channels or user authentication is sometimes expected to fail.
This should be apparent from the state machine.

The client must truncate messages longer than the protocol-allowed maximum before sending them to the remote server.
If such an event occurs, a local error message must also inform the client.
The local error output format is further specified in the [client output section](#client-output).

Both `ERR` and `BYE` messages must result in graceful connection termination.
Receiving either one means that the current connection has been finalised by the sender of the corresponding message.
`BYE` and `ERR` are the final messages sent/received in a conversation (except their potential confirmations in the UDP variant).

The program might receive additional messages from the networking layer after transitioning to the `end` state.
However, according to the FSM, the transition to the `end` state also means that the client cannot process any other messages.
Behaviour of the program in such a state is undefined.
The client program is neither required to process nor required to prevent the processing of such messages; only graceful connection termination is required.

### UDP variant
The first variant of the `IPK25-CHAT` protocol is built on top of UDP [RFC768].
As the UDP is connection-less and the delivery is unreliable, using it as a transport layer protocol poses particular challenges that must be addressed at the application layer.
These challenges include but are not limited to datagram loss, duplication and reordering.
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
The confirmation should be sent immediately after receiving the message, regardless of any potential higher-level processing issues - unless the connection has already been successfully terminated; in such a case, it is valid not to respond to the message at all.
The message is considered lost in transit when the original sender does not receive the confirmation within a given timespan.
Messages lost in transit are re-transmitted until the confirmation is successfully received or an internal re-try condition is triggered.
Only the original sender performs message re-transmit, not the receiver (confirmation messages are never re-transmitted or explicitly confirmed).

| Variable             | Recommended value | Notes
| -------------------- | ----------------: | -----
| Confirmation timeout | `250ms`           | 
| Retry count          | `3`               | 1 initial + 3 retries

**Packet delay/duplication** can be detected by keeping track of processed unique message IDs.
Once a message is received, its unique ID is compared to a list of already-seen message IDs.
Afterwards, there are two options:
either the message ID was not previously seen (the message is then processed typically),
or the message ID is contained within the list, meaning it has already been processed.
In the latter's case, only the delivery confirmation is sent to the message sender.
No additional action is taken otherwise.

The transport protocol issues and their solutions described above can be seen visualised in the following diagrams.
| Packet loss                        | Packet delay/duplication
| :--------------------------------: | :----------------------------------:
| ![UDP Loss](diagrams/udp_loss.svg) | ![UDP Delay](diagrams/udp_delay.svg)

> <span style="color:gray">Food for thought: What would be the maximum message size for this protocol variant?
</span>

> <span style="color:gray">Food for thought: What would happen on the network layer if the specification would allow messages of such size?
</span>

#### Message Header
The following snippet presents the general structure of any application message sent via this protocol variant.
You can notice a uniform header of 3 bytes, which will be present at the beginning of each message (both sent and received).
There are two distinct fields, `Type` and `MessageID` (more details are in the table below the snippet).
The fields comprise 1B for the message type and 2B for the message ID.
The following content is variable in length and depends on the message type.
Some messages may not have any additional content at all.
```
 0      7 8     15 16    23 24
+--------+--------+--------+---~~---+
|  Type  |    MessageID    |  ....  |
+--------+--------+--------+---~~---+
```

| Field name  | Value     | Notes
| :---------- | --------: | -----
| `Type`      | `uint8`   | 
| `MessageID` | `uint16`  | Sent in network byte order

##### Message `Type`
The table below shows the mapping of the protocol message types (as defined in the [Specification section](#specification)) to the values in the first field (`Type`) of the application datagram header for this protocol variant.
This unique number is used to identify which message has been received.

| Message type | Field value
| ------------ | -----------
| `CONFIRM`    | `0x00` 
| `REPLY`      | `0x01` 
| `AUTH`       | `0x02` 
| `JOIN`       | `0x03` 
| `MSG`        | `0x04` 
| `PING`       | `0xFD` 
| `ERR`        | `0xFE` 
| `BYE`        | `0xFF` 

##### `MessageID`
Message ID is a 2-byte number for a unique identification of a particular message.
The value must never appear as a message identifier of a different message in the communication once it has been used.
Each side of the communication has its identifier sequence.
Your implementation must use values starting from `0`, incremented by `1` for each message _sent_, **not received**.

#### Message Contents
This section describes the messages used in this protocol version.
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

| Field name      | Value     | Notes
| :-------------- | --------: | -----
| `Ref_MessageID` | `uint16`  | The `MessageID` value of the message being confirmed

##### `REPLY`
```
  1 byte       2 bytes       1 byte       2 bytes      
+--------+--------+--------+--------+--------+--------+--------~~---------+---+
|  0x01  |    MessageID    | Result |  Ref_MessageID  |  MessageContents  | 0 |
+--------+--------+--------+--------+--------+--------+--------~~---------+---+
```

| Field name        | Value      | Notes
| :---------------- | ---------: | -----
| `Result`          | `0` or `1` | `0` indicates failure, `1` indicates success
| `Ref_MessageID`   | `uint16`   | The `MessageID` value of the message replying to
| `MessageContents` | `string`   | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte

##### `AUTH`
```
  1 byte       2 bytes      
+--------+--------+--------+-----~~-----+---+-------~~------+---+----~~----+---+
|  0x02  |    MessageID    |  Username  | 0 |  DisplayName  | 0 |  Secret  | 0 |
+--------+--------+--------+-----~~-----+---+-------~~------+---+----~~----+---+
```

| Field name    | Value    | Notes
| :------------ | -------: | -----
| `Username`    | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte
| `DisplayName` | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte
| `Secret`      | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte

##### `JOIN`
```
  1 byte       2 bytes      
+--------+--------+--------+-----~~-----+---+-------~~------+---+
|  0x03  |    MessageID    |  ChannelID | 0 |  DisplayName  | 0 |
+--------+--------+--------+-----~~-----+---+-------~~------+---+
```

| Field name    | Value    | Notes
| :------------ | -------: | -----
| `ChannelID`   | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte
| `DisplayName` | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte

##### `MSG`
```
  1 byte       2 bytes      
+--------+--------+--------+-------~~------+---+--------~~---------+---+
|  0x04  |    MessageID    |  DisplayName  | 0 |  MessageContents  | 0 |
+--------+--------+--------+-------~~------+---+--------~~---------+---+
```

| Field name        | Value    | Notes
| :---------------- | -------: | -----
| `DisplayName`     | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte
| `MessageContents` | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte

##### `ERR`
```
  1 byte       2 bytes
+--------+--------+--------+-------~~------+---+--------~~---------+---+
|  0xFE  |    MessageID    |  DisplayName  | 0 |  MessageContents  | 0 |
+--------+--------+--------+-------~~------+---+--------~~---------+---+
```

The structure is identical to the `MSG` message.

##### `BYE`
```
  1 byte       2 bytes
+--------+--------+--------+-------~~------+---+
|  0xFF  |    MessageID    |  DisplayName  | 0 |
+--------+--------+--------+-------~~------+---+
```

| Field name        | Value    | Notes
| :---------------- | -------: | -----
| `DisplayName`     | `string` | Only contains non-`0` bytes (further conforms to rules set in the [protocol Specification](#specification)), is always followed by a zero byte

##### `PING`
```
  1 byte       2 bytes
+--------+--------+--------+
|  0xFD  |    MessageID    |
+--------+--------+--------+
```


#### UDP transport summarised

The following diagrams show the protocol's behaviour in different transport conditions.

| Packet loss                        | Packet delay/duplication             |
| :--------------------------------: | :----------------------------------: |
| ![UDP Loss](diagrams/udp_loss.svg) | ![UDP Delay](diagrams/udp_delay.svg) |

| Session initialization                    | Session termination (Client)                      | Session termination (Client)                      |
| :---------------------------------------: | :-----------------------------------------------: | :-----------------------------------------------: |
| ![UDP Client INIT](diagrams/udp_open.svg) | ![UDP Client TERM](diagrams/udp_close_client.svg) | ![UDP Server TERM](diagrams/udp_close_server.svg) |

### TCP variant
The second variant of the `IPK25-CHAT` protocol is built on top of TCP [RFC9293].
Given the properties of this transport protocol (connection-oriented with reliable delivery), there is little to worry about on the application layer.
This protocol variant is entirely textual; hence, it uses text-based commands (much like HTTP [RFC1945]) to communicate with the remote server in all cases.
The connection to the server is stateful and must respect the same client state behaviour described in the general protocol section above.

> <span style= "color:orange">Graceful connection termination does not involve TCP messages with the `RST` flag set by either communicating party.
</span>

#### Message Grammar
The following ABNF [RFC5234] grammar snippet describes the forming of valid messages for this version of the application protocol (HTTP specification [RFC1945, section 2 and 3] also uses a similar grammar).
Refer to the notation specification for information on interpreting the grammar syntax and semantics.
**Read the grammar specification carefully**; complete and correct understanding of the notation *will* be tested.
It is imperative that you can reliably interpret the real meaning of the formal definition.

```abnf
; core content components
ID        = 1*20    ( ALPHA / DIGIT / "_" / "-" )
SECRET    = 1*128   ( ALPHA / DIGIT / "_" / "-" )
CONTENT   = 1*60000 ( VCHAR / SP / LF )
DNAME     = 1*20    VCHAR

; additional content components
is     = SP "IS"    SP
as     = SP "AS"    SP
using  = SP "USING" SP

; message content variant parts
contentJoin     = "JOIN"     SP ID    as DNAME
contentAuth     = "AUTH"     SP ID    as DNAME using SECRET
contentMessage  = "MSG FROM" SP DNAME is CONTENT
contentError    = "ERR FROM" SP DNAME is CONTENT
contentBye      = "BYE FROM" SP DNAME
contentReply    = "REPLY"    SP ( "OK" / "NOK" ) is CONTENT

; message content variants
content  =  contentAuth
content  =/ contentJoin
content  =/ contentMessage
content  =/ contentError
content  =/ contentBye
content  =/ contentReply

; each message is terminated with "\r\n"
message = content CRLF
```

Contents of each message sent and received in this protocol variant must conform to the `message` rule from the grammar above.

#### Message Content Parameter Mapping
The following table shows a mapping of message content rules of the content grammar above to the message types and parameters available in the `IPK25-CHAT` protocol (as defined in the [Specification section](#specification)).
Note that the message of type `CONFIRM` is unused in this protocol version as it is unnecessary as opposed to the UDP variant.
That is because the selected transport layer protocol ensures correct application data delivery for us.

| Message type | Message parameter template
| ------------ | --------------------------
| `ERR`        | `ERR FROM {DisplayName} IS {MessageContent}\r\n`
| `REPLY`      | `REPLY {"OK"\|"NOK"} IS {MessageContent}\r\n`
| `AUTH`       | `AUTH {Username} AS {DisplayName} USING {Secret}\r\n`
| `JOIN`       | `JOIN {ChannelID} AS {DisplayName}\r\n`
| `MSG`        | `MSG FROM {DisplayName} IS {MessageContent}\r\n`
| `BYE`        | `BYE FROM {DisplayName}\r\n`
| `CONFIRM`    | *Unused in TCP*
| `PING`       | *Unused in TCP*

Remember that values for variables in the templates defined above further conform to rules defined by the [message grammar](#message-grammar).

> <span style="color:gray">Food for thought: Why is the message termination string `\r\n` necessary?
> How does it compare to processing messages sent over the UDP?
</span>


## Program Execution
This section defines the required behaviour and interface of the implemented client application on the program execution level.

### CLI arguments
The implemented program must support and respect command line arguments as the table below defines.
It is required to have corresponding program subsystems parameterisable by these values at a minimum.

| Argument | Value                                           | Possible values        | Meaning or expected program behaviour
| -------- | ----------------------------------------------- | ---------------------- | -------------------------------------
| `-t`     | <span style="color:orange">User provided</span> | `tcp` or `udp`         | Transport protocol used for connection
| `-s`     | <span style="color:orange">User provided</span> | IP address or hostname | Server IP or hostname
| `-p`     | `4567`                                          | `uint16`               | Server port
| `-d`     | `250`                                           | `uint16`               | UDP confirmation timeout (in milliseconds)
| `-r`     | `3`                                             | `uint8`                | Maximum number of UDP retransmissions
| `-h`     |                                                 |                        | Prints program help output and exits

> <span style=" color:orange">Edge cases of argument processing will not be a part of evaluation (e.g., providing argument more than once, providing invalid argument value, providing unknown arguments).
Application behaviour is expected to be undefined in such cases.
</span>

Arguments with "<span style="color:orange">User provided</span>" text in the value column are mandatory and have to be always specified when running the program.
Other values indicate that the argument is optional with its default value defined in the column (or no value).

> <span style="color:deepskyblue">**Note:** Your program may support more command line arguments than defined above.
Ensure there is no name or behaviour clash between the required and custom arguments.
</span>

### Client behaviour, input and commands
Any user-provided data from the standard program input stream (`stdin`) are to be interpreted either as a local command or a chat message to be sent to the remote server.
Each user chat message or a local client command invocation is terminated by a new line character (`\n`).
All valid commands must be prefixed with a command character (forward slash `/`) and immediately followed by a non-zero number of `a-z0-9_-` characters uniquely identifying the command.
The client must support the following client commands:

| Command     | Parameters                              | Client behaviour
| ----------- | --------------------------------------- | ----------------
| `/auth`     | `{Username}`&nbsp;`{Secret}`&nbsp;`{DisplayName}` | Sends `AUTH` message with the data provided from the command to the server (and correctly handles the `Reply` message), locally sets the `DisplayName` value (same as the `/rename` command)
| `/join`     | `{ChannelID}`                           | Sends `JOIN` message with channel name from the command to the server (and correctly handles the `Reply` message)
| `/rename`   | `{DisplayName}`                         | Locally changes the display name of the user to be sent with new messages/selected commands
| `/help`     |                                         | Prints out supported local commands with their parameters and a description

Please note that the order of the command parameters must stay the same, as shown in the definitions above.

> <span style="color:deepskyblue">**Note:** Your program may support more local client commands than defined above.
Ensure there is no name or behaviour clash between the required and custom commands.
</span>

User input not prefixed with the proper command character shall be interpreted as a chat message to be sent to the server.
If the provided user input is unacceptable at the current client state, the application must inform the user about such a situation (by printing out a helpful error message).
The application must not terminate in such a case.
These states include, for example:
- trying to send a message in a non-`open` state,
- trying to send a malformed chat message,
- trying to join a channel in a non-`open` state,
- trying to process an unknown or otherwise malformed command or user input in general.

Nevertheless, the client must simultaneously process only a single user input (chat or request message/local command invocation).
Processing of additional user input is deferred until after the previous action has been completed.
By the completion of an action, it is understood that the message has been **successfully delivered** to the remote server (e.g., in the UDP protocol variant, a `CONFIRM` message has been received from the server) **and processed** by the server (a `REPLY` message has been received from the server where appropriate).
Or, in the case of a local command invocation, it has been processed by the client.

> <span style=" color:orange">Edge cases of argument processing will not be a part of evaluation (e.g., providing argument more than once, providing invalid argument value, providing unknown arguments).
Application behaviour is expected to be undefined in such cases.
</span>

### Client program and connection termination

The client must react to the *Interrupt signal* (`C-c`) by gracefully exiting and cleanly terminating the connection as appropriate for the protocol variant.
That means appropriately processing a `BYE` message with the server in any protocol variant.
In addition, TCP connection finalisation must not contain the `RST` flag [RFC9293, section 3.5.2].
The equivalent client behaviour can be achieved by reaching the end of user input (`C-d`).

Receiving a `BYE` or an `ERR` message from the server is also required to lead to graceful connection termination, as in the case where the client initiates the termination.
It should be apparent from the [UDP transport diagrams](#udp-transport-summarised) that the client will be required to wait for a possible `BYE`/`ERR` message retransmission if their `CONFIRM` message is lost in transit to the server.

### Client exception handling

This section further explains client behaviour in some specific exceptional circumstances.

| Situation                                      | Category               | Expected client behaviour
| ---------------------------------------------- | ---------------------- | -------------------------
| Receiving a malformed message from the server  | Protocol error         | <ol><li>local client error is displayed</li><li>`ERR` message is sent to server, _if possible_</li><li>connection is gracefully terminated, _if possible_</li><li>the client application is terminated with an error code</li><ol>
| Confirmation of a sent `UDP` message times out | Protocol error         | <ol><li>local client error is displayed</li><li>the connection is understood to be finalized, no further messages are sent</li><li>the client application is terminated with an error code</li><ol>
| No `REPLY` message is received to a confirmed _request message_ in time | Protocol error | <ol><li>local client error is displayed</li><li>`ERR` message is sent to server, _if possible_</li><li>connection is gracefully terminated, _if possible_</li><li>the client application is terminated with an error code</li><ol>

> <span style=" color:orange">Replies must be received within 5s of sending the request message.
</span>

> <span style="color:deepskyblue">**Note:** If an exceptional case in client behaviour is missing, feel free to ask about it.
</span>

### Client output
The contents of an incoming `MSG` message are required to be printed to the standard output stream (`stdout`) and formatted as follows:
```
{DisplayName}: {MessageContent}\n
```

The contents of an incoming `ERR` message are required to be printed to standard output stream (`stdout`) and formatted as follows:
```
ERROR FROM {DisplayName}: {MessageContent}\n
```

Internal (local) client application errors and exceptions are required to be printed to standard output stream (`stdout`) and formatted as follows:
```
ERROR: {MessageContent}\n
```

The contents of an incoming `REPLY` message are required to be printed to standard output stream (`stdout`) and formatted as follows (there are two variants of the reply message):
```
Action Success: {MessageContent}\n
```
```
Action Failure: {MessageContent}\n
```

No application messages other than the abovementioned should trigger any program output to `stdout`.

> <span style="color:deepskyblue">**Note:** You may customise the default message format as much as you like (e.g., adding timestamps);
> however, such custom changes to the output format must be toggleable (either by an environment variable, program argument, or a build variable).
The default output format is required to stay the same as described above.
</span>

### Client logging

Output to `stderr` will not impact grading your solution; however, it will be tracked and can help you pinpoint and understand potential issues later.
It is **highly recommended** that `stderr` output be used for all application logging/debugging messages.
And that these messages should be enabled at all times by default.

The recommended logging solution for projects in C/C++ is a simple variadic print macro:
```c
#ifdef DEBUG_PRINT
#define printf_debug(format, ...) fprintf(stderr, "%s:%-4d | %15s | " format "\n", __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define printf_debug(format, ...) (0)
#endif
```

The recommended logging solution for .NET projects is to use the built-in logging tooling (`Microsoft.Extensions.Logging`), ideally by leveraging DI:
```csharp
// requires Microsoft.Extensions.Hosting package installed
var builder = Host.CreateApplicationBuilder();

builder.Services.AddLogging(loggingBuilder => loggingBuilder
 .ClearProviders()
 .AddSimpleConsole(opts => opts.SingleLine = true)
 .AddConsole(opts => opts.LogToStandardErrorThreshold = LogLevel.Trace));

// ...
```


## Functionality Illustration
Contents in this section demonstrate how the application should behave or provide means of validating the implementation of given protocol features.

### Client run examples
The command snippets below show examples of running the application with different command line options.
The examples demonstrate how will the application be run when testing.

Print help output of the program, do not connect anywhere:
```shell
./ipk25-chat -h
```

Run client in `TCP` variant, connect to server at `127.0.0.1` with default port `4567`:
```shell
./ipk25-chat -t tcp -s 127.0.0.1
```
```shell
/home/path/to/exe/ipk25-chat -t tcp -s 127.0.0.1
```

Run client in `UDP` variant, connect to server at `ipk.fit.vutbr.cz` (perform translation) with port `10000`:
```shell
./ipk25-chat -t udp -s ipk.fit.vutbr.cz -p 10000
```

Run client in `UDP` variant, connect to server at `127.0.0.1` with port `3000`, UDP response timeout `100ms` and up to `1` message retransmission max:
```shell
./ipk25-chat -t udp -s 127.0.0.1 -p 3000 -d 100 -r 1
```

### Client I/O examples
Below, you can see a simple example of program input and output for
(1) authenticating,
(2) joining a different channel and finally
(3) sending a message.
Contents written to standard input stream (`stdin`) are distinguished by <span style="color:turquoise">turquoise colour</span>.

<pre>
<span style="color:turquoise">/auth username Abc-123-BCa Display_Name</span>
Action Success: Auth success.
Server: Display_Name has joined default.
<span style="color:turquoise">/join channel1</span>
Action Success: Join success.
Server: Display_Name has joined channel1.
<span style="color:turquoise">Hello, this is a message to the current channel.</span>
</pre>

Below is another example of an application's input and output when receiving and sending some messages in a default server channel.

<pre>
<span style="color:turquoise">/auth username Abc-123-BCa Display_Name</span>
Action Success: Auth success.
Server: Display_Name has joined default.
User_1: Lorem ipsum dolor sit amet, consectetuer adipiscing elit.
User_2: Donec ipsum massa, ullamcorper in, auctor et, scelerisque sed, est. Quisque porta.
<span style="color:turquoise">Et harum quidem rerum facilis est et expedita distinctio. Nullam dapibus fermentum ipsum.</span>
User_1: Duis ante orci, molestie vitae vehicula venenatis, tincidunt ac pede.
</pre>

> <span style="color:orange">Please note the server does not send your own messages back to you.
</span>

#### Implementation limitations
The evaluation suite will simulate interactive user input.
Your solution should only read complete lines (terminated by a new line character `\n`) and process them as a whole afterwards.
Interactive behaviour or non-standard input processing of your application is undesirable and may lead to issues in evaluation.
That includes behaviours such as:
- interactive user menus and prompts,
- real-time input processing (single character, one by one),
- changing application behaviour based on whether the standard input stream is a file or a console.

> <span style="color:orange">Deviating from these recommendations may result in your application behaving unexpectedly during evaluation.
> Such a situation often leads to unintentionally breaking the test cases and your solution being graded with 0 points.
</span>

### Network Transport
In this section, you can find example illustrations and real-world network traffic captures for the `IPK25-CHAT` protocol.

#### Using Captured PCAPs

You can download and inspect live network traffic captured from the reference client and server.
The capture files' corresponding descriptions and download links are in the table below.
To inspect the captures, download and install the [Wireshark application](https://www.wireshark.org/download.html).

| Capture file                                                                                                                                             | Description
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | -----------
| [`ipk25_chat-tcp_tcp.pcapng.gz`](https://moodle.vut.cz/pluginfile.php/1064248/mod_folder/content/0/ipk25_chat-tcp_tcp.pcapng.gz?forcedownload=1)         | A conversation between two clients using TCP connection to the server
| [`ipk25_chat-udp_udp.pcapng.gz`](https://moodle.vut.cz/pluginfile.php/1064248/mod_folder/content/0/ipk25_chat-udp_udp.pcapng.gz?forcedownload=1)         | A conversation between two clients using UDP to transfer their messages
| [`ipk25_chat-tcp_udp.pcapng.gz`](https://moodle.vut.cz/pluginfile.php/1064248/mod_folder/content/0/ipk25_chat-tcp_udp.pcapng.gz?forcedownload=1)         | A conversation between two clients, one using TCP and one using UDP to communicate with each other via the server

All captures that were made available can be found in the [e-learning file directory](https://moodle.vut.cz/mod/folder/view.php?id=508426).

> <span style="color:deepskyblue">**Note:** Make sure to use the custom Wireshark protocol dissector plugin created for `IPK25-CHAT` protocol.
Refer to the [corresponding section](#using-wireshark-protocol-dissector) to download and install it.
</span>

#### UDP protocol variant
The following text snippet can be an example of communication between two parties using the UDP version of this protocol.
```
 port   | client                                          server | port   | message type
--------+--------------------------------------------------------+--------+--------------
 :45789 | |2|0|username|0|User_1|0|Secret|0|  -->                | :4567  | AUTH
 :45789 |                                             <--  |0|0| | :4567  | CONFIRM
 :45789 |                                        <--  |1|0|1|OK| | :59873 | REPLY
 :45789 | |0|0|  -->                                             | :59873 | CONFIRM
 :45789 |                  <--  |4|1|Server|0|Joined default.|0| | :59873 | MSG
 :45789 | |0|1|  -->                                             | :59873 | CONFIRM
 :45789 | |3|1|channel-id|User_1|0|  -->                         | :59873 | JOIN
 :45789 |                                             <--  |0|1| | :59873 | CONFIRM
 :45789 |               <--  |4|2|Server|0|Joined channel-id.|0| | :59873 | MSG
 :45789 | |0|2|  -->                                             | :59873 | CONFIRM
 :45789 |                                        <--  |1|3|1|OK| | :59873 | REPLY
 :45789 | |0|3|  -->                                             | :59873 | CONFIRM
 :45789 |                                           <--  |253|4| | :59873 | PING
 :45789 | |0|4|  -->                                             | :59873 | CONFIRM
 :45789 | |4|2|User_1|0| ~message content~ |0|  -->              | :59873 | MSG
 :45789 |                                             <--  |0|2| | :59873 | CONFIRM
 :45789 | |4|3|User_1|0| ~message content~ |0|  -->              | :59873 | MSG
 :45789 |                                             <--  |0|3| | :59873 | CONFIRM
 :45789 |                                           <--  |253|5| | :59873 | PING
 :45789 | |0|5|  -->                                             | :59873 | CONFIRM
 :45789 |                                           <--  |253|6| | :59873 | PING
 :45789 | |0|6|  -->                                             | :59873 | CONFIRM
 :45789 |              <--  |4|7|User_2|0| ~message content~ |0| | :59873 | MSG
 :45789 | |0|7|  -->                                             | :59873 | CONFIRM
 :45789 | |255|4|User_1|  -->                                    | :59873 | BYE
 :45789 |                                             <--  |0|4| | :59873 | CONFIRM
```

> <span style="color:deepskyblue">**Note:** This snippet is just an example; the actual order of messages (especially `JOIN` -> `REPLY` -> `MSG`) may differ.
</span>

#### TCP protocol variant
The content of Wireshark's "follow TCP stream" for a short conversation may look something like the following text snippet.
<span style="color:pink">Pink</span>-coloured messages were sent by the client, whereas <span style="color:turquoise">turquoise</span> messages were sent by the remote server.
Each message was correctly terminated using the `\r\n` character sequence - these have been omitted from the snippet.

<pre>
<span style="color:pink">AUTH tcp AS TCP_man USING TCPsecret</span>
<span style="color:turquoise">REPLY OK IS Auth success.</span>
<span style="color:turquoise">MSG FROM Server IS TCP_man joined default.</span>
<span style="color:pink">MSG FROM TCP_man IS Hello everybody!</span>
<span style="color:pink">JOIN general AS TCP_man</span>
<span style="color:turquoise">MSG FROM Server IS TCP_man joined general.</span>
<span style="color:turquoise">REPLY OK IS Join success.</span>
<span style="color:pink">JOIN default AS TCP_man</span>
<span style="color:pink">MSG FROM TCP_man IS Just saying hello here as well!</span>
<span style="color:pink">MSG FROM TCP_man IS Peace!</span>
<span style="color:pink">BYE FROM TCP_man</span>
</pre>

> <span style="color:deepskyblue">**Note:** This snippet is just an example; the actual order of messages may differ based on server implementation.
</span>

### Reference Resources
This section describes which resources are available to you so you can verify the correct implementation of the specification protocol.

#### Using Public Reference Server

You can test your application in a production-like environment against a reference server implementation that is compliant with the protocol specification.
Hosting details are available in the table below.
Please read the instructions and rules carefully to allow everyone an equal chance of validating their application's behaviour against this reference.

| Server property     | Value                 |
| ------------------- | --------------------- |
| Address or hostname | `anton5.fit.vutbr.cz` |
| Application port    | `4567`                |
| Supported protocols | `TCP`, `UDP`          |

> <span style="color:orange">Due to the nature of the project, every student will be issued their own authentication details to use when communicating with the server to ensure content compliance.
The credentials will be issued on demand using an automated process.
Do not share them with anyone else.
</span>

> <span style="color:orange">You might encounter communication issues when communicating with the remote server from behind NAT.
You can work around this issue using the VUT or FIT VPN or connecting from the CESNET/eduroam networks.
</span>

To get your confidential credentials for the public reference server:
1. create a free account at https://discord.com,
2. join the integration server at https://discord.gg/zmuss9VfzJ,
3. follow the guide in the [welcome channel](https://discord.com/channels/1205490529249267712/1205494743581069333) to activate your account.

Account verification can only be done once and only with a single Discord account to prevent service abuse.
You will need access to your faculty email address to confirm your credentials.
The access credentials are student account-bound, so please refrain from **sharing** and **abusing** them since that can be tracked and could land you in trouble.
The username for authentication is your faculty login (it will never be used in chat by the server), the secret is a GUID string you receive in your mail after successful account verification, and your display name can be anything tasteful.

> <span style="color:orange">Any breaches against the terms of service will result in account access limitation or its complete termination.
Make sure your implementation is reasonably <ins>well tested</ins> in your local environment <ins>before</ins> using the public server.
Major ToS violations will be understood as intentional even when alleged to be caused by erroneous program implementation.
</span>

This option is provided as a token of goodwill and can be disabled at any given time before the project submissions are complete.
In case you have any questions, ideas for improvement or stumble upon any service issues, let us know using the [issue tracking channel](https://discord.com/channels/1205490529249267712/1210952602041196564) on the server.
Assignment-related questions must be asked via the [e-learning portal forum for Project 2](https://moodle.vut.cz/mod/forum/view.php?id=508428).

The service will be terminated if the rules for reference server usage are violated.
Termination of the service may occur at any time before or after the project solution submission deadline and for any reason.
The service's uptime is not guaranteed.

> <span style="color:deepskyblue">**Note:** the reference server allows extended `ChannelID` notation (which is not in strict compliance with the protocol definition).
The value can contain a service prefix `discord.` (e.g., `discord.general`) to join/create integrated channels on the Discord platform.
When no prefix is provided, `native.` is assumed, and the channel will not be visible on the Discord server.
</span>

#### Using Wireshark Protocol Dissector
A custom `IPK25-CHAT` protocol dissector plugin for Wireshark has been prepared for you.
This resource should be handy when analysing the protocol contents that were physically sent over the network.
The dissector source can be found under [`resources/ipk25-chat.lua`](resources/ipk25-chat.lua).
Please leverage this plugin, as it can help you debug your implementation anytime during the development.
Follow these steps to install and use it:
1. download and install the [Wireshark application](https://www.wireshark.org/download.html) for your platform,
2. locate your "Personal Lua Plugins" directory from the Wireshark application window (in the menu, under [`Wireshark >`] `About > Folders > Personal Lua Plugins`),
 - if it does not exist, you may be able to create it by a double click,
 - otherwise refer to the application manual,
3. copy the `resources/ipk25-chat.lua` file into the plugin directory,
4. restart the application or press `Ctrl + Shift + L` (or `Command + Shift + L` on Mac) to reload any changes in Lua plugins (this also works when changing the plugin source code).

In case you encounter any issues within the dissector, you can try to fix them yourself and contribute to this repository by a [pull request](https://git.fit.vutbr.cz/NESFIT/IPK-Projects/pulls) or [create an issue](https://git.fit.vutbr.cz/NESFIT/IPK-Projects/issues/new) with appropriate description of the problem, screenshots and exported network capture (`.pcap`).
If you would like to contribute, please describe and share the issues you are trying to solve with the pull request (with the appropriate attachments when possible).
If you are unsure about your contribution, please reach out beforehand (by email).

#### Using netcat
You can use the `nc` command to start your pseudo-server.
You will be required to craft the responses for your program requests manually; nevertheless, it can act as a local server under your complete control.
Use the command `man nc` to determine what the netcat program can do more.

The table below explains the program arguments used in the following examples.
| Argument | Description
| -------- | -----------
| `-4`     | Will only use IPv4 addresses
| `-u`     | Will use UDP as a transport layer protocol
| `-c`     | Will send CRLF (`\r\n`) instead of just LF (`\n`) upon pressing the return key
| `-l`     | Will listen at the given IP and port instead of initiating a connection (default behaviour)
| `-v`     | Will produce a more verbose output

##### UDP communication
Manual conversation using the UDP variant will be more difficult since the messages are binary.
The following command can still listen to incoming UDP messages, but responses cannot be easily generated from the keyboard.
```
nc -4 -u -l -v 127.0.0.1 4567
```

To send a reply to the client, it is necessary first to create a binary message.
That can be done using the `xxd` command.
The `xxd` command line utility can read and write binary content using hexadecimal byte representation.
To create a simple `MSG` message, you can do the following:

Translate ASCII characters to hex (underscores were used at locations that need to be replaced with appropriate binary values):
```
echo "___User_1_This is a short message in hex._" | xxd
```
```
00000000: 5f5f 5f55 7365 725f 315f 5468 6973 2069  ___User_1_This i
00000010: 7320 6120 7368 6f72 7420 6d65 7373 6167  s a short messag
00000020: 6520 696e 2068 6578 2e5f 0a              e in hex._.
```

Save the hexadecimal representation of the to the `udp_msg.bin` file:
```
echo "___User_1_This is a short message in hex._" | xxd >udp_msg.bin
```

Edit the hex representation of the output and put whatever values are required to form a valid message (replace the underscore characters `0x5f`):
```
00000000: 0401 0055 7365 7220 3100 5468 6973 2069
00000010: 7320 6120 7368 6f72 7420 6d65 7373 6167
00000020: 6520 696e 2068 6578 2e5f 00
```

Finally, use `xxd -r` to transform the hex representation to binary contents:
```
xxd -r <udp_msg.bin
```
```
...User 1.This is a short message in hex.
```

Save the final binary message representation to file:
```
xxd -r <udp_msg.bin >udp_msg.bin
```

This file can, in turn, be sent by netcat to any party specified:
```
nc -4 -u -v 127.0.0.1 56478 <udp_msg.bin
```

##### TCP communication
The following command starts a netcat program listening for incoming TCP (netcat default) connections to `127.0.0.1:4567`.
After the connection is made, you can use the program's standard input to converse with the party connected.
```
nc -4 -c -l -v 127.0.0.1 4567
```

#### Using tcpdump
The `tcpdump` program is ideal for passive traffic monitoring on any local interface.
However, it is much easier to use Wireshark whenever possible.
If you need to use `tcpdump`, this section briefly describes how to do that.

| Argument | Description
| -------- | -----------
| `-A`     | Will print the content of each packet
| `-X`     | Will print a hex representation of the content
| `-n`     | Disables address to name conversion
| `-i`     | Selects the interface to listen on

Show traffic on the loopback interface (`ip a` or `ifconfig` can show you available interfaces on your machine):
```
sudo tcpdump -A -X -n -i lo0
```

Show only TCP traffic using port 4567:
```
sudo tcpdump -A -X -n tcp port 4567
```

Show only UDP traffic:
```
sudo tcpdump -A -X -n udp
```

<details>
<summary>Output example for <code>sudo tcpdump -A -X -n -i lo0 tcp port 4567</code></summary>

```shell
% sudo tcpdump -A -X -n -i lo0 tcp port 4567
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on lo0, link-type NULL (BSD loopback), snapshot length 524288 bytes
08:53:40.892300 IP 127.0.0.1.51782 > 127.0.0.1.4567: Flags [S], seq 142158297, win 65535, options [mss 16344,nop,wscale 6,nop,nop,TS val 2014337252 ecr 0,sackOK,eol], length 0
	0x0000:  4500 0040 0000 4000 4006 0000 7f00 0001  E..@..@.@.......
	0x0010:  7f00 0001 ca46 11d7 0879 29d9 0000 0000  .....F...y).....
	0x0020:  b002 ffff fe34 0000 0204 3fd8 0103 0306  .....4....?.....
	0x0030:  0101 080a 7810 58e4 0000 0000 0402 0000  ....x.X.........
08:53:40.892393 IP 127.0.0.1.4567 > 127.0.0.1.51782: Flags [S.], seq 1571972603, ack 142158298, win 65535, options [mss 16344,nop,wscale 6,nop,nop,TS val 1091280514 ecr 2014337252,sackOK,eol], length 0
	0x0000:  4500 0040 0000 4000 4006 0000 7f00 0001  E..@..@.@.......
	0x0010:  7f00 0001 11d7 ca46 5db2 65fb 0879 29da  .......F].e..y).
	0x0020:  b012 ffff fe34 0000 0204 3fd8 0103 0306  .....4....?.....
	0x0030:  0101 080a 410b 9e82 7810 58e4 0402 0000  ....A...x.X.....
08:53:40.892409 IP 127.0.0.1.51782 > 127.0.0.1.4567: Flags [.], ack 1, win 6379, options [nop,nop,TS val 2014337252 ecr 1091280514], length 0
	0x0000:  4500 0034 0000 4000 4006 0000 7f00 0001  E..4..@.@.......
	0x0010:  7f00 0001 ca46 11d7 0879 29da 5db2 65fc  .....F...y).].e.
	0x0020:  8010 18eb fe28 0000 0101 080a 7810 58e4  .....(......x.X.
	0x0030:  410b 9e82                                A...
08:53:40.892422 IP 127.0.0.1.4567 > 127.0.0.1.51782: Flags [.], ack 1, win 6379, options [nop,nop,TS val 1091280514 ecr 2014337252], length 0
	0x0000:  4500 0034 0000 4000 4006 0000 7f00 0001  E..4..@.@.......
	0x0010:  7f00 0001 11d7 ca46 5db2 65fc 0879 29da  .......F].e..y).
	0x0020:  8010 18eb fe28 0000 0101 080a 410b 9e82  .....(......A...
	0x0030:  7810 58e4                                x.X.
08:53:40.915530 IP 127.0.0.1.51782 > 127.0.0.1.4567: Flags [P.], seq 1:37, ack 1, win 6379, options [nop,nop,TS val 2014337275 ecr 1091280514], length 36
	0x0000:  4500 0058 0000 4000 4006 0000 7f00 0001  E..X..@.@.......
	0x0010:  7f00 0001 ca46 11d7 0879 29da 5db2 65fc  .....F...y).].e.
	0x0020:  8018 18eb fe4c 0000 0101 080a 7810 58fb  .....L......x.X.
	0x0030:  410b 9e82 4155 5448 2075 7365 7231 2041  A...AUTH.user1.A
	0x0040:  5320 5573 6572 2d31 2055 5349 4e47 2073  S.User-1.USING.s
	0x0050:  6563 7265 7431 0d0a                      ecret1..
08:53:40.915569 IP 127.0.0.1.4567 > 127.0.0.1.51782: Flags [.], ack 37, win 6379, options [nop,nop,TS val 1091280537 ecr 2014337275], length 0
	0x0000:  4500 0034 0000 4000 4006 0000 7f00 0001  E..4..@.@.......
	0x0010:  7f00 0001 11d7 ca46 5db2 65fc 0879 29fe  .......F].e..y).
	0x0020:  8010 18eb fe28 0000 0101 080a 410b 9e99  .....(......A...
	0x0030:  7810 58fb                                x.X.
08:53:40.916826 IP 127.0.0.1.4567 > 127.0.0.1.51782: Flags [P.], seq 1:41, ack 37, win 6379, options [nop,nop,TS val 1091280538 ecr 2014337275], length 40
	0x0000:  4500 005c 0000 4000 4006 0000 7f00 0001  E..\..@.@.......
	0x0010:  7f00 0001 11d7 ca46 5db2 65fc 0879 29fe  .......F].e..y).
	0x0020:  8018 18eb fe50 0000 0101 080a 410b 9e9a  .....P......A...
	0x0030:  7810 58fb 5245 504c 5920 4f4b 2049 5320  x.X.REPLY.OK.IS.
	0x0040:  4175 7468 656e 7469 6361 7469 6f6e 2073  Authentication.s
	0x0050:  7563 6365 7373 6675 6c2e 0d0a            uccessful...
08:53:40.916867 IP 127.0.0.1.51782 > 127.0.0.1.4567: Flags [.], ack 41, win 6379, options [nop,nop,TS val 2014337276 ecr 1091280538], length 0
	0x0000:  4500 0034 0000 4000 4006 0000 7f00 0001  E..4..@.@.......
	0x0010:  7f00 0001 ca46 11d7 0879 29fe 5db2 6624  .....F...y).].f$
	0x0020:  8010 18eb fe28 0000 0101 080a 7810 58fc  .....(......x.X.
	0x0030:  410b 9e9a                                A...
08:53:40.916949 IP 127.0.0.1.4567 > 127.0.0.1.51782: Flags [P.], seq 41:88, ack 37, win 6379, options [nop,nop,TS val 1091280538 ecr 2014337276], length 47
	0x0000:  4500 0063 0000 4000 4006 0000 7f00 0001  E..c..@.@.......
	0x0010:  7f00 0001 11d7 ca46 5db2 6624 0879 29fe  .......F].f$.y).
	0x0020:  8018 18eb fe57 0000 0101 080a 410b 9e9a  .....W......A...
	0x0030:  7810 58fc 4d53 4720 4652 4f4d 2053 6572  x.X.MSG.FROM.Ser
	0x0040:  7665 7220 4953 2055 7365 722d 3120 6861  ver.IS.User-1.ha
	0x0050:  7320 6a6f 696e 6564 2067 656e 6572 616c  s.joined.general
	0x0060:  2e0d 0a                                  ...
08:53:40.916966 IP 127.0.0.1.51782 > 127.0.0.1.4567: Flags [.], ack 88, win 6378, options [nop,nop,TS val 2014337276 ecr 1091280538], length 0
	0x0000:  4500 0034 0000 4000 4006 0000 7f00 0001  E..4..@.@.......
	0x0010:  7f00 0001 ca46 11d7 0879 29fe 5db2 6653  .....F...y).].fS
	0x0020:  8010 18ea fe28 0000 0101 080a 7810 58fc  .....(......x.X.
	0x0030:  410b 9e9a                                A...
08:53:42.757644 IP 127.0.0.1.51782 > 127.0.0.1.4567: Flags [P.], seq 37:64, ack 88, win 6378, options [nop,nop,TS val 2014339117 ecr 1091280538], length 27
	0x0000:  4500 004f 0000 4000 4006 0000 7f00 0001  E..O..@.@.......
	0x0010:  7f00 0001 ca46 11d7 0879 29fe 5db2 6653  .....F...y).].fS
	0x0020:  8018 18ea fe43 0000 0101 080a 7810 602d  .....C......x.`-
	0x0030:  410b 9e9a 4d53 4720 4652 4f4d 2055 7365  A...MSG.FROM.Use
	0x0040:  722d 3120 4953 2048 656c 6c6f 210d 0a    r-1.IS.Hello!..
08:53:42.757708 IP 127.0.0.1.4567 > 127.0.0.1.51782: Flags [.], ack 64, win 6378, options [nop,nop,TS val 1091282379 ecr 2014339117], length 0
	0x0000:  4500 0034 0000 4000 4006 0000 7f00 0001  E..4..@.@.......
	0x0010:  7f00 0001 11d7 ca46 5db2 6653 0879 2a19  .......F].fS.y*.
	0x0020:  8010 18ea fe28 0000 0101 080a 410b a5cb  .....(......A...
	0x0030:  7810 602d                                x.`-
```

</details>

## Submission
The submission must follow all the requirements described in the [general project specifications README](https://git.fit.vutbr.cz/NESFIT/IPK-Projects/src/branch/master/README.md).
Running the `make` command (using the default Makefile target) in the project root shall build a single executable called `ipk25chat-client` and place it in the project root.
The resulting executable may be implemented as a wrapper/launcher; however, it must conform to the command line interface described above.


## Evaluation
This assignment will be graded with up to **30 points**.
The actual functionality and code quality will be graded up to 24 points.
The project's documentation will be graded with up to 6 points (please refer to the [documentation instructions](https://git.fit.vutbr.cz/NESFIT/IPK-Projects#documentation-instructions) to see what good documentation is required to contain).
The distribution and general assessment rules are in accordance with the [general project evaluation criteria](https://git.fit.vutbr.cz/NESFIT/IPK-Projects#evaluation).

> <span style="color:orange">Please note that not all parts of the assignment are equally challenging to implement and will be, as a result, graded differently.
</span>


## Contributing
If you notice anything that could be improved on this project assignment, please propose a change/fix or an idea to do so.
You can use the [pull request](https://git.fit.vutbr.cz/NESFIT/IPK-Projects/pulls) or [repository issues](https://git.fit.vutbr.cz/NESFIT/IPK-Projects/issues) features of Gitea for this.
If you are unsure of doing so publicly, feel free to reach out using an email beforehand.

> <span style="color:orange">Please note that the specification/assignment related <ins>questions</ins> should be asked through the [e-learning portal forum for Project 2](https://moodle.vut.cz/mod/forum/view.php?id=508428).
</span>


## Bibliography

[RFC2119] Bradner, S. _Key words for use in RFCs to Indicate Requirement Levels_ [online]. March 1997. [cited 2024-02-11]. DOI: 10.17487/RFC2119. Available at: https://datatracker.ietf.org/doc/html/rfc2119

[RFC5234] Crocker, D. and Overell, P. _Augmented BNF for Syntax Specifications: ABNF_ [online]. January 2008. [cited 2024-02-11]. DOI: 10.17487/RFC5234. Available at: https://datatracker.ietf.org/doc/html/rfc5234

[RFC9293] Eddy, W. _Transmission Control Protocol (TCP)_ [online]. August 2022. [cited 2024-02-11]. DOI: 10.17487/RFC9293. Available at: https://datatracker.ietf.org/doc/html/rfc9293

[RFC894] Hornig, C. _A Standard for the Transmission of IP Datagrams over Ethernet Networks_ [online]. April 1984. [cited 2024-02-14]. DOI: 10.17487/RFC894. Available at: https://datatracker.ietf.org/doc/html/rfc894

[RFC791] Information Sciences Institute, University of Southern California. _Internet Protocol_ [online]. September 1981. [cited 2024-02-14]. DOI: 10.17487/RFC791. Available at: https://datatracker.ietf.org/doc/html/rfc791

[RFC768] Postel, J. _User Datagram Protocol_ [online]. March 1997. [cited 2024-02-11]. DOI: 10.17487/RFC0768. Available at: https://datatracker.ietf.org/doc/html/rfc768

[RFC1350] Sollins, D. _The TFTP Protocol (Revision 2)_ [online]. July 1992. [cited 2024-02-12]. DOI: 10.17487/RFC1350. Available at: https://datatracker.ietf.org/doc/html/rfc1350

[RFC1945] NIELSEN, Henrik, Roy T FIELDING a Tim BERNERS-LEE, 2022. _Hypertext Transfer Protocol -- HTTP/1.0_ [online]. May 1996. [cited 2025-01-23]. Available at: https://datatracker.ietf.org/doc/html/rfc1945
