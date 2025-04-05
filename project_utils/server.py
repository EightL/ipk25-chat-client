#!/usr/bin/env python3
import socket
import select
import struct
import time
import random

HOST = '0.0.0.0'
PORT = 4567

# UDP message type constants per the specification.
TYPE_CONFIRM = 0x00
TYPE_REPLY   = 0x01
TYPE_AUTH    = 0x02
TYPE_JOIN    = 0x03
TYPE_MSG     = 0x04
TYPE_BYE     = 0xFF

# Add these variables to track clients
client_sockets = {}  # addr -> dynamic_socket
client_msg_ids = {}  # addr -> set of seen message IDs

def debug_hex(data):
    return ' '.join(f'{b:02X}' for b in data)

def parse_udp_fields(data):
    """
    Parse the zero-terminated string fields starting from offset 3.
    Returns a list of decoded fields.
    """
    fields = []
    pos = 3  # Skip 1 byte type and 2 bytes message ID.
    while pos < len(data):
        try:
            # Find next zero byte.
            end = data.index(0, pos)
        except ValueError:
            break
        field = data[pos:end].decode('ascii', errors='replace')
        fields.append(field)
        pos = end + 1
    return fields

def udp_handle_message(udp_sock):
    try:
        data, addr = udp_sock.recvfrom(1024)
    except Exception as e:
        print(f"[UDP] Error receiving: {e}")
        return
    if not data:
        return
    print(f"[UDP] === Received {len(data)} bytes from {addr} ===")
    print(f"[UDP] Raw data: {debug_hex(data)}")
    
    if len(data) < 3:
        print(f"[UDP] Received too short packet from {addr}")
        return
    msg_type = data[0]
    (msg_id,) = struct.unpack("!H", data[1:3])
    print(f"[UDP] Parsed Header: Type=0x{msg_type:02X}, MsgID={msg_id}")
    
    # Decode any zero-terminated fields.
    fields = parse_udp_fields(data)
    if msg_type == TYPE_AUTH:
        if len(fields) >= 3:
            print(f"[UDP] AUTH fields: username='{fields[0]}', displayName='{fields[1]}', secret='{fields[2]}'")
        else:
            print("[UDP] AUTH: Not enough fields!")
    elif msg_type == TYPE_JOIN:
        if len(fields) >= 2:
            print(f"[UDP] JOIN fields: channelID='{fields[0]}', displayName='{fields[1]}'")
        else:
            print("[UDP] JOIN: Not enough fields!")
    elif msg_type == TYPE_MSG:
        if len(fields) >= 2:
            print(f"[UDP] MSG fields: displayName='{fields[0]}', messageContent='{fields[1]}'")
        else:
            print("[UDP] MSG: Not enough fields!")
    elif msg_type == TYPE_BYE:
        if len(fields) >= 1:
            print(f"[UDP] BYE field: displayName='{fields[0]}'")
        else:
            print("[UDP] BYE: Not enough fields!")
    else:
        print(f"[UDP] Received message of type 0x{msg_type:02X} with fields: {fields}")
    
    # Check for duplicates
    client_key = f"{addr[0]}:{addr[1]}"
    if client_key not in client_msg_ids:
        client_msg_ids[client_key] = set()
    
    # Send CONFIRM from the receiving socket
    confirm = struct.pack("!B H", TYPE_CONFIRM, msg_id)
    udp_sock.sendto(confirm, addr)
    print(f"[UDP] Sent CONFIRM for MsgID={msg_id} to {addr}")
    
    # Check if this is a duplicate
    if msg_id in client_msg_ids[client_key]:
        print(f"[UDP] Ignoring duplicate message ID {msg_id} from {addr}")
        return
        
    client_msg_ids[client_key].add(msg_id)
    
    # For AUTH, create a new dynamic socket and respond from it
    if msg_type == TYPE_AUTH:
        if client_key not in client_sockets:
            # Create dynamic socket
            dynamic_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dynamic_sock.bind((HOST, 0))  # Bind to random port
            dynamic_port = dynamic_sock.getsockname()[1]
            client_sockets[client_key] = dynamic_sock
            print(f"[UDP] Created dynamic socket on port {dynamic_port} for {addr}")
            
        time.sleep(0.1)  # Existing delay
        
        # Send REPLY from dynamic socket
        dynamic_sock = client_sockets[client_key]
        new_msg_id = msg_id + 1
        reply = struct.pack("!B H B H", TYPE_REPLY, new_msg_id, 1, msg_id)
        content = "Auth success.".encode('ascii') + b'\x00'
        reply += content
        dynamic_sock.sendto(reply, addr)
        print(f"[UDP] Sent REPLY from port {dynamic_sock.getsockname()[1]} for AUTH MsgID={msg_id} to {addr}")
    
    # Handle other messages using the dynamic socket if available
    elif client_key in client_sockets and msg_type in [TYPE_JOIN, TYPE_MSG, TYPE_BYE]:
        dynamic_sock = client_sockets[client_key]
        time.sleep(0.1)
        new_msg_id = msg_id + 1
        
        if msg_type == TYPE_JOIN:
            reply = struct.pack("!B H B H", TYPE_REPLY, new_msg_id, 1, msg_id)
            content = "Join success.".encode('ascii') + b'\x00'
            reply += content  # Add this line to include the content string
            dynamic_sock.sendto(reply, addr)
            print(f"[UDP] Sent REPLY from dynamic socket for JOIN MsgID={msg_id} to {addr}")
        
        # Add handling for MSG and BYE too
    else:
        print(f"[UDP] No additional REPLY for message type 0x{msg_type:02X}")

def tcp_handle_client(conn, addr):
    print(f"[TCP] Client connected from {addr}")
    buffer = ""
    while True:
        data = conn.recv(1024)
        if not data:
            print(f"[TCP] Client disconnected: {addr}")
            break
        buffer += data.decode('ascii', errors='replace')
        while "\r\n" in buffer:
            line, buffer = buffer.split("\r\n", 1)
            line = line.strip()
            if not line:
                continue
            print(f"[TCP] Received: {line}")
            if line.startswith("AUTH"):
                response = "REPLY OK IS Auth success.\r\n"
                conn.sendall(response.encode('ascii'))
                print(f"[TCP] Sent: {response.strip()}")
            elif line.startswith("JOIN"):
                response = "REPLY OK IS Join success.\r\n"
                conn.sendall(response.encode('ascii'))
                print(f"[TCP] Sent: {response.strip()}")
            elif line.startswith("MSG"):
                response = "MSG FROM Server IS Thanks for your message.\r\n"
                conn.sendall(response.encode('ascii'))
                print(f"[TCP] Sent: {response.strip()}")
            elif line.startswith("BYE"):
                response = "BYE FROM Server\r\n"
                conn.sendall(response.encode('ascii'))
                print(f"[TCP] Sent: {response.strip()}")
                conn.close()
                return
            else:
                print(f"[TCP] Unknown command: {line}")

def main():
    # Create and configure TCP socket.
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind((HOST, PORT))
    tcp_sock.listen(5)
    tcp_sock.setblocking(False)
    print(f"[*] TCP server listening on {HOST}:{PORT}")

    # Create and configure UDP socket.
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((HOST, PORT))
    udp_sock.setblocking(False)
    print(f"[*] UDP server listening on {HOST}:{PORT}")

    sockets = [tcp_sock, udp_sock]
    while True:
        readable, _, _ = select.select(sockets, [], [])
        for s in readable:
            if s is tcp_sock:
                conn, addr = tcp_sock.accept()
                tcp_handle_client(conn, addr)
            elif s is udp_sock:
                udp_handle_message(udp_sock)

if __name__ == "__main__":
    main()
