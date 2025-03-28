#!/usr/bin/env python3
import socket

HOST = '0.0.0.0'   # Listen on all interfaces
PORT = 4567        # Change if you prefer another port

def handle_client(conn, addr):
    print(f"[+] Client connected from {addr}")
    
    buffer = ""
    while True:
        data = conn.recv(1024)
        if not data:
            print(f"[-] Client disconnected: {addr}")
            break
        
        buffer += data.decode('ascii', errors='replace')
        
        # We split on '\r\n' to find complete lines.
        while '\r\n' in buffer:
            line, buffer = buffer.split('\r\n', 1)
            line = line.strip()
            if not line:
                continue
            
            print(f"Received: {line}")
            
            # Check which command was received
            if line.startswith("AUTH"):
                # e.g. "AUTH username AS DisplayName USING secret"
                response = "REPLY OK IS Auth success.\r\n"
                conn.sendall(response.encode('ascii'))
            
            elif line.startswith("JOIN"):
                # e.g. "JOIN channel AS DisplayName"
                response = "REPLY OK IS Join success.\r\n"
                conn.sendall(response.encode('ascii'))
            
            elif line.startswith("MSG"):
                # e.g. "MSG FROM DisplayName IS Hello"
                # Just echo or send a dummy message
                response = "MSG FROM Server IS Thanks for your message.\r\n"
                conn.sendall(response.encode('ascii'))
            
            elif line.startswith("BYE"):
                # e.g. "BYE FROM DisplayName"
                response = "BYE FROM Server\r\n"
                conn.sendall(response.encode('ascii'))
                conn.close()
                return  # End the function, closing the connection
            
            else:
                # Unknown or unhandled command
                # You could send an ERR or just ignore
                pass

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[*] Listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    main()
