import sys
import socket
import datetime
import json
import threading
import time
from pathlib import Path
"""
Socket and Threading???
followed tutorial and learned through https://www.freecodecamp.org/news/build-a-honeypot-with-python/
Going to go back through and comment it more
"""


"""
What does this honeypot do?

This honey pot contains a network listner, logging system, and emulation to interact with attackers.
"""

LOG_DIR = Path("honeypot_logs")
LOG_DIR.mkdir(exist_ok=True)

#Creating a class Honeypot
#initalizing
class Honeypot:
    def __init__(self, bind_ip="0.0.0.0", ports=None):
        self.bind_ip = bind_ip
        self.ports = ports or [21,22, 80, 443]
        self.active_connections = {}
        self.log_file = LOG_DIR / f"honeypot_{datetime.datetime.now().strftime('%Y%m%d')}.json"
        #defines the IP address to listen on self.bind_ip as it is set to 0.0.0.0 = all interfaces.
        #self.ports = ports or [21,22,80,443] sets ports to listen on which is listed FTP, SSH, HTTP and the HTTPS protocols.
        #self.active_connections = {} sets the variable to an empty dictionary. It stores active connections
        #self.log_file = LOG_DIR /...       formatted string, defines the log file path using current date.
    
    #dictonary
    def log_activity(self, port, remote_ip, data):
        activity = {
            "timestamp": datetime.datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "port": port,
            "data": data.decode('utf-8', errors='ignore')
            #"timestamp": datetime.datetime.now().. 

        }
        with open(self.log_file, 'a') as f:
            json.dump(activity, f)
            f.write('\n')
    #dictonary
    def handle_connection(self, client_socket, remote_ip, port):
        
        service_banners = {
            21: "220 FTP server ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu) \r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu) \r\n\r\n"
        }

        try: 
            
            if port in service_banners:
                client_socket.send(service_banners[port].encode())

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                self.log_activity(port, remote_ip, data)

                client_socket.send(b"Command not recognized. \r\n")
        except Exception as e:
            print(f"Error handling connection: {e}")
        finally:
            client_socket.close()
    

    def start_listner(self,port):
        """Start a listner on specified port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.bind_ip, port))
            server.listen(5)

            print(f"[*] Listening on {self.bind_ip}:{port}")

            while True:
                client, addr = server.accept()
                print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

                #Handle connection in separate thread
                client_handler = threading.Thread(
                    target=self.handle_connection,
                    args=(client,addr[0],port)
                )
                client_handler.start()
        
        except Exception as e:
            print(f"Error starting listner on port {port}: {e}")
    

def main():
    
    honeypot = Honeypot()
    
    #Starts listners for each port in seperate threads
    for port in honeypot.ports:
        listener_thread = threading.Thread(
            target=honeypot.start_listner,
            args=(port,)
        )
        listener_thread.daemon = True
        listener_thread.start()

        try:
            # Keep main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot...")
            sys.exit(0)

if __name__ == "__main__":
    main()
        

 