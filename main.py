import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import argparse

logging.basicConfig(filename='ssh_sys.log', level=logging.INFO, format='%(asctime)s - %(message)s')

server_key = paramiko.RSAKey(filename='server.key')

SSH_BANNER = "SSH-2.0-SSHServer_1.0"

funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('command_log.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('auth.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
creds_logger.addHandler(creds_handler)

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        
        if self.input_username and self.input_password:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def emulated_shell(channel, client_ip, username="root"):
    channel.send(f"{username}@webcorp:/home/{username}# ".encode())
    command = b""
    current_line = b""
    cursor_position = 0
    
    while True:
        char = channel.recv(1)
        if not char:
            channel.close()
            break

        if char in (b'\x7f', b'\x08'):
            if cursor_position > 0:
                # Remove last character from current line
                current_line = current_line[:-1]
                command = command[:-1]
                cursor_position -= 1
                # Send backspace sequence: backspace, space, backspace
                channel.send(b'\x08 \x08')
            continue

        channel.send(char)
        current_line += char
        command += char
        cursor_position += 1

        if char == b"\r":
            command = command.strip()
            if command == b'exit':
                response = b"\nGoodbye!\n"
                channel.send(response)
                channel.close()
                break
            elif command == b'pwd':
                response = f"\n/home/{username}\r\n".encode()
            elif command == b'echo $SHELL':
                response = f"\n/bin/bash\r\n".encode()
            elif command == b'which $SHELL':
                response = f"\n/bin/bash\r\n".encode()
            elif command == b'whoami':
                response = f"\n{username}\r\n".encode()
            elif command == b'ls':
                response = b"\ncode.js  temp\r\n"
            elif command == b'ls -a':
                response = b"\n.  ..  .rsa_key  code.js  temp\r\n"
            elif command == b'cd code.js':
                response = b"\n-bash: cd: code.js: Not a directory\r\n"
            elif command == b'cat code.js':
                response = b"\nhello World\r\n"
            elif command == b'uname':
                response = b"\nLinux\r\n"
            elif command == b'hostname':
                response = b"\nwebcorp\r\n"
            elif command == b'cd temp':
                response = b"\n-bash: cd: /temp: Permission denied\r\n"
            elif command == b'cat temp':
                response = b"\ncat: temp: Is a directory\r\n"
            elif command == b'cd .rsa_key':
                response = b"\n-bash: cd: .rsa_key: Not a directory\r\n"
            elif command == b'cat .rsa_key':
                response = b"\n-bash: cat: .rsa_key: Permission denied\r\n"
            elif command == b'cd ..':
                response = b"\n-bash: cd..: Permission denied\r\n"
            else:
                response = f"\n{command.decode()}\r\n".encode()

            funnel_logger.info(f'Command {command.decode()} executed by {client_ip}')
            channel.send(response)
            channel.send(f"{username}@webcorp:/home/{username}# ".encode())
            command = b""
            current_line = b""
            cursor_position = 0

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        server = SSHServer(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(server_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            funnel_logger.error(f"No channel was opened for {client_ip}.")
            return

        prompt_username = username if username else "root"
        channel.send(f"Welcome to Ubuntu 8.04 LTS (Hardy Heron) as {prompt_username}!\r\n\r\n".encode())
        emulated_shell(channel, client_ip=client_ip, username=prompt_username)

    except Exception as error:
        funnel_logger.error(f"Exception occurred with client {client_ip}: {error}")
    finally:
        try:
            transport.close()
        except Exception as close_error:
            funnel_logger.error(f"Failed to close transport for {client_ip}: {close_error}")
        client.close()

def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            threading.Thread(target=client_handle, args=(client, addr, username, password)).start()
        except Exception as error:
            print(f"Exception occurred in accepting client: {error}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', type=str, required=True, help='IP address')
    parser.add_argument('-p', '--port', type=int, required=True, help='PORT')
    parser.add_argument('-u', '--username', type=str, help='Username')
    parser.add_argument('-d', '--password', type=str, help='Password')
    args = parser.parse_args()

    try:
        honeypot(args.address, args.port, args.username, args.password)
    except KeyboardInterrupt:
        print("\nSSH server terminated.")
