import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import argparse
import os
import signal
import sys
from datetime import datetime

logging.basicConfig(filename='ssh_sys.log', level=logging.INFO, format='%(asctime)s - %(message)s')

SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

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
        creds_logger.info(f'Authentication attempt: IP={self.client_ip}, username={username}, password={password}')

        if self.input_username is None and self.input_password is None:
            funnel_logger.info(f"Default login successful for IP={self.client_ip}, username={username}")
            return paramiko.AUTH_SUCCESSFUL

        if username == self.input_username and password == self.input_password:
            funnel_logger.info(f"Authentication successful for IP={self.client_ip}, username={username}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            funnel_logger.warning(f"Authentication failed for IP={self.client_ip}, username={username}")
            return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True


def emulated_shell(channel, client_ip, username="root"):
    file_system = {
        "/root": {
            "config.txt": "This is the root user's config file.",
            "secret.key": "-----BEGIN RSA PRIVATE KEY-----1079a055f110d54ba12f08bd6b671f6c-----END RSA PRIVATE KEY-----",
        },
        f"/home/{username}": {
            "Desktop": {},  # Empty directory
            "Documents": {},  # Empty directory
            "Downloads": {},  # Empty directory
            "Music": {},  # Empty directory
            "notes.txt": "hello friend",
            "Pictures": {},  # Empty directory
            "Public": {},  # Empty directory
            "secret.txt": "This is a super secret file!",
            "Templates": {},  # Empty directory
            "Videos": {},  # Empty directory
        },
    }

    if username == "root":
        current_directory = "/root"
        prompt = f"root@webcorp:{current_directory}# "
    else:
        current_directory = f"/home/{username}"
        prompt = f"{username}@webcorp:{current_directory}$ "

    channel.send(prompt.encode())

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
                current_line = current_line[:-1]
                command = command[:-1]
                cursor_position -= 1
                channel.send(b'\x08 \x08')
            continue
            
        channel.send(char)
        current_line += char
        command += char
        cursor_position += 1

        if char == b"\r":
            command = command.strip()
            response = b""

            if command == b'exit':
                response = b"\nGoodbye!\n"
                channel.send(response)
                channel.close()
                break
            elif command == b'pwd':
                response = f"\n{current_directory}\r\n".encode()
            elif command == b'whoami':
                response = f"\n{username}\r\n".encode()
            elif command == b'ls':
                files = file_system.get(current_directory, {})
                response = f"\n{'  '.join(files.keys())}\r\n".encode()
            elif command == b'cd ..':
                response = b"\n-bash: cd..: Permission denied\r\n"
            elif command == b'cd ../..':
                response = b"\n-bash: cd../..: Permission denied\r\n"
            elif command == b'uname':
                response = b"\nLinux\r\n"
            elif command == b'uname -a':
                current_time = datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')
                response = f"\nLinux webcorp 2.6.24-16-generic #1 SMP {current_time} i686 GNU/Linux\r\n".encode()
            elif command == b'uname -r':
                response = b"\n2.6.24-16-generic\r\n"
            elif command == b'id':
                response = f"\nuid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users)\r\n"
            elif command == b'hostname':
                response = b"\nwebcorp\r\n"
            elif command == b'echo $SHELL':
                response = f"\n/bin/bash\r\n".encode()
            elif command == b'which $SHELL':
                response = f"\n/bin/bash\r\n".encode()
            elif command.startswith(b'cd '):
                target = command.split(b' ')[1].decode()
                files = file_system.get(current_directory, {})
                if target in files:
                    if isinstance(files[target], dict):
                        current_directory = f"{current_directory}/{target}"
                        response = f"\n{current_directory}\r\n".encode()
                    else:
                        response = f"\ncd: not a directory: {target}\r\n".encode()
                else:
                    response = f"\ncd: {target}: No such file or directory\r\n".encode()
            elif command.startswith(b'cat '):
                target = command.split(b' ')[1].decode()
                files = file_system.get(current_directory, {})
                if target in files:
                    if isinstance(files[target], dict):
                        response = f"\ncat: {target}: Is a directory\r\n".encode()
                    else:
                        response = f"\n{files[target]}\r\n".encode()
                else:
                    response = f"\ncat: {target}: No such file or directory\r\n".encode()
            elif command == b"sudo su":
                response = b""
            else:
                response = f"\n{command.decode()}: command not found\r\n".encode()

            funnel_logger.info(f'Command {command.decode()} executed by {client_ip}')
            channel.send(response)
            channel.send(f"{username}@webcorp:{current_directory}$ ".encode())
            command = b""
            current_line = b""
            cursor_position = 0


def client_handle(client, addr, username, password):
    client_ip = addr[0]
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        server = SSHServer(client_ip=client_ip, input_username=username, input_password=password)
        server_key = paramiko.RSAKey(filename='server.key')
        transport.add_server_key(server_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            funnel_logger.error(f"No channel was opened for {client_ip}.")
            return

        server.event.wait(10)
        if not server.event.is_set():
            funnel_logger.warning(f'Client {client_ip} never asked for a shell')
            return
        
        prompt_username = username if username else "root"

        channel.send(f"Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n\r\n".encode())
        emulated_shell(channel, client_ip=client_ip, username=prompt_username)

    except Exception as error:
        funnel_logger.error(f"Exception occurred with client {client_ip}: {error}")
    finally:
        try:
            transport.close()
        except Exception as close_error:
            funnel_logger.error(f"Failed to close transport for {client_ip}: {close_error}")
        client.close()

def main(address, port, username, password):
    if not os.path.exists('server.key'):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file('server.key')
    print(f"\nStarting server with username: {username} password: {password}\n")
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


class CustomParser(argparse.ArgumentParser):
    def error(self, message):
        print("SSH Honeypot: Try '-h' or '--help' for more options.")
        self.exit(2)

    def format_help(self):
        return (
            "SSH Honeypot Server 2.25 (https://github.com/rihadroshan/ssh-honeypot)\n\n"
            "required arguments:\n"
            "  -p, --port <port>          Port to listen on\n\n"
            "optional arguments:\n"
            "  -a, --address <IP>         IP address to bind (default: machine's IP address)\n"
            "  -u, --username <username>  Username to accept (default: root)\n"
            "  -d, --password <password>  Password to accept (default: no password)\n"
            "  -v, --version              Display version information\n"
            "  -h, --help                 Get help for commands\n\n"
            "Report bugs to: https://github.com/rihadroshan/ssh-honeypot\n"
        )

    def parse_known_args(self, args=None, namespace=None):
        if args is None:
            args = sys.argv[1:]

        try:
            return super().parse_known_args(args, namespace)
        except argparse.ArgumentError as e:
            self.print_usage(sys.stderr)
            print(f"{self.prog}: error: {e}", file=sys.stderr)
            sys.exit(2)

def get_default_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        print(f"Failed to get default IP address: {e}")
        return "0.0.0.0"

def signal_handler(sig, frame):
    print("\nShutting down the server..")
    try:
        global running
        running = False
        
        if 'socks' in globals():
            socks.close()
            
        print("Waiting for existing connections to close...")
        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join(timeout=1.0)
                
    except Exception as e:
        print(f"Error during shutdown: {e}")
    finally:
        print("Server shutdown complete")
        os._exit(0)

def main(address, port, username, password):
    global socks, running
    running = True

    if not os.path.exists('server.key'):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file('server.key')
    print(f"\nStarting server with username: {username} password: {password}\n")
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)

    print(f"SSH server is listening on {address}:{port}.")

    signal.signal(signal.SIGINT, signal_handler)

    while running:
        try:
            socks.settimeout(1.0)
            try:
                client, addr = socks.accept()
                threading.Thread(target=client_handle, args=(client, addr, username, password)).start()
            except socket.timeout:
                continue
        except Exception as error:
            if running:
                print(f"Exception occurred in accepting client: {error}")

if __name__ == "__main__":
    parser = CustomParser(
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    required_group = parser.add_argument_group('required arguments')
    required_group.add_argument('-p', '--port', type=int, required=True, help='Port to listen on')

    optional_group = parser.add_argument_group('optional arguments:')
    optional_group.add_argument('-a', '--address', type=str, help="IP address to bind (default: machine's IP address)")
    optional_group.add_argument('-u', '--username', type=str, help="Username to accept (default: root)")
    optional_group.add_argument('-d', '--password', type=str, help="Password to accept (default: no password)")
    optional_group.add_argument('-v', '--version', action='version', version='SSH Honeypot Server 2.25', help='Display version information')

    help_group = parser.add_argument_group()
    help_group.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Get help for commands')

    args = parser.parse_args()

    address = args.address if args.address else get_default_ip()

    print(f"Starting server with IP address: {address}, Port: {args.port}")
    if args.username:
        print(f"Username: {args.username}")
    if args.password:
        print(f"Password: {args.password}")

    main(address, args.port, args.username, args.password)
