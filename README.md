This SSH honeypot logs authentication attempts and command executions, providing insights into potential malicious activities.

## Features

- Logs SSH connection attempts, including usernames and passwords.
- Simulates an interactive shell environment.
- Logs executed commands.
- Provides customizable username and password for authentication.

### Basic Usage 

By default, the honeypot will use the username `root`; no password is required.

```sh
python3 server.py -a <IP address> -p <port>
```

### Usage with Custom Authentication

```sh
python3 server.py -a <IP address> -p <port> -u <username> -w <password>
```

### Examples

Basic Usage:
```sh
python3 server.py -a 0.0.0.0 -p 2222

sudo python3 server.py -a 0.0.0.0 -p 22
```

Usage with Custom Authentication:

```sh
python3 server.py -a 0.0.0.0 -p 2222 -u ubuntu -d passwd

sudo python3 server.py -a 0.0.0.0 -p 22 -u ubuntu -d passwd 
```

### Arguments

* `-a`, `--address`: IP address.
* `-p`, `--port`: Port number.
* `-u`, `--username`: (Optional) Username for authentication.
* `-d`, `--password`: (Optional) Password for authentication.

## Logs

The honeypot logs activities in three files:

- `ssh_sys.log`: General log file for server activities.
- `command_log.log`: Log file for executed commands.
- `auth.log`: Log file for authentication attempts.

## License

This project is licensed under the MIT License. See the `LICENSE.md` file for details.

## Contributions & Reporting Issues:

Contributions of new features, improvements, or bug fixes are always welcome!

Feel free to open a pull request or open an issue.

## Disclaimer

This tool is intended for educational and research purposes only. Use it responsibly and only on networks you own or have permission to test.

## Files in the Repository

- **`server.py`**: The main Python script for the SSH honeypot.
- **`README.md`**: This readme file providing an overview and usage instructions.
- **`LICENSE`**:  The license file (`LICENSE`) contains the legal terms under which the SSH honeypot project is distributed and used.
