<div align="center">

# `ssh honeypot`

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/rihadroshan/ssh-honeypot/blob/main/LICENSE)

This project is an SSH honeypot implemented in Python. The honeypot logs authentication attempts and command executions, providing insights into potential malicious activities.
</div>

## Features

- Logs SSH connection attempts, including usernames and passwords.
- Simulates an interactive shell environment.
- Logs executed commands.
- Provides customizable username and password for authentication.

### Usage 

By default, the honeypot will use the username `root`; no password is required.

```sh
python3 main.py -a <address> -p <port>
```

### Usage with Custom Authentication

```sh
python3 main.py -a <address> -p <port> -u <username> -w <password>
```

### Examples

Basic Usage:
```sh
python3 main.py -a 0.0.0.0 -p 2222
sudo python3 main.py -a 0.0.0.0 -p 22
```

Usage with Custom Authentication:

```sh
python3 main.py -a 0.0.0.0 -p 2222 -u ubuntu -d passwd 
sudo python3 main.py -a 0.0.0.0 -p 22 -u ubuntu -d passwd 
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

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Disclaimer

This tool is intended for educational and research purposes only. Use it responsibly and only on networks you own or have permission to test.

## Files in the Repository

- **`main.py`**: The main Python script for the SSH honeypot.
- **`README.md`**: This readme file providing an overview and usage instructions.
- **`LICENSE`**:  The license file (`LICENSE`) contains the legal terms under which the SSH honeypot project is distributed and used.
