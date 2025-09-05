# Async SSH Tool (Educational SSH Client/Server)

> DISCLAIMER: This project is for educational and research purposes only.  
> It demonstrates how to build an asynchronous SSH client/server in Python using `asyncssh` and `cryptography`.  
> Do not use this on systems or networks you do not own or explicitly control.

## Overview
This project provides a simple SSH tool that can run as either a client or a server.  
It is intended for lab environments to explore:

- Asynchronous SSH connections with Python `asyncssh`  
- Running remote commands over SSH  
- Interactive SSH sessions  
- Building a minimal SSH server with password authentication  
- Generating RSA key pairs for SSH authentication  

## Features
- Client Mode
  - Connects to a remote SSH server with password or key-based auth  
  - Execute commands or open an interactive shell  
- Server Mode
  - Run a simple SSH server with password authentication (default creds configurable)  
  - Supports key-based authentication (planned extension)  
- RSA Key Generation
  - Generates 2048-bit RSA key for server identity  

## Project Structure
```
.
├── src/
│   └── bhssh_tool.py
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── CONTRIBUTING.md
├── CHANGELOG.md
└── config.example.json
```

## Quick Start (Lab Only)
```bash
pip install -r requirements.txt

# Run server (lab)
python src/bhssh_tool.py -l -H 127.0.0.1 -P 2222 --auth password

# Run client
python src/bhssh_tool.py -H 127.0.0.1 -P 2222 -u admin -p securepassword --command "whoami"

# Interactive client
python src/bhssh_tool.py -H 127.0.0.1 -P 2222 -u admin -p securepassword --interactive
```

## Key Generation
```bash
python src/bhssh_tool.py --genkey server_key.pem
```

## Educational Value
This project demonstrates:  
- Python `asyncio` and `asyncssh` for networking  
- Secure key generation using `cryptography`  
- Building custom SSH client/server flows  
- Handling interactive shells in async code  

## Ethical Use
- Use for labs, demos, and educational practice  
- Do not use on unauthorized networks or systems  

## License
Licensed under GPL-3.0.

Author: Ishaq — Async SSH Tool (Educational Client/Server)

## ☕ Support My Work

If you find my projects helpful and want to support me, you can donate using the addresses below:

- **USDT (TRC-20):** TAW81Mk7z7TTGRMMve91fgAyCGskXVvjy7

