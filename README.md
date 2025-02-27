# SSH Key Management Guide

This guide explains how to set up and use the SSH Key Management Script (`ssh-keyman.sh`), which simplifies the creation, organization, and management of SSH keys for cloud server access.

## Overview

The SSH Key Management Script automates SSH key management with a consistent naming convention and directory structure. It helps you:

- Create and organize SSH keys by environment (dev/prod)
- Generate properly formatted SSH config entries
- Manage keys with ssh-agent for password-less login
- Delete keys and their configuration when no longer needed
- List all keys in your system with their configuration details

## Installation

### 1. Save the Script

Save the script in your SSH directory:

```bash
mkdir -p ~/.ssh
# Download the script
curl -o ssh-keyman.sh https://raw.githubusercontent.com/sudharsan-007/keyman/main/ssh-keyman.sh
# Download the README
curl -o README.md https://raw.githubusercontent.com/sudharsan-007/keyman/main/README.md
# Make the script executable
chmod +x ssh-keyman.sh
```

One-liner for convenience: 
```bash
curl -o ssh-keyman.sh https://raw.githubusercontent.com/sudharsan-007/keyman/main/ssh-keyman.sh && curl -o README.md https://raw.githubusercontent.com/sudharsan-007/keyman/main/README.md && chmod +x ssh-keyman.sh
```

Or create it manually:

```bash
nano ~/.ssh/ssh-keyman.sh
# Paste the script content
chmod +x ~/.ssh/ssh-keyman.sh
```

### 2. Set Up the Alias

Add an alias to your shell configuration file:

For Bash (in `~/.bashrc`):
```bash
echo 'alias sshsetup="~/.ssh/ssh-keyman.sh"' >> ~/.bashrc
source ~/.bashrc
```

For Zsh (in `~/.zshrc`):
```bash
echo 'alias sshsetup="~/.ssh/ssh-keyman.sh"' >> ~/.zshrc
source ~/.zshrc
```

## Directory Structure

The script creates and maintains the following directory structure:

```
~/.ssh/
├── config                  # SSH client configuration file
├── keys/                   # Base directory for all SSH keys
│   ├── dev/                # Development environment keys
│   │   ├── do-librechat-sudu           # Private key
│   │   └── do-librechat-sudu.pub       # Public key
│   └── prod/               # Production environment keys
│       ├── do-librechat-sudu           # Private key
│       └── do-librechat-sudu.pub       # Public key
└── known_hosts            # Known hosts file
```

## Naming Convention

Keys follow a structured naming convention:
- `{provider}-{app}-{user}`

Where:
- `provider`: Cloud provider identifier (e.g., `do` for Digital Ocean)
- `app`: Application or project name (e.g., `librechat`)
- `user`: Username on the remote server

Environment (dev/prod) is determined by the directory structure.

## Usage

### Basic Usage

Use the `sshsetup` alias to run the script from anywhere in your system:

```bash
sshsetup
```

Without parameters, the script will display an interactive menu with options.

### Creating a New Key

Interactive mode:
```bash
sshsetup create
```

Non-interactive mode with parameters:
```bash
sshsetup create --env dev --provider do --app librechat --user sudu --ip 123.45.67.89
```

### Listing Keys

Display all managed keys:
```bash
sshsetup list
```

### Deleting a Key

Delete a key and its configuration:
```bash
sshsetup delete
```

### Editing Config

Update configuration for an existing key:
```bash
sshsetup edit
```

### Help

Show all available commands and options:
```bash
sshsetup help
```

## SSH Agent Integration

The script automatically adds new keys to ssh-agent if it's running. To ensure keys are loaded at startup, add these lines to your shell's startup file:

```bash
# Start SSH agent if not running
if [ -z "$SSH_AUTH_SOCK" ]; then
  eval "$(ssh-agent -s)"
fi

# Add your most used keys
ssh-add ~/.ssh/keys/dev/do-librechat-sudu 2>/dev/null
```

## SSH Config Example

The script creates SSH config entries in this format:

```
Host do-librechat-sudu-dev
    HostName 123.45.67.89
    User sudu
    IdentityFile ~/.ssh/keys/dev/do-librechat-sudu
    ForwardAgent yes
```

## Common Workflows

### Setting Up a New Server

1. Create a new SSH key:
   ```bash
   sshsetup create
   ```
   
2. Copy the public key to the server:
   ```bash
   ssh-copy-id -i ~/.ssh/keys/dev/do-librechat-sudu user@server-ip
   ```
   
3. Connect to the server:
   ```bash
   ssh do-librechat-sudu-dev
   ```

### Rotating Keys

1. Create a new key with the same app and user:
   ```bash
   sshsetup create
   ```
   
2. Add the new key to the server
3. Test the new key works
4. Delete the old key:
   ```bash
   sshsetup delete
   ```

## Troubleshooting

### Permission Denied Errors

If you get "Permission denied" when connecting:

1. Ensure the key has correct permissions:
   ```bash
   chmod 600 ~/.ssh/keys/dev/do-librechat-sudu
   ```

2. Verify the key is loaded in ssh-agent:
   ```bash
   ssh-add -l
   ```

3. Check connection with verbose output:
   ```bash
   ssh -v do-librechat-sudu-dev
   ```

### Key Not Working with Agent

If ssh-agent isn't recognizing your key:

1. Restart ssh-agent:
   ```bash
   eval "$(ssh-agent -s)"
   ```

2. Add key explicitly:
   ```bash
   ssh-add ~/.ssh/keys/dev/do-librechat-sudu
   ```

## Best Practices

1. **Use ED25519 keys** - They're smaller, faster, and more secure than RSA keys.

2. **Organize by environment** - Keep development and production keys separate.

3. **Use descriptive names** - Follow the naming convention for clarity.

4. **Set up aliases** - Create aliases for frequent connections:
   ```bash
   alias goto-librechat-dev="ssh do-librechat-sudu-dev"
   ```

5. **Regular backups** - Back up your `~/.ssh` directory regularly.

## Security Considerations

- Set appropriate permissions on SSH keys (private keys: 600, public keys: 644)
- Limit SSH access on your servers to key-based authentication only
- Consider using separate keys for different services/applications
- Rotate keys periodically for sensitive environments

## Advanced Features

### Multiple Users on Same Server

For servers where you need to connect as different users, create separate keys:

```bash
sshsetup create --env prod --provider do --app librechat --user admin
sshsetup create --env prod --provider do --app librechat --user deploy
```

### Different Key Types

For systems with specific requirements:

```bash
sshsetup create --key-type rsa  # For older systems
sshsetup create --key-type ecdsa  # Alternative to ED25519
```

## Additional Resources

- [OpenSSH Documentation](https://www.openssh.com/manual.html)
- [SSH Key Management Best Practices](https://www.ssh.com/academy/ssh/keygen)
- [SSH Agent Forwarding Explained](https://www.ssh.com/academy/ssh/agent)