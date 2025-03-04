# KeyVault SSH - v1.2.0
t
A robust SSH key management system for cloud infrastructure that simplifies creation, organization, and management of SSH keys with a consistent naming convention and directory structure.

*Previously known as ssh-keyman*

## Features

- Create and organize SSH keys by environment (dev/prod)
- Generate properly formatted SSH config entries
- Manage keys with ssh-agent for password-less login
- Delete keys and their configuration when no longer needed
- View all keys in your system with table or list formats with sequential numbering
- Display IP addresses for your SSH keys in verbose mode
- Generate keys following cloud provider workflows (key first, then server creation)
- Support for multiple users on the same server
- Provider-specific instructions for Digital Ocean, Linode, and GCP
- Clean known_hosts entries when servers are recreated to prevent "man-in-the-middle" warnings

## Developments in Progress

- **Key rotation automation**: Streamlined process for regularly updating SSH keys for enhanced security
- **Backup/restore functionality**: Easily back up and restore your SSH keys and configurations
- **Enhanced web interface**: Planned GUI for managing SSH keys more visually
- **Multi-server deployment**: Simplified key deployment across multiple servers

## Installation

### 1. Save the Script

Save the script in your SSH directory:

```bash
mkdir -p ~/.ssh
# Download the script
curl -o ~/.ssh/ssh-keyvault.sh https://raw.githubusercontent.com/sudharsan-007/keyman/main/ssh-keyvault.sh
# Download the README
curl -o README.md https://raw.githubusercontent.com/sudharsan-007/keyman/main/README.md
# Make the script executable
chmod +x ~/.ssh/ssh-keyvault.sh
```

One-liner for convenience: 
```bash
curl -o ~/.ssh/ssh-keyvault.sh https://raw.githubusercontent.com/sudharsan-007/keyman/main/ssh-keyvault.sh && curl -o README.md https://raw.githubusercontent.com/sudharsan-007/keyman/main/README.md && chmod +x ~/.ssh/ssh-keyvault.sh
```

Or create it manually:

```bash
nano ~/.ssh/ssh-keyvault.sh
# Paste the script content
chmod +x ~/.ssh/ssh-keyvault.sh
```

### 2. Set Up the Alias

Add an alias to your shell configuration file:

For Bash (in `~/.bashrc`):
```bash
echo 'alias kv="~/.ssh/ssh-keyvault.sh"' >> ~/.bashrc
source ~/.bashrc
```

For Zsh (in `~/.zshrc`):
```bash
echo 'alias kv="~/.ssh/ssh-keyvault.sh"' >> ~/.zshrc
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

## Workflow

The script follows the typical cloud provider workflow:

1. First, the SSH key is generated
2. You receive provider-specific instructions for adding the key to your cloud console
3. After adding the key and creating your server, you provide the IP address
4. The script configures your SSH config and adds the key to your SSH agent

This workflow ensures your SSH key is available during server creation, which is required by most cloud providers.

## Usage

### Basic Usage

Use the `kv` alias to run the script from anywhere in your system:

```bash
kv
```

Without parameters, the script will display an interactive menu with options.

### Creating a New Key

Interactive mode:
```bash
kv create
```

Non-interactive mode with parameters:
```bash
kv create --env dev --provider do --app librechat --user sudu --ip 123.45.67.89
``` 

#### Create keys for multiple users on a server
```bash
# Start with the primary user
kv create
# Select "yes" when asked about additional users
```

### Viewing Keys

Display all managed keys:
```bash
kv view                  # Default table view with numbering
kv view --list           # List format with numbering
kv view --verbose        # Detailed information including IP addresses
kv view --list --verbose # Detailed list view with IP addresses
```

The view command now includes:
- Sequential numbering for each key (#1, #2, etc.)
- IP address display when using the --verbose/-v flag
- Enhanced table format with better organization

### Deleting a Key

Delete a key and its configuration:
```bash
kv delete
```

### Editing Config

Update configuration for an existing key:
```bash
kv edit
```

### Cleaning Known Hosts Entries

When you recreate a server with the same IP or hostname, SSH will show a "man-in-the-middle attack" warning because the host key has changed. Use the clean command to remove old host key entries:

```bash
# Clean by IP address
kv clean --ip 123.45.67.89

# Clean by hostname
kv clean --hostname example.com

# Interactive mode
kv clean
```

The clean command will:
1. Create a backup of your known_hosts file before making changes
2. Remove entries for the specified IP or hostname
3. Optionally clean related entries (hostnames for an IP, or IP for a hostname)
4. Provide guidance on what to expect when connecting to the server next

### Help

Show all available commands and options:
```bash
kv help
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
   kv create
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
   kv create
   ```
   
2. Add the new key to the server
3. Test the new key works
4. Delete the old key:
   ```bash
   kv delete
   ```

### Recreating a Server

When you recreate a server (e.g., rebuilding a droplet, creating a new VM with the same IP):

1. Clean the old host key from known_hosts:
   ```bash
   kv clean --ip YOUR_SERVER_IP
   ```
   
2. Connect to the server using your existing SSH config:
   ```bash
   ssh your-server-alias
   ```
   
3. Verify and accept the new host key when prompted

### Setting Up Multiple Users on the Same Server

You can create keys for multiple users on the same server:

1. Create the first key following the normal process
2. When prompted, choose to add additional users
3. For each additional user, a new key will be generated
4. Add each key to your cloud provider as needed

This creates separate SSH identities for different user accounts on the same server, all properly configured in your SSH config.

## Provider Support

The script provides tailored instructions for:

- **Digital Ocean**: Adding keys to DO dashboard and selecting during droplet creation
- **Linode**: Adding keys to account settings and selecting during Linode creation
- **Google Cloud Platform**: Adding keys to metadata for project-wide use
- **Other Providers**: Generic instructions applicable to most cloud services

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

### Host Key Verification Failed

If you see a warning like "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" when connecting to a server:

1. This happens when a server has been recreated with the same IP address
2. Use the clean command to remove the old host key:
   ```bash
   kv clean --ip YOUR_SERVER_IP
   ```
3. Or remove it manually:
   ```bash
   ssh-keygen -R YOUR_SERVER_IP
   ```
4. The next time you connect, you'll be prompted to accept the new host key

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
- Properly manage known_hosts entries when servers are recreated to avoid bypassing host verification
- Always verify new host key fingerprints when connecting to recreated servers

## Advanced Features

### Multiple Users on Same Server

For servers where you need to connect as different users, create separate keys:

```bash
kv create --env prod --provider do --app librechat --user admin
kv create --env prod --provider do --app librechat --user deploy
```

### Different Key Types

For systems with specific requirements:

```bash
kv create --key-type rsa  # For older systems
kv create --key-type ecdsa  # Alternative to ED25519
```

### Known Hosts Management

The script provides advanced known_hosts management features:

```bash
# Clean entries for both IP and related hostnames
kv clean --ip 192.168.1.100

# Clean entries for a hostname and its IP address
kv clean --hostname server.example.com

# Interactive mode with guided options
kv clean
```

Features include:
- Automatic backup of known_hosts file before changes
- Detection of related entries in SSH config
- Intelligent cleaning of both IP and hostname entries
- Guidance on what to expect when connecting after cleaning

## Additional Resources

- [OpenSSH Documentation](https://www.openssh.com/manual.html)
- [SSH Key Management Best Practices](https://www.ssh.com/academy/ssh/keygen)
- [SSH Agent Forwarding Explained](https://www.ssh.com/academy/ssh/agent)