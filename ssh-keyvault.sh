#!/bin/bash
#
# ssh-keyvault.sh - KeyVault SSH Management Script
#
# This script manages SSH keys for cloud server deployments following a structured
# naming convention and directory organization. It supports creating, deleting,
# and managing SSH keys and configurations, as well as handling known_hosts entries.
#
# Previously known as ssh-keyman
#
# Author: Your Name
# Version: 1.2.1
# Created: February 2025
#
# Usage:
#   ./ssh-keyvault.sh [COMMAND] [OPTIONS]
#
# Commands:
#   create      Create a new SSH key
#   delete      Delete an existing SSH key
#   view        View all managed SSH keys
#   edit        Edit SSH config for a key
#   clean       Clean known_hosts entries for a host
#   help        Show this help message
#
# Options:
#   --env ENV             Specify environment (dev/prod)
#   --provider PROVIDER   Specify cloud provider (do/li/gcp)
#   --app APP             Specify application name
#   --user USER           Specify username on remote server
#   --ip IP               Specify IP address of remote server
#   --key-type TYPE       Specify key type (ed25519/rsa/ecdsa)
#   --hostname HOSTNAME   Specify hostname for known_hosts operations
#   --table, -t           Display keys in table format (default)
#   --list, -l            Display keys in list format
#   --verbose, -v         Show verbose information
#
# Examples:
#   ./ssh-keyvault.sh create
#   ./ssh-keyvault.sh create --env dev --provider do --app librechat --user sudu
#   ./ssh-keyvault.sh delete
#   ./ssh-keyvault.sh view
#   ./ssh-keyvault.sh view --table
#   ./ssh-keyvault.sh view --list --verbose
#   ./ssh-keyvault.sh edit
#   ./ssh-keyvault.sh clean --ip 192.168.1.100
#   ./ssh-keyvault.sh clean --hostname example.com

set -e

# Script version
VERSION="1.2.1"

# Default values
COMMAND=""
ENV=""
PROVIDER=""
APP=""
USER=""
IP=""
HOSTNAME=""
KEY_TYPE="ed25519"
INTERACTIVE=true
VIEW_MODE="table"  # Default view mode: table or list
VERBOSE=false     # Default verbosity level: false (concise) or true (verbose)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Provider options
PROVIDERS=("do:Digital Ocean" "li:Linode" "gcp:Google Cloud Platform" "other:Other Provider")

# Function to display help
show_help() {
  echo -e "${BLUE}${BOLD}KeyVault SSH Management Script v${VERSION}${NC}"
  echo
  echo "This script manages SSH keys for cloud server deployments following a structured"
  echo "naming convention and directory organization."
  echo
  echo -e "${YELLOW}${BOLD}Usage:${NC}"
  echo "  ./ssh-keyvault.sh [COMMAND] [OPTIONS]"
  echo
  echo -e "${YELLOW}${BOLD}Commands:${NC}"
  echo "  create      Create a new SSH key"
  echo "  delete      Delete an existing SSH key"
  echo "  view        View all managed SSH keys"
  echo "  edit        Edit SSH config for a key"
  echo "  clean       Clean known_hosts entries for a host"
  echo "  help        Show this help message"
  echo
  echo -e "${YELLOW}${BOLD}Options:${NC}"
  echo "  --env ENV             Specify environment (dev/prod)"
  echo "  --provider PROVIDER   Specify cloud provider (do/li/gcp)"
  echo "  --app APP             Specify application name"
  echo "  --user USER           Specify username on remote server"
  echo "  --ip IP               Specify IP address of remote server"
  echo "  --hostname HOSTNAME   Specify hostname for known_hosts operations"
  echo "  --key-type TYPE       Specify key type (ed25519/rsa/ecdsa)"
  echo "  --table, -t           Display keys in table format (default)"
  echo "  --list, -l            Display keys in list format"
  echo "  --verbose, -v         Show verbose information"
  echo
  echo -e "${YELLOW}${BOLD}Examples:${NC}"
  echo "  ./ssh-keyvault.sh create"
  echo "  ./ssh-keyvault.sh create --env dev --provider do --app librechat --user sudu"
  echo "  ./ssh-keyvault.sh delete"
  echo "  ./ssh-keyvault.sh view"
  echo "  ./ssh-keyvault.sh clean --ip 192.168.1.100"
  echo "  ./ssh-keyvault.sh clean --hostname example.com"
  echo
}

# Function to log a message with timestamp
log_message() {
  local level="$1"
  local message="$2"
  local color=""
  
  case "$level" in
    "ERROR") color="$RED" ;;
    "WARNING") color="$YELLOW" ;;
    "INFO") color="$BLUE" ;;
    "SUCCESS") color="$GREEN" ;;
    *) color="$NC" ;;
  esac
  
  echo -e "${color}[$level] $message${NC}"
}

# Function to check prerequisites
check_prerequisites() {
  log_message "INFO" "Checking prerequisites..."
  
  # Check if ssh-keygen is installed
  if ! command -v ssh-keygen &> /dev/null; then
    log_message "ERROR" "ssh-keygen is not installed. Please install OpenSSH utilities."
    exit 1
  fi
  
  # Check if ssh-agent is available
  if ! command -v ssh-agent &> /dev/null; then
    log_message "WARNING" "ssh-agent not found. Agent functionality will be limited."
  fi
  
  log_message "SUCCESS" "Prerequisites check passed."
}

# Function to create directory structure
create_directory_structure() {
  log_message "INFO" "Creating directory structure..."
  
  # Create main SSH directory if it doesn't exist
  if [ ! -d "$HOME/.ssh" ]; then
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    log_message "INFO" "Created ~/.ssh directory"
  fi
  
  # Create keys directory if it doesn't exist
  if [ ! -d "$HOME/.ssh/keys" ]; then
    mkdir -p "$HOME/.ssh/keys"
    chmod 700 "$HOME/.ssh/keys"
    log_message "INFO" "Created ~/.ssh/keys directory"
  fi
  
  # Create environment-specific directories
  if [ ! -d "$HOME/.ssh/keys/dev" ]; then
    mkdir -p "$HOME/.ssh/keys/dev"
    chmod 700 "$HOME/.ssh/keys/dev"
    log_message "INFO" "Created ~/.ssh/keys/dev directory"
  fi
  
  if [ ! -d "$HOME/.ssh/keys/prod" ]; then
    mkdir -p "$HOME/.ssh/keys/prod"
    chmod 700 "$HOME/.ssh/keys/prod"
    log_message "INFO" "Created ~/.ssh/keys/prod directory"
  fi
  
  log_message "SUCCESS" "Directory structure created successfully."
}

# Function to validate environment
validate_environment() {
  if [[ ! "$ENV" =~ ^(dev|prod)$ ]]; then
    log_message "ERROR" "Environment must be 'dev' or 'prod'."
    return 1
  fi
  return 0
}

# Function to validate provider
validate_provider() {
  if [[ -z "$PROVIDER" ]]; then
    log_message "ERROR" "Provider cannot be empty."
    return 1
  fi
  return 0
}

# Function to validate app name
validate_app() {
  if [[ -z "$APP" ]]; then
    log_message "ERROR" "Application name cannot be empty."
    return 1
  fi
  return 0
}

# Function to validate username
validate_user() {
  if [[ -z "$USER" ]]; then
    log_message "ERROR" "Username cannot be empty."
    return 1
  fi
  return 0
}

# Function to validate key type
validate_key_type() {
  if [[ ! "$KEY_TYPE" =~ ^(ed25519|rsa|ecdsa)$ ]]; then
    log_message "ERROR" "Key type must be 'ed25519', 'rsa', or 'ecdsa'."
    return 1
  fi
  return 0
}

# Function to generate SSH key
generate_ssh_key() {
  local key_path="$HOME/.ssh/keys/$ENV/$PROVIDER-$APP-$USER"
  local key_comment="$PROVIDER-$APP-$USER-$ENV"
  
  log_message "INFO" "Generating SSH key..."
  
  # Check if key already exists
  if [ -f "$key_path" ]; then
    log_message "WARNING" "SSH key already exists at $key_path"
    read -p "Do you want to overwrite it? [y/N] " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
      log_message "WARNING" "Key generation aborted."
      return 0
    fi
  fi
  
  # Generate key based on type
  case "$KEY_TYPE" in
    ed25519)
      ssh-keygen -t ed25519 -C "$key_comment" -f "$key_path" -N ""
      ;;
    rsa)
      ssh-keygen -t rsa -b 4096 -C "$key_comment" -f "$key_path" -N ""
      ;;
    ecdsa)
      ssh-keygen -t ecdsa -b 521 -C "$key_comment" -f "$key_path" -N ""
      ;;
  esac
  
  # Set correct permissions
  chmod 600 "$key_path"
  chmod 644 "$key_path.pub"
  
  log_message "SUCCESS" "SSH key generated successfully:"
  echo -e "Private key: ${CYAN}$key_path${NC}"
  echo -e "Public key: ${CYAN}$key_path.pub${NC}"
  
  # Show public key content
  echo -e "${YELLOW}Public key content:${NC}"
  cat "$key_path.pub"
  echo
  
  return 0
}

# Function to update SSH config
update_ssh_config() {
  local key_path="$HOME/.ssh/keys/$ENV/$PROVIDER-$APP-$USER"
  local host_name="$PROVIDER-$APP-$USER-$ENV"
  local config_path="$HOME/.ssh/config"
  
  log_message "INFO" "Updating SSH config..."
  
  # Create SSH config file if it doesn't exist
  if [ ! -f "$config_path" ]; then
    touch "$config_path"
    chmod 600 "$config_path"
  fi
  
  # Check if host entry already exists
  if grep -q "^Host $host_name$" "$config_path"; then
    log_message "WARNING" "Host entry already exists in SSH config."
    read -p "Do you want to update it? [y/N] " update
    if [[ ! "$update" =~ ^[Yy]$ ]]; then
      log_message "WARNING" "SSH config update aborted."
      return 0
    fi
    
    # Remove existing host entry
    sed -i.bak "/^Host $host_name$/,/^$/d" "$config_path"
  fi
  
  # Add new host entry
  cat >> "$config_path" << EOF

Host $host_name
    HostName ${IP:-YOUR_SERVER_IP}
    User $USER
    IdentityFile $key_path
    ForwardAgent yes
EOF
  
  log_message "SUCCESS" "SSH config updated successfully."
  return 0
}

# Function to manage SSH agent
manage_ssh_agent() {
  local key_path="$HOME/.ssh/keys/$ENV/$PROVIDER-$APP-$USER"
  
  log_message "INFO" "Setting up SSH agent..."
  
  # Check if ssh-agent is running
  if [ -z "$SSH_AUTH_SOCK" ]; then
    log_message "WARNING" "SSH agent is not running. Starting it..."
    eval "$(ssh-agent -s)"
  fi
  
  # Add key to agent
  ssh-add "$key_path"
  
  log_message "SUCCESS" "SSH key added to agent."
  
  # Provide command for shell startup
  echo -e "${YELLOW}To automatically add this key to SSH agent at login, add these lines to your shell startup file:${NC}"
  echo -e "${CYAN}eval \"\$(ssh-agent -s)\"${NC}"
  echo -e "${CYAN}ssh-add $key_path${NC}"
  
  return 0
}

# Function to provide next steps
show_next_steps() {
  local key_path="$HOME/.ssh/keys/$ENV/$PROVIDER-$APP-$USER"
  local host_name="$PROVIDER-$APP-$USER-$ENV"
  
  echo -e "${BLUE}${BOLD}Next steps:${NC}"
  echo -e "1. Test the connection:"
  if [ -n "$IP" ]; then
    echo -e "   ${CYAN}ssh $host_name${NC}"
  else
    echo -e "   ${CYAN}ssh -i $key_path $USER@YOUR_SERVER_IP${NC}"
    echo -e "   or, after setting the IP in your SSH config:"
    echo -e "   ${CYAN}ssh $host_name${NC}"
  fi
  echo
  echo -e "2. Create an alias in your shell profile (~/.bashrc, ~/.zshrc, etc.):"
  echo -e "   ${CYAN}alias goto-$APP-$ENV=\"ssh $host_name\"${NC}"
  echo
}

# Function to manage known_hosts entries
# This function handles cleaning and managing SSH known_hosts entries
# to prevent "man-in-the-middle attack" warnings when servers are recreated
manage_known_hosts() {
  log_message "INFO" "Managing SSH known_hosts entries..."
  
  local known_hosts_file="$HOME/.ssh/known_hosts"
  local backup_file="$HOME/.ssh/known_hosts.backup.$(date +%Y%m%d%H%M%S)"
  local cleaned=false
  local target_type=""
  local target_value=""
  
  # Check if known_hosts file exists
  if [ ! -f "$known_hosts_file" ]; then
    log_message "INFO" "No known_hosts file found at $known_hosts_file"
    return 0
  fi
  
  # Create backup of known_hosts file
  cp "$known_hosts_file" "$backup_file"
  log_message "INFO" "Created backup of known_hosts file at $backup_file"
  
  # Determine if we're working with IP or hostname
  if [ -n "$IP" ]; then
    target_type="IP"
    target_value="$IP"
  elif [ -n "$HOSTNAME" ]; then
    target_type="hostname"
    target_value="$HOSTNAME"
  else
    # Interactive mode - ask for IP or hostname
    echo -e "${YELLOW}Select target type:${NC}"
    select target_option in "IP Address" "Hostname"; do
      case $target_option in
        "IP Address")
          target_type="IP"
          
          # Extract all IPs from known_hosts file
          local ips=($(grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' "$known_hosts_file" | sort -u))
          
          if [ ${#ips[@]} -eq 0 ]; then
            log_message "INFO" "No IP addresses found in known_hosts file."
            read -p "Enter IP address to clean from known_hosts: " target_value
          else
            echo -e "${YELLOW}Select IP address to clean:${NC}"
            select ip in "${ips[@]}" "Enter manually"; do
              if [ "$ip" = "Enter manually" ]; then
                read -p "Enter IP address to clean from known_hosts: " target_value
              else
                target_value="$ip"
              fi
              break
            done
          fi
          break
          ;;
        "Hostname")
          target_type="hostname"
          
          # Extract all hostnames from known_hosts file
          # This extracts entries before the first comma or space
          local hostnames=($(cut -d ' ' -f1 "$known_hosts_file" | cut -d ',' -f1 | grep -v '^[0-9]' | sort -u))
          
          if [ ${#hostnames[@]} -eq 0 ]; then
            log_message "INFO" "No hostnames found in known_hosts file."
            read -p "Enter hostname to clean from known_hosts: " target_value
          else
            echo -e "${YELLOW}Select hostname to clean:${NC}"
            select hostname in "${hostnames[@]}" "Enter manually"; do
              if [ "$hostname" = "Enter manually" ]; then
                read -p "Enter hostname to clean from known_hosts: " target_value
              else
                target_value="$hostname"
              fi
              break
            done
          fi
          break
          ;;
        *)
          log_message "ERROR" "Invalid selection. Please try again."
          ;;
      esac
    done
  fi
  
  # Validate target value
  if [ -z "$target_value" ]; then
    log_message "ERROR" "No $target_type specified. Cannot proceed."
    return 1
  fi
  
  log_message "INFO" "Cleaning $target_type: $target_value from known_hosts file..."
  
  # Check if the entry exists before attempting to remove it
  if grep -q "$target_value" "$known_hosts_file"; then
    # Use ssh-keygen to remove the entry
    if ssh-keygen -R "$target_value" > /dev/null 2>&1; then
      log_message "SUCCESS" "Removed $target_type: $target_value from known_hosts file."
      cleaned=true
    else
      log_message "ERROR" "Failed to remove $target_type: $target_value from known_hosts file."
      log_message "INFO" "Restoring backup from $backup_file"
      cp "$backup_file" "$known_hosts_file"
      return 1
    fi
  else
    log_message "INFO" "No entries found for $target_type: $target_value in known_hosts file."
  fi
  
  # Check if we're cleaning for a host in our SSH config
  if [ "$target_type" = "IP" ]; then
    # Look for hosts in SSH config that use this IP
    if [ -f "$HOME/.ssh/config" ]; then
      local matching_hosts=$(grep -B1 "HostName $target_value" "$HOME/.ssh/config" | grep "^Host " | awk '{print $2}')
      
      if [ -n "$matching_hosts" ]; then
        echo -e "${YELLOW}Found hosts in SSH config using this IP:${NC}"
        echo "$matching_hosts"
        
        read -p "Do you want to clean known_hosts entries for these hostnames too? [y/N] " clean_hostnames
        if [[ "$clean_hostnames" =~ ^[Yy]$ ]]; then
          for host in $matching_hosts; do
            if ssh-keygen -R "$host" > /dev/null 2>&1; then
              log_message "SUCCESS" "Removed hostname: $host from known_hosts file."
              cleaned=true
            else
              log_message "WARNING" "Failed to remove hostname: $host from known_hosts file."
            fi
          done
        fi
      fi
    fi
  fi
  
  # If we're cleaning a hostname that's in our SSH config, also clean its IP
  if [ "$target_type" = "hostname" ] && [ -f "$HOME/.ssh/config" ]; then
    local host_ip=$(grep -A2 "^Host $target_value$" "$HOME/.ssh/config" | grep "HostName" | awk '{print $2}')
    
    if [ -n "$host_ip" ] && [[ "$host_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo -e "${YELLOW}Found IP address $host_ip for hostname $target_value in SSH config.${NC}"
      
      read -p "Do you want to clean known_hosts entry for this IP too? [y/N] " clean_ip
      if [[ "$clean_ip" =~ ^[Yy]$ ]]; then
        if ssh-keygen -R "$host_ip" > /dev/null 2>&1; then
          log_message "SUCCESS" "Removed IP: $host_ip from known_hosts file."
          cleaned=true
        else
          log_message "WARNING" "Failed to remove IP: $host_ip from known_hosts file."
        fi
      fi
    fi
  fi
  
  # If nothing was cleaned, we can remove the backup
  if [ "$cleaned" = false ]; then
    log_message "INFO" "No changes were made to known_hosts file."
    rm -f "$backup_file"
    log_message "INFO" "Removed unnecessary backup file."
  else
    log_message "SUCCESS" "Successfully cleaned known_hosts entries."
    echo -e "${GREEN}A backup of your original known_hosts file was created at:${NC}"
    echo -e "${CYAN}$backup_file${NC}"
  fi
  
  # Provide information about what happens next
  echo -e "\n${BLUE}${BOLD}What happens next:${NC}"
  echo -e "1. The next time you connect to this server, SSH will ask you to verify and accept the new host key."
  echo -e "2. This is normal when a server has been recreated or reinstalled."
  echo -e "3. Verify the fingerprint carefully before accepting to ensure security."
  
  return 0
}

# Function to show provider-specific key setup instructions
show_key_instructions() {
  echo -e "\n${YELLOW}${BOLD}IMPORTANT: Copy the above public key to your cloud provider${NC}"
  echo -e "${BLUE}Based on your selection (${PROVIDER}), here's what to do:${NC}"

  # Provider-specific instructions
  case "$PROVIDER" in
    "do")
      echo -e "1. Go to Digital Ocean dashboard > Settings > Security > SSH Keys > Add SSH Key"
      echo -e "2. Paste the key and give it a name like: $APP-$USER-$ENV"
      echo -e "3. When creating your droplet, select this key in the Authentication section"
      ;;
    "li")
      echo -e "1. Go to Linode dashboard > Account > SSH Keys > Add a Key"
      echo -e "2. Paste the key and give it a label like: $APP-$USER-$ENV"
      echo -e "3. When creating your Linode, select this key under 'Add SSH Keys'"
      ;;
    "gcp")
      echo -e "1. Go to GCP Console > Compute Engine > Settings > Metadata > SSH Keys"
      echo -e "2. Click Add Item and paste your key"
      ;;
    *)
      echo -e "Please add this public key to your cloud provider's SSH key section"
      ;;
  esac
}

# Function to list all managed SSH keys - completely rewritten
list_ssh_keys() {
  log_message "INFO" "Listing managed SSH keys..."
  
  # Data structures to store key info
  declare -a all_keys
  declare -a key_names
  declare -a key_types
  declare -a key_environments
  declare -a key_host_entries
  declare -a key_ip_addresses
  declare -a key_in_known_hosts
  
  # Total key count
  local key_count=0
  
  # Helper function to get key type
  get_key_type() {
    local pub_key="$1"
    if [ -f "$pub_key" ]; then
      head -1 "$pub_key" | awk '{print $1}' | cut -d- -f2
    else
      echo "unknown"
    fi
  }
  
  # Helper function to check if host in known_hosts
  in_known_hosts() {
    local host="$1"
    if [ -n "$host" ] && grep -q "$host" "$HOME/.ssh/known_hosts" 2>/dev/null; then
      echo "Yes"
    else
      echo "No"
    fi
  }
  
  # Helper function to get host entry from SSH config
  get_host_entry() {
    local key_path="$1"
    if [ -f "$HOME/.ssh/config" ]; then
      grep -B3 -A1 "IdentityFile.*$key_path" "$HOME/.ssh/config" | grep "^Host " | head -1 | awk '{print $2}'
    fi
  }
  
  # Helper function to get IP address for a host entry
  get_ip_address() {
    local host_entry="$1"
    if [ -n "$host_entry" ] && [ -f "$HOME/.ssh/config" ]; then
      local ip=$(grep -A2 "^Host $host_entry" "$HOME/.ssh/config" | grep "HostName" | awk '{print $2}')
      echo "${ip:-Not set}"
    else
      echo "Not set"
    fi
  }
  
  # First collect all keys from both environments
  for env in "dev" "prod"; do
    log_message "INFO" "Collecting keys from $env environment"
    
    # Check if directory exists
    if [ ! -d "$HOME/.ssh/keys/$env" ]; then
      log_message "INFO" "Directory $HOME/.ssh/keys/$env does not exist"
      continue
    fi
    
    # List directory contents (for debugging)
    log_message "INFO" "Contents of $HOME/.ssh/keys/$env:"
    ls -la "$HOME/.ssh/keys/$env"
    
    # Fix directory permissions
    chmod 755 "$HOME/.ssh/keys/$env" 2>/dev/null
    
    # Get all private keys (non-.pub files)
    for key_path in "$HOME/.ssh/keys/$env"/*; do
      if [[ -f "$key_path" && ! "$key_path" == *.pub ]]; then
        # Fix permissions
        chmod 600 "$key_path" 2>/dev/null
        if [[ -f "$key_path.pub" ]]; then
          chmod 644 "$key_path.pub" 2>/dev/null
        fi
        
        # Get key details
        local name=$(basename "$key_path")
        local type=$(get_key_type "$key_path.pub")
        local host_entry=$(get_host_entry "$key_path")
        local ip_address=$(get_ip_address "$host_entry")
        local known=$(in_known_hosts "$host_entry")
        
        # Store details in arrays
        all_keys[$key_count]="$key_path"
        key_names[$key_count]="$name"
        key_types[$key_count]="$type"
        key_environments[$key_count]="$env"
        key_host_entries[$key_count]="$host_entry"
        key_ip_addresses[$key_count]="$ip_address"
        key_in_known_hosts[$key_count]="$known"
        
        key_count=$((key_count + 1))
        log_message "INFO" "Found key: $name in $env environment"
      fi
    done
  done
  
  # If no keys found, display message and return
  if [ $key_count -eq 0 ]; then
    echo -e "${YELLOW}No SSH keys found.${NC}"
    log_message "INFO" "No SSH keys found"
    return 0
  fi
  
  log_message "INFO" "Found $key_count keys total"
  
  # Display keys for each environment
  for env in "dev" "prod"; do
    local env_display="Development (dev)"
    if [ "$env" = "prod" ]; then
      env_display="Production (prod)"
    fi
    
    local env_count=0
    for i in $(seq 0 $((key_count - 1))); do
      if [ "${key_environments[$i]}" = "$env" ]; then
        env_count=$((env_count + 1))
      fi
    done
    
    # Skip environment if no keys found
    if [ $env_count -eq 0 ]; then
      log_message "INFO" "No keys found in $env environment"
      continue
    fi
    
    # Display environment header
    if [ "$VIEW_MODE" = "list" ]; then
      echo -e "${BOLD}${CYAN}$env_display Environment Keys:${NC}"
      echo "-------------------------------------"
    else
      echo -e "${BOLD}${CYAN}$env_display:${NC}"
    fi
    
    # Display table header if in table mode
    if [ "$VIEW_MODE" = "table" ]; then
      if [ "$VERBOSE" = true ]; then
        printf "%-5s | %-30s | %-15s | %-12s | %-15s | %-15s\n" "#" "Key Name" "Type" "In Known Hosts" "Host Entry" "IP Address"
        printf "%-5s-+-%-30s-+-%-15s-+-%-12s-+-%-15s-+-%-15s\n" "-----" "------------------------------" "---------------" "------------" "---------------" "---------------"
      else
        printf "%-5s | %-30s | %-15s | %-12s\n" "#" "Key Name" "Type" "In Known Hosts"
        printf "%-5s-+-%-30s-+-%-15s-+-%-12s\n" "-----" "------------------------------" "---------------" "------------"
      fi
    fi
    
    # Display keys for current environment using global numbering
    local global_num=${global_num:-0} # Initialize if not set
    for i in $(seq 0 $((key_count - 1))); do
      if [ "${key_environments[$i]}" = "$env" ]; then
        global_num=$((global_num + 1))
        
        # Display in appropriate format
        if [ "$VIEW_MODE" = "table" ]; then
          if [ "$VERBOSE" = true ]; then
            printf "%-5s | %-30s | %-15s | %-12s | %-15s | %-15s\n" "$global_num" "${key_names[$i]}" "${key_types[$i]}" "${key_in_known_hosts[$i]}" "${key_host_entries[$i]:-Not configured}" "${key_ip_addresses[$i]}"
          else
            printf "%-5s | %-30s | %-15s | %-12s\n" "$global_num" "${key_names[$i]}" "${key_types[$i]}" "${key_in_known_hosts[$i]}"
          fi
        else
          # List view
          echo -e "${BOLD}#$global_num ${key_names[$i]}${NC}"
          if [ "$VERBOSE" = true ]; then
            echo -e "  Private Key: ${all_keys[$i]}"
            echo -e "  Public Key: ${all_keys[$i]}.pub"
            echo -e "  Key Type: ${key_types[$i]}"
            if [ -n "${key_host_entries[$i]}" ]; then
              echo -e "  Host Entry: ${key_host_entries[$i]}"
              echo -e "  IP Address: ${key_ip_addresses[$i]}"
            else
              echo -e "  Host Entry: ${YELLOW}Not configured${NC}"
            fi
            echo -e "  In Known Hosts: ${key_in_known_hosts[$i]}"
          else
            if [ -n "${key_host_entries[$i]}" ]; then
              echo -e "  Host Entry: ${key_host_entries[$i]}"
            else
              echo -e "  Host Entry: ${YELLOW}Not configured${NC}"
            fi
          fi
          echo
        fi
      fi
    done
    
    # Add spacing after tables
    if [ "$VIEW_MODE" = "table" ]; then
      echo
    fi
  done
  
  log_message "SUCCESS" "Listing completed."
  return 0
}

# Function to delete SSH key and related config
delete_ssh_key() {
  log_message "INFO" "Deleting SSH key..."
  
  # Get list of all keys
  local keys=()
  local keys_paths=()
  
  # Add dev keys
  if [ -d "$HOME/.ssh/keys/dev" ]; then
    for key in "$HOME/.ssh/keys/dev"/*; do
      if [ -f "$key" ] && [[ ! "$key" == *.pub ]]; then
        local basename=$(basename "$key")
        keys+=("dev:$basename")
        keys_paths+=("$key")
      fi
    done
  fi
  
  # Add prod keys
  if [ -d "$HOME/.ssh/keys/prod" ]; then
    for key in "$HOME/.ssh/keys/prod"/*; do
      if [ -f "$key" ] && [[ ! "$key" == *.pub ]]; then
        local basename=$(basename "$key")
        keys+=("prod:$basename")
        keys_paths+=("$key")
      fi
    done
  fi
  
  # Check if any keys exist
  if [ ${#keys[@]} -eq 0 ]; then
    log_message "ERROR" "No SSH keys found to delete."
    return 1
  fi
  
  # Display keys for selection
  echo -e "${YELLOW}Select SSH key to delete:${NC}"
  for i in "${!keys[@]}"; do
    local idx=$((i+1))
    local parts=(${keys[$i]//:/ })
    echo -e "$idx) ${parts[0]} - ${parts[1]}"
  done
  
  read -p "Enter selection (1-${#keys[@]}): " selection
  
  # Validate selection
  if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#keys[@]} ]; then
    log_message "ERROR" "Invalid selection."
    return 1
  fi
  
  # Get selected key
  local key_info=${keys[$((selection-1))]}
  local key_path=${keys_paths[$((selection-1))]}
  local parts=(${key_info//:/ })
  local env=${parts[0]}
  local basename=${parts[1]}
  
  # Confirm deletion
  echo -e "${RED}Warning: This will delete the SSH key and remove its entry from SSH config.${NC}"
  read -p "Are you sure you want to delete $env - $basename? [y/N] " confirm
  
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    log_message "WARNING" "Deletion aborted."
    return 0
  fi
  
  # Remove from SSH agent
  ssh-add -d "$key_path" 2>/dev/null || true
  
  # Remove from SSH config
  local host_entry=$(grep -l "IdentityFile.*$key_path" "$HOME/.ssh/config" | xargs grep "^Host" 2>/dev/null | awk '{print $2}')
  if [ -n "$host_entry" ]; then
    sed -i.bak "/^Host $host_entry$/,/^$/d" "$HOME/.ssh/config"
    log_message "INFO" "Removed host entry $host_entry from SSH config."
  fi
  
  # Delete key files
  rm -f "$key_path"
  rm -f "$key_path.pub"
  
  log_message "SUCCESS" "Deleted SSH key $basename ($env)."
  return 0
}

# Function to edit SSH config for an existing key
edit_ssh_config() {
  log_message "INFO" "Editing SSH config..."
  
  # Get list of all keys
  local keys=()
  local keys_paths=()
  
  # Add dev keys
  if [ -d "$HOME/.ssh/keys/dev" ]; then
    for key in "$HOME/.ssh/keys/dev"/*; do
      if [ -f "$key" ] && [[ ! "$key" == *.pub ]]; then
        local basename=$(basename "$key")
        keys+=("dev:$basename")
        keys_paths+=("$key")
      fi
    done
  fi
  
  # Add prod keys
  if [ -d "$HOME/.ssh/keys/prod" ]; then
    for key in "$HOME/.ssh/keys/prod"/*; do
      if [ -f "$key" ] && [[ ! "$key" == *.pub ]]; then
        local basename=$(basename "$key")
        keys+=("prod:$basename")
        keys_paths+=("$key")
      fi
    done
  fi
  
  # Check if any keys exist
  if [ ${#keys[@]} -eq 0 ]; then
    log_message "ERROR" "No SSH keys found to edit."
    return 1
  fi
  
  # Display keys for selection
  echo -e "${YELLOW}Select SSH key to edit config for:${NC}"
  for i in "${!keys[@]}"; do
    local idx=$((i+1))
    local parts=(${keys[$i]//:/ })
    echo -e "$idx) ${parts[0]} - ${parts[1]}"
  done
  
  read -p "Enter selection (1-${#keys[@]}): " selection
  
  # Validate selection
  if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#keys[@]} ]; then
    log_message "ERROR" "Invalid selection."
    return 1
  fi
  
  # Get selected key
  local key_info=${keys[$((selection-1))]}
  local key_path=${keys_paths[$((selection-1))]}
  local parts=(${key_info//:/ })
  local env=${parts[0]}
  local basename=${parts[1]}
  
  # Parse key name to get components
  IFS='-' read -ra COMPONENTS <<< "$basename"
  PROVIDER=${COMPONENTS[0]}
  APP=${COMPONENTS[1]}
  USER=${COMPONENTS[2]}
  ENV=$env
  
  # Check if there's an existing host entry
  local host_name="$PROVIDER-$APP-$USER-$ENV"
  local existing_ip=""
  
  if grep -q "^Host $host_name$" "$HOME/.ssh/config"; then
    existing_ip=$(grep -A1 "^Host $host_name$" "$HOME/.ssh/config" | grep "HostName" | awk '{print $2}')
    log_message "INFO" "Found existing host entry with IP: $existing_ip"
  fi
  
  # Get new IP
  read -p "Enter new IP address for $host_name [${existing_ip:-Enter new IP}]: " new_ip
  IP=${new_ip:-$existing_ip}
  
  # Update SSH config
  update_ssh_config
  
  log_message "SUCCESS" "SSH config updated for $basename ($env)."
  return 0
}

# Function to create new SSH key with modified workflow and multi-user support
create_new_key() {
  # Get environment
  if [ -z "$ENV" ]; then
    echo -e "${YELLOW}Select environment:${NC}"
    select env_option in "Development (dev)" "Production (prod)"; do
      case $env_option in
        "Development (dev)")
          ENV="dev"
          break
          ;;
        "Production (prod)")
          ENV="prod"
          break
          ;;
        *)
          log_message "ERROR" "Invalid selection. Please try again."
          ;;
      esac
    done
  fi
  
  # Get provider
  if [ -z "$PROVIDER" ]; then
    echo -e "${YELLOW}Select cloud provider:${NC}"
    select provider_option in "${PROVIDERS[@]}"; do
      local value=${provider_option%%:*}
      if [ -n "$value" ]; then
        PROVIDER="$value"
        break
      else
        log_message "ERROR" "Invalid selection. Please try again."
      fi
    done
    
    if [ "$PROVIDER" = "other" ]; then
      read -p "Enter provider shortcode (e.g., aws): " custom_provider
      PROVIDER="$custom_provider"
    fi
  fi
  
  # Get application name
  if [ -z "$APP" ]; then
    read -p "Enter application name (e.g., librechat): " APP
  fi
  
  # Get username
  if [ -z "$USER" ]; then
    read -p "Enter username on remote server: " USER
  fi
  
  # Validate required inputs
  validate_environment || return 1
  validate_provider || return 1
  validate_app || return 1
  validate_user || return 1
  validate_key_type || return 1
  
  # Generate SSH key
  generate_ssh_key
  
  # Show provider-specific instructions
  show_key_instructions
  
  # Wait for user to confirm they've added the key
  read -p "Have you added the key to your cloud provider? [y/N] " key_added
  if [[ ! "$key_added" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}You can complete this process later using the 'edit' command.${NC}"
    # Save the key information for later
    echo "$PROVIDER-$APP-$USER-$ENV" > "$HOME/.ssh/.last_key_created"
    return 0
  fi
  
  # Now prompt for the IP address
  read -p "Enter the server IP address provided by your cloud provider: " IP
  
  # Update SSH config with this IP
  update_ssh_config
  
  # Add key to SSH agent
  manage_ssh_agent
  
  # Show next steps
  show_next_steps
  
  # Support for multiple users
  read -p "Do you want to create keys for additional users on this same server? [y/N] " add_more_users
  if [[ "$add_more_users" =~ ^[Yy]$ ]]; then
    local original_user="$USER"
    local continue_adding="yes"
    
    while [[ "$continue_adding" =~ ^[Yy] ]]; do
      read -p "Enter additional username: " USER
      if [[ -n "$USER" ]]; then
        # Generate key for additional user with same server details
        generate_ssh_key
        show_key_instructions
        
        read -p "Have you added this user's key to your cloud provider? [y/N] " user_key_added
        if [[ "$user_key_added" =~ ^[Yy]$ ]]; then
          update_ssh_config
          manage_ssh_agent
        else
          log_message "WARNING" "Skipping config for this user. You can edit it later."
        fi
      fi
      read -p "Add another user? [y/N] " continue_adding
    done
    
    # Restore original user
    USER="$original_user"
  fi
  
  return 0
}

# Main function
main() {
  # Display banner
  echo -e "${BLUE}${BOLD}===========================================================${NC}"
  echo -e "${BLUE}${BOLD}           KeyVault SSH Management Script v${VERSION}            ${NC}"
  echo -e "${BLUE}${BOLD}===========================================================${NC}"
  echo
  
  # Check prerequisites
  check_prerequisites
  
  # Create directory structure
  create_directory_structure
  
  # Process command
  case "$COMMAND" in
    "create")
      create_new_key
      ;;
    "delete")
      delete_ssh_key
      ;;
    "view"|"list")  # Support both "view" and "list" for backward compatibility
      list_ssh_keys
      ;;
    "edit")
      edit_ssh_config
      ;;
    "clean")
      manage_known_hosts
      ;;
    "help")
      show_help
      ;;
    "")
      # No command specified, show interactive menu
      echo -e "${YELLOW}Select operation:${NC}"
      select op in "Create new SSH key" "Delete SSH key" "View SSH keys" "Edit SSH config" "Clean known_hosts entries" "Exit"; do
        case $op in
          "Create new SSH key")
            create_new_key
            break
            ;;
          "Delete SSH key")
            delete_ssh_key
            break
            ;;
          "View SSH keys")
            list_ssh_keys
            break
            ;;
          "Edit SSH config")
            edit_ssh_config
            break
            ;;
          "Clean known_hosts entries")
            manage_known_hosts
            break
            ;;
          "Exit")
            log_message "INFO" "Exiting..."
            exit 0
            ;;
          *)
            log_message "ERROR" "Invalid selection. Please try again."
            ;;
        esac
      done
      ;;
    *)
      log_message "ERROR" "Unknown command: $COMMAND"
      show_help
      exit 1
      ;;
  esac
  
  log_message "SUCCESS" "Operation completed successfully!"
  exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    create|delete|view|list|edit|clean|help)
      COMMAND="$1"
      shift
      ;;
    --env)
      ENV="$2"
      shift 2
      ;;
    --provider)
      PROVIDER="$2"
      shift 2
      ;;
    --app)
      APP="$2"
      shift 2
      ;;
    --user)
      USER="$2"
      shift 2
      ;;
    --ip)
      IP="$2"
      shift 2
      ;;
    --hostname)
      HOSTNAME="$2"
      shift 2
      ;;
    --key-type)
      KEY_TYPE="$2"
      shift 2
      ;;
    --table|-t)
      VIEW_MODE="table"
      shift
      ;;
    --list|-l)
      VIEW_MODE="list"
      shift
      ;;
    --verbose|-v)
      VERBOSE=true
      shift
      ;;
    --help)
      COMMAND="help"
      shift
      ;;
    *)
      log_message "ERROR" "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

# Run main function
main
