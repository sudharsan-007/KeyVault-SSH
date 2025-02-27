#!/bin/bash
#
# ssh-keyman.sh - SSH Key Management Script
#
# This script manages SSH keys for cloud server deployments following a structured 
# naming convention and directory organization. It supports creating, deleting,
# and managing SSH keys and configurations.
#
# Author: Your Name
# Version: 1.0.0
# Created: February 2025
#
# Usage:
#   ./ssh-keyman.sh [COMMAND] [OPTIONS]
#
# Commands:
#   create      Create a new SSH key
#   delete      Delete an existing SSH key
#   list        List all managed SSH keys
#   edit        Edit SSH config for a key
#   help        Show this help message
#
# Options:
#   --env ENV             Specify environment (dev/prod)
#   --provider PROVIDER   Specify cloud provider (do/li/gcp)
#   --app APP             Specify application name
#   --user USER           Specify username on remote server
#   --ip IP               Specify IP address of remote server
#   --key-type TYPE       Specify key type (ed25519/rsa/ecdsa)
#
# Examples:
#   ./ssh-keyman.sh create
#   ./ssh-keyman.sh create --env dev --provider do --app librechat --user sudu
#   ./ssh-keyman.sh delete
#   ./ssh-keyman.sh list
#   ./ssh-keyman.sh edit

set -e

# Script version
VERSION="1.0.0"

# Default values
COMMAND=""
ENV=""
PROVIDER=""
APP=""
USER=""
IP=""
KEY_TYPE="ed25519"
INTERACTIVE=true

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
  echo -e "${BLUE}${BOLD}SSH Key Management Script v${VERSION}${NC}"
  echo
  echo "This script manages SSH keys for cloud server deployments following a structured"
  echo "naming convention and directory organization."
  echo
  echo -e "${YELLOW}${BOLD}Usage:${NC}"
  echo "  ./ssh-keyman.sh [COMMAND] [OPTIONS]"
  echo
  echo -e "${YELLOW}${BOLD}Commands:${NC}"
  echo "  create      Create a new SSH key"
  echo "  delete      Delete an existing SSH key"
  echo "  list        List all managed SSH keys"
  echo "  edit        Edit SSH config for a key"
  echo "  help        Show this help message"
  echo
  echo -e "${YELLOW}${BOLD}Options:${NC}"
  echo "  --env ENV             Specify environment (dev/prod)"
  echo "  --provider PROVIDER   Specify cloud provider (do/li/gcp)"
  echo "  --app APP             Specify application name"
  echo "  --user USER           Specify username on remote server"
  echo "  --ip IP               Specify IP address of remote server"
  echo "  --key-type TYPE       Specify key type (ed25519/rsa/ecdsa)"
  echo
  echo -e "${YELLOW}${BOLD}Examples:${NC}"
  echo "  ./ssh-keyman.sh create"
  echo "  ./ssh-keyman.sh create --env dev --provider do --app librechat --user sudu"
  echo "  ./ssh-keyman.sh delete"
  echo "  ./ssh-keyman.sh list"
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
  echo -e "1. Copy the public key to your server:"
  echo -e "   ${CYAN}cat $key_path.pub${NC}"
  echo
  echo -e "2. Add it to the authorized_keys file on your server:"
  echo -e "   ${CYAN}ssh-copy-id -i $key_path $USER@YOUR_SERVER_IP${NC}"
  echo -e "   or"
  echo -e "   ${CYAN}echo \"$(cat $key_path.pub)\" >> ~/.ssh/authorized_keys${NC}"
  echo
  echo -e "3. Test the connection:"
  if [ -n "$IP" ]; then
    echo -e "   ${CYAN}ssh $host_name${NC}"
  else
    echo -e "   ${CYAN}ssh -i $key_path $USER@YOUR_SERVER_IP${NC}"
    echo -e "   or, after setting the IP in your SSH config:"
    echo -e "   ${CYAN}ssh $host_name${NC}"
  fi
  echo
  echo -e "4. Create an alias in your shell profile (~/.bashrc, ~/.zshrc, etc.):"
  echo -e "   ${CYAN}alias goto-$APP-$ENV=\"ssh $host_name\"${NC}"
  echo
}

# Function to list all managed SSH keys
list_ssh_keys() {
  log_message "INFO" "Listing managed SSH keys..."
  
  local count=0
  echo -e "${BOLD}${CYAN}Development (dev) Environment Keys:${NC}"
  echo "-------------------------------------"
  if [ -d "$HOME/.ssh/keys/dev" ]; then
    for key in "$HOME/.ssh/keys/dev"/*; do
      if [ -f "$key" ] && [[ ! "$key" == *.pub ]]; then
        local basename=$(basename "$key")
        local host_entry=$(grep -l "IdentityFile.*$key" "$HOME/.ssh/config" | xargs grep "^Host" | awk '{print $2}')
        
        echo -e "${BOLD}$basename${NC}"
        echo -e "  Private Key: $key"
        echo -e "  Public Key: $key.pub"
        if [ -n "$host_entry" ]; then
          echo -e "  Host Entry: $host_entry"
        else
          echo -e "  Host Entry: ${YELLOW}Not configured${NC}"
        fi
        echo
        count=$((count+1))
      fi
    done
  fi
  
  if [ $count -eq 0 ]; then
    echo -e "${YELLOW}No development keys found.${NC}"
    echo
  fi
  
  count=0
  echo -e "${BOLD}${CYAN}Production (prod) Environment Keys:${NC}"
  echo "-------------------------------------"
  if [ -d "$HOME/.ssh/keys/prod" ]; then
    for key in "$HOME/.ssh/keys/prod"/*; do
      if [ -f "$key" ] && [[ ! "$key" == *.pub ]]; then
        local basename=$(basename "$key")
        local host_entry=$(grep -l "IdentityFile.*$key" "$HOME/.ssh/config" | xargs grep "^Host" 2>/dev/null | awk '{print $2}')
        
        echo -e "${BOLD}$basename${NC}"
        echo -e "  Private Key: $key"
        echo -e "  Public Key: $key.pub"
        if [ -n "$host_entry" ]; then
          echo -e "  Host Entry: $host_entry"
        else
          echo -e "  Host Entry: ${YELLOW}Not configured${NC}"
        fi
        echo
        count=$((count+1))
      fi
    done
  fi
  
  if [ $count -eq 0 ]; then
    echo -e "${YELLOW}No production keys found.${NC}"
    echo
  fi
  
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

# Function to create new SSH key
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
  
  # Get IP address (optional)
  if [ -z "$IP" ]; then
    read -p "Enter server IP address (optional, can be added later): " IP
  fi
  
  # Get key type
  if [ -z "$KEY_TYPE" ] || [ "$KEY_TYPE" = "ed25519" ]; then
    echo -e "${YELLOW}Select key type:${NC}"
    select key_option in "ED25519 (recommended)" "RSA" "ECDSA"; do
      case $key_option in
        "ED25519 (recommended)")
          KEY_TYPE="ed25519"
          break
          ;;
        "RSA")
          KEY_TYPE="rsa"
          break
          ;;
        "ECDSA")
          KEY_TYPE="ecdsa"
          break
          ;;
        *)
          log_message "ERROR" "Invalid selection. Please try again."
          ;;
      esac
    done
  fi
  
  # Validate inputs
  validate_environment || return 1
  validate_provider || return 1
  validate_app || return 1
  validate_user || return 1
  validate_key_type || return 1
  
  # Generate SSH key
  generate_ssh_key
  
  # Update SSH config
  update_ssh_config
  
  # Manage SSH agent
  manage_ssh_agent
  
  # Show next steps
  show_next_steps
  
  return 0
}

# Main function
main() {
  # Display banner
  echo -e "${BLUE}${BOLD}===========================================================${NC}"
  echo -e "${BLUE}${BOLD}           SSH Key Management Script v${VERSION}            ${NC}"
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
    "list")
      list_ssh_keys
      ;;
    "edit")
      edit_ssh_config
      ;;
    "help")
      show_help
      ;;
    "")
      # No command specified, show interactive menu
      echo -e "${YELLOW}Select operation:${NC}"
      select op in "Create new SSH key" "Delete SSH key" "List SSH keys" "Edit SSH config" "Exit"; do
        case $op in
          "Create new SSH key")
            create_new_key
            break
            ;;
          "Delete SSH key")
            delete_ssh_key
            break
            ;;
          "List SSH keys")
            list_ssh_keys
            break
            ;;
          "Edit SSH config")
            edit_ssh_config
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
    create|delete|list|edit|help)
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
    --key-type)
      KEY_TYPE="$2"
      shift 2
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