#!/bin/bash

# shellcheck disable=1090  # Sourcing dynamic files
# shellcheck disable=2009  # ps instead of pgrep (simpler here)
# shellcheck disable=2034  # Variables may be used in sourced scripts

set -u -o pipefail

# Check if running in bash
if ! ps -p $$ | grep -si bash >/dev/null; then
    echo "Sorry, this script requires bash."
    exit 1
fi

# Check for systemctl
if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl required. Exiting."
    exit 1
fi

# Function to log messages (consistent with individual scripts)
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

function main {
    clear

    # Ensure ubuntu.cfg exists and is sourced
    if [[ ! -f ./ubuntu.cfg ]]; then
        log_message "ERROR: ubuntu.cfg not found, cannot proceed"
        echo "ubuntu.cfg not found. Exiting."
        exit 1
    fi
    source ./ubuntu.cfg || {
        log_message "ERROR: Failed to source ubuntu.cfg"
        echo "Failed to source ubuntu.cfg. Exiting."
        exit 1
    }
    log_message "INFO: Successfully sourced ubuntu.cfg"

    # Ensure backup directory exists
    mkdir -p "$BACKUP_DIR" || {
        log_message "ERROR: Failed to create backup directory $BACKUP_DIR"
        echo "Failed to create backup directory $BACKUP_DIR. Exiting."
        exit 1
    }
    chmod 0700 "$BACKUP_DIR"  # Restrict permissions
    log_message "INFO: Ensured backup directory $BACKUP_DIR exists"

    # Check and install required packages
    local required_progs=(
        "arp" "dig" "ping" "w" "coreutils" "systemd" "ufw" "usbguard" "passwd" "iputils-ping"
        "bind9-dnsutils" "net-tools" "procps" "rkhunter" "psad" "aide" "apparmor-utils"
    )
    local missing_progs=()
    for prog in "${required_progs[@]}"; do
        if ! command -v "$prog" >/dev/null 2>&1; then
            missing_progs+=("$prog")
            log_message "WARNING: $prog is required but not installed"
        fi
    done
    if [[ ${#missing_progs[@]} -gt 0 ]]; then
        log_message "INFO: Installing missing packages: ${missing_progs[*]}"
        if $APT update -qq && $APT install -y --no-install-recommends "${missing_progs[@]}" 2>/tmp/apt_install_error; then
            log_message "INFO: Successfully installed required packages"
        else
            local error_msg=$(cat /tmp/apt_install_error)
            log_message "ERROR: Failed to install required packages - Error: $error_msg"
            echo "Failed to install required packages. Exiting."
            rm -f /tmp/apt_install_error
            exit 1
        fi
    else
        log_message "INFO: All required programs are installed"
    fi

    # Define binary paths (use variables from ubuntu.cfg if set)
    ARPBIN="${ARPBIN:-$(command -v arp)}"
    DIGBIN="${DIGBIN:-$(command -v dig)}"
    PINGBIN="${PINGBIN:-$(command -v ping)}"
    WBIN="${WBIN:-$(command -v w)}"
    WHOBIN="${WHOBIN:-$(command -v who)}"
    LXC="${LXC:-0}"
    [[ "$VERBOSE" == "Y" ]] && log_message "INFO: Binary paths set - ARPBIN=$ARPBIN, DIGBIN=$DIGBIN, PINGBIN=$PINGBIN, WBIN=$WBIN, WHOBIN=$WHOBIN"

    # Determine SERVERIP
    if resolvectl status >/dev/null 2>&1; then
        SERVERIP=$(ip route get "$(resolvectl status | grep -E 'DNS (Server:|Servers:)' | tail -n1 | awk '{print $NF}')" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -n1)
    else
        SERVERIP=$(ip route get "$(grep '^nameserver' /etc/resolv.conf | tail -n1 | awk '{print $NF}')" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -n1)
    fi
    if [[ -n "$SERVERIP" ]]; then
        log_message "INFO: Determined SERVERIP as $SERVERIP"
    else
        log_message "WARNING: Could not determine SERVERIP, using default or proceeding without"
    fi

    # Check LXC environment
    if grep -qE 'container=lxc|container=lxd' /proc/1/environ; then
        LXC="1"
        log_message "INFO: Detected LXC environment, setting LXC=1"
    else
        log_message "INFO: No LXC environment detected, LXC=0"
    fi

    # Autofill configuration if AUTOFILL='Y'
    if [[ "$AUTOFILL" == "Y" ]]; then
        USERIP=$($WHOBIN | awk '{print $NF}' | tr -d '()' | grep -E '^[0-9]' | head -n1)
        if [[ "$USERIP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ADMINIP="$USERIP"
        else
            ADMINIP="$(hostname -I | sed -E 's/\.[0-9]+ /.0\/24 /g')"
        fi
        log_message "INFO: Autofilling configuration - ADMINIP=$ADMINIP"

        sed -i "s/FW_ADMIN=.*/FW_ADMIN='$ADMINIP'/" ./ubuntu.cfg
        sed -i "s/SSH_GRPS=.*/SSH_GRPS='$(id "$($WBIN -ih | awk '{print $1}' | head -n1)" -ng)'/" ./ubuntu.cfg
        sed -i "s/CHANGEME=.*/CHANGEME='$(date +%s)'/" ./ubuntu.cfg
        sed -i "s/VERBOSE=.*/VERBOSE='Y'/" ./ubuntu.cfg
        log_message "INFO: Updated ubuntu.cfg with autofilled values"
    fi

    # Re-source ubuntu.cfg after potential autofill updates
    source ./ubuntu.cfg || {
        log_message "ERROR: Failed to re-source ubuntu.cfg after autofill"
        echo "Failed to re-source ubuntu.cfg after autofill. Exiting."
        exit 1
    }

    # Source all function scripts
    local script_dir="./scripts"
    if [[ ! -d "$script_dir" ]]; then
        log_message "ERROR: $script_dir directory not found, cannot load functions"
        echo "$script_dir directory not found. Exiting."
        exit 1
    fi
    for s in "$script_dir"/*; do
        if [[ -f "$s" ]]; then
            source "$s" || {
                log_message "ERROR: Failed to source $s"
                echo "Failed to source $s. Exiting."
                exit 1
            }
            [[ "$VERBOSE" == "Y" ]] && log_message "INFO: Sourced $s"
        fi
    done
    log_message "INFO: Successfully sourced all scripts from $script_dir"

    # Define function execution list with updated AIDE functions
    local hardening_functions=(
        f_pre f_kernel f_firewall f_disablenet f_disablefs f_disablemod
        f_systemdconf f_resolvedconf f_logindconf f_journalctl f_timesyncd
        f_fstab f_prelink f_aptget_configure f_aptget f_hosts f_issue
        f_sudo f_logindefs f_sysctl f_limitsconf f_adduser f_rootaccess
        f_package_install f_psad f_coredump f_usbguard f_postfix f_apport
        f_motdnews f_rkhunter f_sshconfig f_sshdconfig f_password f_cron
        f_ctrlaltdel f_auditd f_aide f_aide_post f_aide_timer f_aptget_noexec f_aptget_clean  # CHANGED: Updated to f_aidepost and f_aidetimer
        f_systemddelta f_post f_checkreboot
    )

    # Execute hardening functions
    for func in "${hardening_functions[@]}"; do
        if declare -f "$func" >/dev/null 2>&1; then
            log_message "INFO: Executing $func"
            "$func" || {
                log_message "ERROR: $func failed"
                echo "$func failed. Check $LOG_FILE for details. Continuing with next function."
            }
        else
            log_message "WARNING: Function $func not defined, skipping"
            echo "Function $func not defined. Skipping."
        fi
    done

    # Final verification (example: check if key services are running)
    local verification_services=("$SSH_SERVICE" "$UFW_SERVICE" "$USBGUARD_SERVICE" "$TIMESYNCD_SERVICE")
    local verified=true
    for svc in "${verification_services[@]}"; do
        if ! systemctl is-active "$svc" >/dev/null 2>&1; then
            log_message "WARNING: Service $svc is not active post-hardening"
            verified=false
        fi
    done
    if [[ "$verified" == "true" ]]; then
        log_message "INFO: Verified key services are active post-hardening"
    else
        log_message "WARNING: Some key services are not active, review logs"
    fi

    log_message "INFO: Hardening process completed"
    echo "Hardening process completed. See $LOG_FILE for details."
    echo
}

# Set up logging and trap errors
LOG_FILE="${LOG_FILE:-/var/log/user_hardening.log}"  # Default if not sourced
echo "[HARDENING LOG - $(hostname --fqdn) - $(LANG=C date)]" > "$LOG_FILE"
trap 'log_message "ERROR: Script terminated unexpectedly with exit code $?"; exit 1' ERR

# Execute main function
main "$@"