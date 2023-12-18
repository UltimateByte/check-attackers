#!/bin/bash
# Description: Check attackers based on your fail2ban log
# Author: Robin LABADIE
# Author website: www.lrob.fr

# Settings
sleep_time="1" # Used to avoid rate-limiting

# Get the name of this script for logging purposes
selfname="$(basename "$(readlink -f "${BASH_SOURCE[0]}")")"

# Check for bc command
if ! command -v bc &> /dev/null; then
    echo "Warning: 'bc' command not found. Please install 'bc' for advanced statistics."
    exit 1
fi

# Download bash API
if [ ! -f "ultimate-bash-api.sh" ]; then
    wget https://raw.githubusercontent.com/UltimateByte/ultimate-bash-api/master/ultimate-bash-api.sh
    chmod +x ultimate-bash-api.sh
fi
source ultimate-bash-api.sh

declare -A ip_counts
total_ips=0

function fetch_whois_data {
    local ip=$1
    whois "${ip}"
}

function extract_org_name {
    local whois_data=$1
    local org_name=$(echo "${whois_data}" | grep -i "OrgName" | awk -F: '{print $2}' | xargs)
    
    if [[ -z "${org_name}" ]]; then
        org_name=$(echo "${whois_data}" | grep -i "netname" | awk -F: '{print $2}' | xargs)
    fi

    echo "${org_name:-Unknown}"
}

function extract_abuse_email {
    local whois_data=$1
    local abuse_email=$(echo "${whois_data}" | grep -i "abuse" | grep "@" | awk '{print $NF}' | head -n 1)
    
    if [[ -z "${abuse_email}" ]]; then
        abuse_email=$(echo "${whois_data}" | grep -i "e-mail" | awk '{print $NF}' | head -n 1)
    fi

    echo "${abuse_email:-Unknown}"
}

function process_ip {
    local ip=$1
    local whois_data=$(fetch_whois_data "${ip}")
    local org_name=$(extract_org_name "${whois_data}")
    local abuse_email=$(extract_abuse_email "${whois_data}")

    # Count IPs per Organization
    ((ip_counts["${org_name}"]++))
    ((total_ips++))

    # Verbose Output and Logging
    fn_logecho "${ip} - ${org_name} - Abuse Email: ${abuse_email}"
}

# Main loop
for ip in $(grep "Ban" /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq); do
    process_ip "${ip}"
    sleep "${sleep_time}"
done

# Output statistics
fn_logecho "Provider IP Statistics:"
for org in $(printf "%s\n" "${!ip_counts[@]}" | sort -nr | while read -r count org; do
    if command -v bc &> /dev/null; then
        percentage=$(bc <<< "scale=2; $count*100/$total_ips")
        stat_output="$org: $count IPs ($percentage%)"
    else
        stat_output="$org: $count IPs"
    fi
    fn_logecho "$stat_output"
done
