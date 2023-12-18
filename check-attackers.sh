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

# Loop through the fail2ban log, extract unique IPs
for ip in $(grep "Ban" /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq); do
    # Fetch whois data for the IP
    whois_data=$(whois "${ip}")

    # First, try to extract OrgName. If not present, use netname as a fallback.
    org_name=$(echo "${whois_data}" | grep -i "OrgName" | awk -F: '{print $2}' | xargs)
    if [[ -z "${org_name}" ]]; then
        org_name=$(echo "${whois_data}" | grep -i "netname" | awk -F: '{print $2}' | xargs)
    fi

    # Extract the first occurrence of an abuse email, fallback to any email if not found
    abuse_email=$(echo "${whois_data}" | grep -i "abuse" | grep "@" | awk '{print $NF}' | head -n 1)
    if [[ -z "${abuse_email}" ]]; then
        abuse_email=$(echo "${whois_data}" | grep -i "e-mail" | awk '{print $NF}' | head -n 1)
    fi

    # Verbose Output and Logging
    fn_logecho "${ip} - ${org_name} - Abuse Email: ${abuse_email}"

    # Count IPs per Organization
    if [[ -n "${org_name}" ]]; then
        ((ip_counts["${org_name}"]++))
        ((total_ips++))
    fi

    # Sleep to avoid rate-limiting
    sleep "${sleep_time}"
done

# Sort providers by usage and output using fn_logecho
fn_logecho "Provider IP Statistics:"
for org in $(printf "%s\n" "${!ip_counts[@]}" | sort -k2 -nr); do
    if command -v bc &> /dev/null; then
        percentage=$(bc <<< "scale=2; ${ip_counts["$org"]}*100/${total_ips}")
        stat_output="${org}: ${ip_counts["$org"]} IPs (${percentage}%)"
    else
        stat_output="${org}: ${ip_counts["$org"]} IPs"
    fi
    fn_logecho "${stat_output}"
done
