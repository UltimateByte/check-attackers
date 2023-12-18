#!/bin/bash
# Description: Check attackers based on your fail2ban log
# Author: Robin LABADIE
# Author website: www.lrob.fr

# Settings
sleep_time="1" # Used to avoid rate-limiting
whois_timeout="5" # Timeout for whois queries in seconds

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
    timeout "${whois_timeout}" whois "${ip}"
}

function extract_org_name {
    local whois_data=$1
    local org_name
    org_name=$(echo "${whois_data}" | grep -i "OrgName" | awk -F: '{print $2}' | xargs)
    
    if [[ -z "${org_name}" ]]; then
        org_name=$(echo "${whois_data}" | grep -i "netname" | awk -F: '{print $2}' | xargs)
    fi

    # Check for duplicated words in org_name and remove them
    org_name=$(echo "${org_name}" | awk '
    {
        for (i=1; i<=NF; i++) {
            if (!seen[$i]++) {
                printf("%s%s", sep, $i)
                sep=OFS
            }
        }
    }')

    echo "${org_name:-Unknown}"
}

function extract_abuse_email {
    local whois_data=$1
    local abuse_email
    abuse_email=$(echo "${whois_data}" | grep -i "abuse" | grep "@" | awk '{print $NF}' | head -n 1)
    
    if [[ -z "${abuse_email}" ]]; then
        abuse_email=$(echo "${whois_data}" | grep -i "e-mail" | awk '{print $NF}' | head -n 1)
    fi

    # Remove single quotes from the email address
    abuse_email=$(echo "${abuse_email}" | tr -d "'")

    echo "${abuse_email:-Unknown}"
}

function process_ip {
    local ip=$1
    local whois_data
    local org_name
    local abuse_email

    whois_data=$(fetch_whois_data "${ip}")
    org_name=$(extract_org_name "${whois_data}")
    abuse_email=$(extract_abuse_email "${whois_data}")

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
printf "%s|%s\n" "${!ip_counts[@]}" "${ip_counts[@]}" | sort -t'|' -k2nr | while IFS='|' read -r org count; do
    # Ensure count and total_ips are valid numbers
    if [[ -n "${count}" ]] && [[ "${total_ips}" -gt 0 ]] && [[ "${count}" -gt 0 ]]; then
        if command -v bc &> /dev/null; then
            percentage=$(bc <<< "scale=2; ${count}*100/${total_ips}")
            stat_output="${org}: ${count} IPs (${percentage}%)"
        else
            stat_output="${org}: ${count} IPs"
        fi
    else
        # Handle cases where count or total_ips is zero or invalid
        stat_output="${org}: ${count:-0} IPs (N/A)"
    fi
    fn_logecho "${stat_output}"
done
