#!/bin/bash
# Description: Check attackers based on your fail2ban log
# Author: Robin LABADIE
# Author website: www.lrob.fr

# Settings
sleep_time="1" # Used to avoid rate-limiting
whois_timeout="5" # Timeout for whois queries in seconds
send_abuse_emails="off" # on/off # WARNING: may expose sensitive information especially when including ssh and apache logs.
abuse_email_sender="abuse@yourdomain.tld" # You shall change to a real email address with an SPF rule authenticating your sender
# Note log paths are valid for a Plesk server - tested on Debian only
include_fail2ban_log="on" # on/off
fail2ban_logpath='/var/log/fail2ban.log'
include_apache_log="off" # on/off
apache_logpath='/var/www/vhosts/*/logs/*log'
include_ssh_log="off" # on/off
ssh_logpath='/var/log/auth.log'

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
declare -A abuse_email_ips
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

    # Collect IPs for each abuse email
    abuse_email_ips[${abuse_email}]+="${ip} "

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

for org in "${!ip_counts[@]}"; do
    if [[ -n "${ip_counts[$org]}" ]] && [[ "${total_ips}" -gt 0 ]] && [[ "${ip_counts[$org]}" -gt 0 ]]; then
        if command -v bc &> /dev/null; then
            percentage=$(bc <<< "scale=2; ${ip_counts[$org]}*100/${total_ips}")
            stat_output="${org}: ${ip_counts[$org]} IPs (${percentage}%)"
        else
            stat_output="${org}: ${ip_counts[$org]} IPs"
        fi
    else
        stat_output="${org}: ${ip_counts[$org]:-0} IPs (N/A)"
    fi
    fn_logecho "${stat_output}"
done

function fetch_fail2ban_log {
    local ip=$1
    grep "${ip}" "${fail2ban_logpath}"
}

function fetch_apache_log {
    local ip=$1
    grep -rnw "${ip}" "${apache_logpath}"
}

function fetch_ssh_log {
    local ip=$1
    grep -rnw "${ip}" "${ssh_logpath}"
}

# Send report for each abuse email
if [ "${send_abuse_emails}" == "on" ]; then
    fn_logecho "Sending abuse emails..."
    for email in "${!abuse_email_ips[@]}"; do
        if [[ "${email}" != "Unknown" ]]; then
            mailsubject="Abuse Report - Your network is attacking ${HOSTNAME}"
            mailcontent="From: ${abuse_email_sender}\n"  # Add your "From" email here
            mailcontent+="To: ${email}\n"
            mailcontent+="Subject: ${mailsubject}\n"
            mailcontent+="Report for Abuse Email: ${email}\n"
            
            for ip in ${abuse_email_ips[${email}]}; do
                mailcontent+="\nIP: ${ip}\n"
                if [[ "${include_fail2ban_log}" == "on" ]]; then
                    mailcontent+="\nFail2Ban Log Entries:\n$(fetch_fail2ban_log "${ip}")\n"
                fi
                if [[ "${include_apache_log}" == "on" ]]; then
                    mailcontent+="\nApache Log Entries:\n$(fetch_apache_log "${ip}")\n"
                fi
                if [[ "${include_ssh_log}" == "on" ]]; then
                    mailcontent+="\nSSH Log Entries:\n$(fetch_ssh_log "${ip}")\n"
                fi
            done
            # Actually send the mail
            echo -e "${mailcontent}" | mail -s "${mailsubject}" "${email}"
            # Log and display what is sent
            fn_logecho "Sending Mail From: ${abuse_email_sender}" ; fn_logecho "Subject: ${mailsubject}" ; fn_logecho "To be sent to: ${email}" ; fn_logecho -e "${mailcontent}"
        fi
    done
fi

# Display script exec duration using Ultimate BASH API
fn_duration
