# Check-Attackers

Are you tired of seeing hundreds or thousands of attacks in your fail2ban logs, feeling powerless to report them all in hopes of a better internet? The internet is filled with hacked servers and unwanted behaviors. The `check-attackers.sh` script is designed to automate the process of analyzing these attacks and reporting them to the appropriate authorities, contributing to a safer internet.

## Features

- Analyzes current fail2ban log for attacking IPs.
- Retrieves provider and abuse email address for every attacker IP.
- Sorts attackers per provider and displays the percentage of incoming attacks.
- Optionally sends automated abuse notifications with relevant logs to abuse email addresses.

## Prerequisites

- fail2ban
- whois (for IP lookups)
- bc (for calculations)
- Properly configured mail system for sending emails

## Installation and Usage

1. Clone the repository or download the script.
2. Make the script executable: `chmod +x check-attackers.sh`.
3. Configure the script settings in the top section of the script.
4. Run the script: `./check-attackers.sh`.

## Configuration

- `sleep_time`: Time to wait between processing IPs to avoid rate limiting.
- `whois_timeout`: Timeout for whois queries.
- `send_abuse_emails`: Toggle to turn on/off the sending of abuse emails.
- `abuse_email_sender`: Set your sending email address for proper delivery.
- Log file paths: Enable or disable and set the correct paths for including your fail2ban, Apache, and SSH logs regarding the attacking IP.
