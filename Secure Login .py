import os
import requests
import logging
import smtplib
import pyotp
import csv
from email.mime.text import MIMEText
from datetime import datetime

# Configure logging
logging.basicConfig(filename="login_attempts.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Approved users
approved_users = {
    "Abdirahman": ("Mac-pro", "abdifatah143@gmail.com\n"),
    "Abdifatah": ("Abdifatah-MacBook-Pro", "abdifatah143@gmail.com\n"),
    "Reyes": ("Windows", "abdifatah143@gmail.com\n"),
    "John": ("PC", "abdifatah143@gmail.com\n"),
    "Raha": ("Mac-Air", "abdifatah143@gmail.com\n")
}

# Gmail credentials
GMAIL_SENDER = "abdifatah143@gmail.com"
GMAIL_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

# Admin email for alerting
admin_email = "abdifatah143@gmail.com"  # Replace with your admin Gmail

if not GMAIL_PASSWORD:
    print("❌ Environment variable 'GMAIL_APP_PASSWORD' not set.")
    exit()

# MFA TOTP setup
totp_secret = pyotp.random_base32()
totp = pyotp.TOTP(totp_secret)

# Failed attempts and blocking
failed_attempts = {}
blocked_users = set()
MAX_ATTEMPTS = 3

# Directly insert your VirusTotal API Key here
VIRUSTOTAL_API_KEY = "6b067aedeeb5ee65ec41d53dc04fa9b599066813c6e89b67d2c109c05a85e76c"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Send email function
def send_email(recipient, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = GMAIL_SENDER
    msg["To"] = recipient

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_SENDER, GMAIL_PASSWORD)
            server.send_message(msg)
        print(f"📧 Email sent to {recipient}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        logging.error(f"Email send failed to {recipient}: {e}")

# Admin alert wrapper
def alert_admin(subject, message):
    try:
        send_email(admin_email, subject, message)
        print(f"📧 Admin alerted via Gmail: {admin_email}")
    except Exception as e:
        print(f"❌ Failed to alert admin: {e}")

# Get IP address
def get_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "Unknown"

# Check IP reputation with VirusTotal
def check_ip_virustotal(ip):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(f"{VIRUSTOTAL_URL}{ip}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                ip_info = data["data"]
                last_analysis = ip_info["attributes"]["last_analysis_stats"]
                malicious_count = last_analysis.get("malicious", 0)
                if malicious_count > 0:
                    return f"⚠️ IP {ip} is flagged as malicious with {malicious_count} detections on VirusTotal."
                else:
                    return f"✅ IP {ip} is clean on VirusTotal."
            return "❌ Unable to get VirusTotal IP info."
        return f"❌ Error checking IP on VirusTotal: {response.status_code}"
    except Exception as e:
        return f"❌ VirusTotal check failed for IP {ip}: {e}"

# Get location from IP
def get_location():
    try:
        ip = get_ip()
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        location = response.get("city", "") + ", " + response.get("region", "")
        isp = response.get("org", "Unknown ISP")
        coords = response.get("loc", "")
        return location, isp, coords
    except:
        return "Unknown", "Unknown", "Unknown"

# CSV logger
def log_to_csv(username, device_id, ip_address, location, isp, status):
    with open("login_logs.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), username, device_id, ip_address, location, isp, status])

# Main login logic
def login(username, device_id, mfa_input, actual_mfa):
    ip_address = get_ip()
    location, isp, coords = get_location()
    result = ""

    if username in blocked_users:
        result += f"🚫 {username} is temporarily blocked after {MAX_ATTEMPTS} failed attempts.\n"
        logging.warning(f"BLOCKED user {username} attempted login | IP: {ip_address}")
        log_to_csv(username, device_id, ip_address, location, isp, "BLOCKED")
        return result

    # Check if the IP is flagged by VirusTotal
    ip_check = check_ip_virustotal(ip_address)
    result += ip_check + "\n"

    if username in approved_users:
        assigned_device, email = approved_users[username]
        result += f"✅ User: {username}\n"

        if device_id == assigned_device:
            result += "✅ Device check passed.\n"
            if mfa_input == actual_mfa:
                result += "🔐 MFA passed: Login successful!\n"
                failed_attempts[username] = 0  # Reset on success
                log_to_csv(username, device_id, ip_address, location, isp, "SUCCESS")
                send_email(email, f"✅ Login Alert: {username}", f"""
Login successful!
User: {username}
Device: {device_id}
IP: {ip_address}
Location: {location}
ISP: {isp}
Coordinates: {coords}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")
            else:
                result += "❌ MFA failed.\n"
                failed_attempts[username] = failed_attempts.get(username, 0) + 1
                logging.warning(f"MFA FAIL for {username} | IP: {ip_address}")
        else:
            result += f"❌ Device mismatch: expected '{assigned_device}', got '{device_id}'\n"
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            logging.warning(f"Device mismatch for {username} | IP: {ip_address}")
    else:
        result += f"❌ Unauthorized user: {username}\n"
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        logging.warning(f"Unauthorized user {username} | IP: {ip_address}")

    if failed_attempts.get(username, 0) >= MAX_ATTEMPTS:
        blocked_users.add(username)
        result += f"🚫 {username} has been blocked after {MAX_ATTEMPTS} failed attempts.\n"
        logging.warning(f"User {username} blocked | IP: {ip_address}")
        log_to_csv(username, device_id, ip_address, location, isp, "BLOCKED")

        alert_subject = f"🚨 BLOCKED LOGIN: {username}"
        alert_body = f"""
User '{username}' has been blocked after {MAX_ATTEMPTS} failed login attempts.

📍 IP Address: {ip_address}
🖥️ Device: {device_id}
🌐 Location: {location}
🛰️ ISP: {isp}
🕒 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        alert_admin(alert_subject, alert_body)

    return result

# --- MAIN ---
if __name__ == "__main__":
    username = input("Enter your username: \n").strip()

    if username in approved_users:
        assigned_device, user_email = approved_users[username]
        print(f"\nHello {username}, your assigned device is: {assigned_device}\n")
        device_id = input("Enter your device ID: ").strip()

        # Generate and send MFA code
        mfa_code = totp.now()
        send_email(user_email, "Your MFA Code", f"Your login verification code is: {mfa_code}")

        # Get code from user and validate
        mfa_input = input("Enter the MFA code sent to your email: ").strip()
        result = login(username, device_id, mfa_input, mfa_code)
        print(result)
    else:
        print(f"❌ The username '{username}' is not approved to access the system.\n")
        logging.warning(f"Login attempt with unknown user: {username}")
