import smtplib  # Imports the library to send emails using the Simple Mail Transfer Protocol (SMTP).
import os  # Provides a way to interact with the operating system, such as environment variables.
import logging  # Used for logging information or errors to a file.
import socket  # Used to get the device's IP address.
import pyotp  # Generates Time-based One-Time Passwords (TOTP) for Multi-Factor Authentication (MFA).
from email.mime.text import MIMEText  # Used to create email messages in text format.
from datetime import datetime  # Provides date and time functions.

# 🔧 Enable SMTP debug output
DEBUG_SMTP = False  # A flag to enable or disable debug output when sending emails.

# Configure logging
logging.basicConfig(filename="login_attempts.log", level=logging.INFO,  # Set up logging to file 'login_attempts.log'.
                    format="%(asctime)s - %(levelname)s - %(message)s")  # Define log format.

# Approved users (this is a dictionary that maps usernames to their assigned device and email)
approved_users = {
    "Abdirahman": ("Mac-pro", "abdifatah143@gmail.com"),
    "Reyes": ("Windows", "abdifatah143@gmail.com"),
    "John": ("PC", "abdifatah143@gmail.com"),
    "Raha": ("Mac-Air", "abdifatah143@gmail.com")
}

# Gmail credentials (using environment variable for security)
GMAIL_SENDER = "galgaloabdifatah@gmail.com"  # Sender's Gmail address.
GMAIL_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")  # Retrieves the Gmail app password from environment variables.

# Check if the Gmail password is set, if not, exit the script.
if not GMAIL_PASSWORD:
    print("❌ Environment variable 'GMAIL_APP_PASSWORD' not set.")
    exit()

# MFA TOTP setup (generates a random base32 secret for MFA)
totp_secret = pyotp.random_base32()  # Randomly generates a secret for TOTP.
totp = pyotp.TOTP(totp_secret)  # Creates the TOTP object to generate MFA codes.

# Function to send an email (used to send login alerts or MFA codes)
def send_email(recipient, subject, body):
    msg = MIMEText(body)  # Create the email body.
    msg["Subject"] = subject  # Set the email subject.
    msg["From"] = GMAIL_SENDER  # Set the sender's email address.
    msg["To"] = recipient  # Set the recipient's email address.

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:  # Connect to Gmail's SMTP server on port 587.
            if DEBUG_SMTP:  # If debugging is enabled, show SMTP details.
                server.set_debuglevel(1)
            server.starttls()  # Secure the connection with TLS.
            server.login(GMAIL_SENDER, GMAIL_PASSWORD)  # Log in to Gmail using the sender's credentials.
            server.send_message(msg)  # Send the email.
        print(f"📧 Email sent to {recipient}")  # If successful, print confirmation.
    except Exception as e:  # Handle any errors that occur during email sending.
        print(f"❌ Failed to send email: {e}")
        logging.error(f"Email send failed to {recipient}: {e}")  # Log the error.

# Function to get the IP address of the device
def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())  # Retrieve the local device's IP address.
    except:
        return "Unknown"  # Return "Unknown" if the IP can't be determined.

# Login logic function
def login(username, device_id, mfa_input, actual_mfa):
    result = ""  # This will hold the login result message.
    ip_address = get_ip()  # Get the device's IP address.

    if username in approved_users:  # Check if the username is approved.
        assigned_device, email = approved_users[username]  # Retrieve the assigned device and email for the user.
        result += f"The user {username} is approved.\nAssigned device: {assigned_device}\n"

        if device_id == assigned_device:  # Check if the device ID matches the assigned device.
            result += "✅ Device check passed.\n"
            if mfa_input == actual_mfa:  # Validate the MFA code.
                result += "🔐 MFA passed: Login successful!\n"
                logging.info(f"SUCCESSFUL login for {username} from IP: {ip_address}, device: {device_id}")  # Log a successful login.
                
                # Send login notification email
                subject = f"✅ Login Alert: {username}"
                body = f"""
Login successful for user: {username}
Device: {device_id}
IP Address: {ip_address}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                send_email(email, subject, body)  # Send a login success email.
            else:
                result += "❌ MFA failed: Incorrect code.\n"
                logging.warning(f"FAILED MFA for {username} from IP: {ip_address}")  # Log MFA failure.
        else:
            result += f"❌ Device mismatch: Expected '{assigned_device}', got '{device_id}'\n"
            logging.warning(f"Device mismatch for {username} - expected: {assigned_device}, entered: {device_id}")  # Log device mismatch.
    else:
        result += f"❌ Username '{username}' is not approved.\n"
        logging.warning(f"Unauthorized username attempt: {username} from IP: {ip_address}")  # Log unauthorized user attempt.

    return result  # Return the result of the login process.

# --- MAIN ---
if __name__ == "__main__":
    username = input("Enter your username: ").strip()  # Prompt for the username.

    if username in approved_users:  # If the user is approved, proceed with login.
        assigned_device, user_email = approved_users[username]  # Get the assigned device and email for the user.
        print(f"Hello {username}, your assigned device is: {assigned_device}")  # Inform the user about the device.
        device_id = input("Enter your device ID: ").strip()  # Prompt for the device ID.

        # Generate and send MFA code
        mfa_code = totp.now()  # Generate a new MFA code using TOTP.
        send_email(user_email, "Your MFA Code", f"Your login verification code is: {mfa_code}")  # Send the MFA code to the user's email.

        # Get MFA input from the user and validate
        mfa_input = input("Enter the MFA code sent to your email: ").strip()  # Prompt for the MFA code from the user.
        result = login(username, device_id, mfa_input, mfa_code)  # Perform the login process and check credentials.
        print(result)  # Print the result of the login attempt.
    else:
        print(f"❌ The username '{username}' is not approved to access the system.")  # Inform the user if the username is not approved.
        logging.warning(f"Login attempt with unknown user: {username}")  # Log the failed login attempt.
