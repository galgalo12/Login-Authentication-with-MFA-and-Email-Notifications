# Login-Authentication-with-MFA-and-Email-Notifications

This Python project is a login authentication system that integrates multi-factor authentication (MFA) using Time-based One-Time Passwords (TOTP), device verification, and email notifications. It ensures that only approved users can log in and provides real-time alerts about login attempts.

Key Features:
User Authentication:

The script validates user login attempts by checking if the username exists in an approved users list.

Each user is associated with a specific device, and the device ID must match the assigned device for the login to proceed.

Multi-Factor Authentication (MFA):

MFA is implemented using TOTP, where the user is required to enter a time-sensitive one-time code sent to their email.

If the code is correct, the user is granted access.

Device Verification:

The script ensures that the login attempt is made from the correct device by matching the device ID with the assigned one.

Email Notifications:

Upon successful login, an email is sent to the user with login details (device, IP address, timestamp).

Failed attempts, including incorrect MFA codes and device mismatches, are logged and an email is sent to notify about the failure.

Logging:

The script logs all successful and failed login attempts, including any device mismatches or unauthorized username attempts, for auditing and security monitoring.

Security:

Gmail's SMTP server is used to send emails securely using TLS.

The Gmail password is retrieved from an environment variable, ensuring that credentials are not hardcoded in the script.

Project Requirements:
Python 3.x

Libraries: smtplib, os, logging, socket, pyotp, email.mime.text

A Gmail account for sending email notifications (requires an app-specific password for authentication).

Environment variables for securely storing Gmail credentials.

Usage:
Users can enter their username, device ID, and the MFA code sent to their email for authentication.

If everything checks out, the system allows the login and sends a notification email. Any failed login attempt is logged and can trigger alerts.
