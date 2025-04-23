# 🔐 Secure Email-Based MFA Login System with GeoIP & Intrusion Blocking

## 📌 Overview
This Python project is a secure login system built with the goal of combining multi-factor authentication, email alerts, geo-location tracking, and brute-force protection into a lightweight, easy-to-use tool. It is ideal for internal environments where heightened access security is needed without the complexity of enterprise IAM tools.

---

## 🚀 Features

- **🔐 Multi-Factor Authentication (MFA)**
  - One-Time Password (OTP) generated via TOTP and emailed using Gmail.
- **📍 GeoIP Location Tracking**
  - IP-based location fetched using `ipinfo.io` API.
- **📧 Email Notifications**
  - Login codes and admin alerts sent via Gmail SMTP.
- **📊 CSV + Log File Logging**
  - Saves login attempts in a structured CSV file and a human-readable log file.
- **🚫 Intrusion Detection**
  - Automatically blocks a user after 3 failed login attempts.
- **🔒 Device Binding**
  - Each approved user is assigned a specific device ID for added verification.

---

## 🛠️ Technologies Used
- `Python 3.x`
- `smtplib`, `email.mime` – for email sending
- `pyotp` – for generating TOTP codes
- `requests` – for IP geolocation lookup
- `logging` – for event logging
- `csv`, `datetime`, `socket`, `os`

---

## 📁 File Structure
```
📦 mfa_login_system
 ┣ 📜 main.py                 # Main script
 ┣ 📜 login_attempts.log      # Log file
 ┣ 📜 login_logs.csv          # CSV log of login attempts
 ┗ 📜 README.md               # This file
```

---

## 🧪 Example Output
### Successful Login:
```
✅ User: Abdirahman
✅ Device check passed.
✅ MFA passed: Login successful!
📍 Location: Nairobi, Kenya (IP: 105.67.34.23)
```

### Failed Login:
```
❌ MFA failed: Incorrect code.
❌ 3 failed attempts. User is now blocked.
📧 Admin alert sent to youradminemail@gmail.com
```

---

## 📬 Setup Instructions
1. Set environment variable `GMAIL_APP_PASSWORD` with your Gmail App Password.
2. Install dependencies:
```bash
pip install pyotp requests
```
3. Run the script:
```bash
python main.py
```

---

## 📈 Future Enhancements
- Add Slack or Telegram bot alert support
- Implement auto-unblock timers or captcha challenge
- Web-based interface for login tracking
- Dashboard visualizations (Grafana, etc.)

---

## 👨‍💻 Author
**Abdifatah Galgalo**  
Cloud & Cybersecurity Engineer

