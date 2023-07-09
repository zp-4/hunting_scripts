########################################################################################################################
### Author: zp-4                                                                                                     ###
### Date: 26/06/2023                                                                                                 ###
### Description: This scripts notifies by mail when extracts iocs from urlshaus and store in database                ###
### Script: urlhaus-get-ioc.py                                                                                       ###
########################################################################################################################

import requests
import json
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sqlite3
from datetime import datetime, timedelta
from urllib.parse import urlparse
from tabulate import tabulate

# URLhaus API configuration
recent_urls_api_url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
payload_api_url = "https://urlhaus-api.abuse.ch/v1/payload/"
api_key = "XXXXXX"  # Replace with your actual API key

# Email configuration
smtp_server = 'smtp.gmail.com'
smtp_port = 587
sender_email = 'johndoe@gmail.com'  # Replace with the actual sender email address
receiver_email = 'johndoe@gmail.com'  # Replace with the actual receiver email address
smtp_password = 'XXXXXX'  # Replace with your actual SMTP password

# Database configuration
database_file = "urlhaus.db"

# Other configuration
delay = 14400  # Delay between each iteration in seconds (1 hour)

# Connect to the database
conn = sqlite3.connect(database_file)
cursor = conn.cursor()

# Create the 'results' table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    md5_hash TEXT,
                    url_status TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

# Create the 'appearance_count' table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS appearance_count (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    md5_hash TEXT,
                    count INTEGER DEFAULT 0
                )''')

# Commit the table creation
conn.commit()

# Function to send email
def send_email(subject, body):
    # Create the multipart message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # Create the HTML part of the message
    html = f"""\
    <html>
        <head></head>
        <body>
            {body}
        </body>
    </html>
    """

    # Attach the HTML part to the message
    msg.attach(MIMEText(html, "html"))

    # Send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, smtp_password)
        server.send_message(msg)

while True:
    try:
        # Fetch recent URLs from API
        response = requests.get(recent_urls_api_url, headers={"API-Key": api_key})
        if response.status_code == 200:
            try:
                response_data = response.json()
                if response_data.get("query_status") == "ok":
                    new_results = []
                    for url in response_data.get("urls", []):
                        url_data = {
                            "url": url.get("url", ""),
                            "md5_hash": url.get("md5_hash", ""),
                            "url_status": url.get("url_status", "")
                        }
                        cursor.execute("SELECT COUNT(*) FROM results WHERE url = ? AND md5_hash = ?",
                                       (url_data["url"], url_data["md5_hash"]))
                        result_count = cursor.fetchone()[0]

                        if result_count == 0:
                            # Extract hostname from URL
                            parsed_url = urlparse(url_data["url"])
                            hostname = parsed_url.hostname

                            url_data["hostname"] = hostname
                            new_results.append(url_data)
                            cursor.execute("INSERT INTO results (url, md5_hash, url_status) VALUES (?, ?, ?)",
                                           (url_data["url"], url_data["md5_hash"], url_data["url_status"]))
                        else:
                            cursor.execute("UPDATE appearance_count SET count = count + 1 WHERE url = ? AND md5_hash = ?",
                                           (url_data["url"], url_data["md5_hash"]))

                    conn.commit()

                    # Send alert email if there are new results
                    if new_results:
                        table_data = [[result["url"], result["hostname"], result["md5_hash"], result["url_status"]]
                                      for result in new_results]

                        # Generate the table
                        table = tabulate(table_data, headers=["URL", "Hostname", "MD5 Hash", "URL Status"], tablefmt="html")

                        # Send alert email with new results
                        email_subject = "URLhaus Alert - New Indicators of Compromise"
                        email_body = f"<h2>New Indicators of Compromise:</h2>{table}"
                        send_email(email_subject, email_body)

                    # Check for appearance count and send report on Monday
                    current_day = datetime.now().strftime("%A")
                    if current_day == "Monday":
                        cursor.execute("SELECT url, md5_hash, count FROM appearance_count ORDER BY count DESC LIMIT 10")
                        top_results = cursor.fetchall()

                        if top_results:
                            table_data = [[result[0], result[1], result[2]] for result in top_results]

                            # Generate the table
                            table = tabulate(table_data, headers=["URL", "MD5 Hash", "Appearance Count"], tablefmt="html")

                            # Send report email
                            report_subject = "URLhaus Weekly Report - Top Indicators of Compromise"
                            report_body = f"<h2>Top Indicators of Compromise for the Past Week:</h2>{table}"
                            send_email(report_subject, report_body)

                else:
                    query_status = response_data.get("query_status")
                    error_message = f"Query status (Recent URLs): {query_status}"
                    send_email("Query Status Error", error_message)
            except Exception as e:
                # Send email notification for script error
                error_message = f"Script error: {str(e)}"
                send_email("URLhaus Script Error - General", error_message)
                raise
        else:
            error_message = f"Error (Recent URLs): {response.status_code}"
            send_email("API Error", error_message)

        # Delay before next iteration
        time.sleep(delay)

    except Exception as e:
        # Send email notification for database error
        error_message = f"Database error: {str(e)}"
        send_email("URLhaus Script Error - Database", error_message)
        raise

# Close the database connection
conn.close()
