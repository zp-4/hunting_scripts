# MyThreatIntel

This project is a threat intelligence aggregation script that collects data from various open-source threat intelligence sources, normalizes the data, and presents it in a comprehensible form for security analysts. The platform supports multiple sources such as AlienVault OTX, AbuseIPDB, CIRCL LISTS, Emerging Threats, ThreatFox, Any.run, VirusTotal, and URLhaus. The script fetches data from these sources, normalizes it, and optionally stores it in a SQLite database. It also supports email alerts for new threat entries.

## Requirements

To run the Threat Intelligence Aggregation and Analysis Platform, you need to have Python 3 installed on your system. You'll also need the following Python libraries, which can be installed using pip:

**requests**
**yagmail**
**sqlite3**

You can create a virtual environment and install the required libraries by running:

```
pip install -r requirements.txt
```

## Installation Process

Clone the repository or download the threat_intelligence.py script.
Install the required libraries using pip as mentioned in the "Requirements" section.

## Configuration

Before running the script, you need to set up your Gmail credentials for email alerts. Open the script in a text editor and replace the GMAIL_USER and GMAIL_PASSWORD variables with your Gmail email address and its password or an app password if you have 2-factor authentication enabled.

```
GMAIL_USER = 'your_email@gmail.com'
GMAIL_PASSWORD = 'your_email_password'
```
## Running the Script

You can run the script by executing the following command:

```
python threat_intelligence.py
```
Using the script as a Linux Service

To run the script as a Linux service on boot, we'll use systemd. Create a new file threat_intelligence.service in the /etc/systemd/system/ directory with the following content:

```
[Unit]
Description=Threat Intelligence Aggregation and Analysis Platform
After=network.target

[Service]
User=your_username
WorkingDirectory=/path/to/your/threat_intelligence_directory
ExecStart=/path/to/your/python3_executable /path/to/your/threat_intelligence.py
Restart=always

[Install]
WantedBy=multi-user.target
```
Replace your_username with your Linux username, and set the correct paths for WorkingDirectory, ExecStart, and python3_executable.

Enable the service and start it with the following commands:

```
sudo systemctl enable threat_intelligence.service
sudo systemctl start threat_intelligence.service
```
Now, the Threat Intelligence Aggregation script will run as a service on boot.

# License
See the license file.
