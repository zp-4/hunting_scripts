import requests
import sqlite3
from datetime import datetime

# Gmail configurations for email alerts
GMAIL_USER = 'your_email@gmail.com'
GMAIL_PASSWORD = 'your_email_password'

# SQLite database configuration
DATABASE_FILE = 'threat_intelligence.db'

# URL of threat intelligence sources
SOURCES = {
    'AlienVault OTX': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
    'AbuseIPDB': 'https://api.abuseipdb.com/api/v2/blacklist',
    'CIRCL LISTS': 'https://www.circl.lu/services/open-source-intelligence/large-scale-campaign-tracker/list/',
    'Emerging Threats': 'https://rules.emergingthreats.net/open/suricata-5.0/',
    'ThreatFox': 'https://threatfox.abuse.ch/api/v1/',
    'Any.run': 'https://api.any.run/v1/analyses',
    'VirusTotal': 'https://www.virustotal.com/api/v3/ip_addresses/report',
    'URLhaus': 'https://urlhaus-api.abuse.ch/v1/payload'
}

# Dictionary to map specific attributes for each source
SOURCE_ATTRIBUTES = {
    'ThreatFox': ['description', 'created', 'threat'],
    'Any.run': ['description', 'created', 'threat'],
    'VirusTotal': ['description', 'created', 'threat'],
    'URLhaus': ['description', 'created', 'threat']
}

def fetch_data_from_source(source_name, url):
    # Function to fetch data from the specified threat intelligence source
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json() if 'threatfox' in source_name.lower() or 'any.run' in source_name.lower() else response.text.splitlines()
        return data
    else:
        print(f"Failed to fetch data from {source_name}.")
        return None

def is_active_ioc(indicator):
    # Function to check if the IOC is active or passive (or N/A)
    # You can customize this function for your specific use case
    # For example, by checking with third-party services or using other threat intelligence sources
    # In this example, we assume all IOC indicators are active
    return True

def normalize_data(data, source_name):
    # Function to normalize data from the specified threat intelligence source
    normalized_data = []
    for entry in data:
        normalized_entry = {
            'source': source_name,
            'indicator': entry.strip(),
            'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'appearance_count': 0,
            'is_active': is_active_ioc(entry.strip())
        }
        # Map specific attributes for the sources that need it
        if source_name in SOURCE_ATTRIBUTES:
            for attr in SOURCE_ATTRIBUTES[source_name]:
                normalized_entry[attr] = None
        normalized_data.append(normalized_entry)

    return normalized_data

def normalize_threatfox_data(data):
    # Function to normalize data from ThreatFox
    normalized_data = []
    for entry in data:
        normalized_entry = {
            'source': 'ThreatFox',
            'indicator': entry['ioc'],
            'created': entry['timestamp'],
            'appearance_count': 0,
            'is_active': is_active_ioc(entry['ioc']),
            'description': entry.get('type'),
            'threat': entry.get('status')
        }
        normalized_data.append(normalized_entry)

    return normalized_data

def normalize_anyrun_data(data):
    # Function to normalize data from Any.run
    normalized_data = []
    for entry in data:
        normalized_entry = {
            'source': 'Any.run',
            'indicator': entry['url'],
            'created': entry['date'],
            'appearance_count': 0,
            'is_active': is_active_ioc(entry['url']),
            'description': entry.get('filename'),
            'threat': entry.get('severity')
        }
        normalized_data.append(normalized_entry)

    return normalized_data

def normalize_virustotal_data(data):
    # Function to normalize data from VirusTotal
    normalized_data = []
    for entry in data:
        normalized_entry = {
            'source': 'VirusTotal',
            'indicator': entry['ip_address'],
            'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'appearance_count': 0,
            'is_active': is_active_ioc(entry['ip_address']),
            'description': entry['attributes']['as_owner'],
            'threat': entry['attributes']['last_analysis_stats']['malicious']
        }
        normalized_data.append(normalized_entry)

    return normalized_data

def normalize_urlhaus_data(data):
    # Function to normalize data from URLhaus
    normalized_data = []
    for entry in data:
        normalized_entry = {
            'source': 'URLhaus',
            'indicator': entry['url'],
            'created': entry['date_added'],
            'appearance_count': 0,
            'is_active': is_active_ioc(entry['url']),
            'description': entry['threat'],
            'threat': entry['tags'][0]
        }
        normalized_data.append(normalized_entry)

    return normalized_data

def save_data_to_database(data):
    # Function to save normalized data into the SQLite database
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        for entry in data:
            cursor.execute("SELECT * FROM threat_intelligence WHERE indicator=?", (entry['indicator'],))
            existing_entry = cursor.fetchone()
            if existing_entry:
                # If the entry already exists in the database, update the count, last appearance, and active status
                count = existing_entry[6] + 1
                is_active = entry['is_active']
                last_appearance = entry['created'] if is_active else existing_entry[5]
                cursor.execute("UPDATE threat_intelligence SET appearance_count=?, last_appearance=?, is_active=? WHERE indicator=?", 
                               (count, last_appearance, is_active, entry['indicator']))
            else:
                # If the entry does not exist, insert a new entry into the database
                cursor.execute("INSERT INTO threat_intelligence (source, indicator, description, created, threat, last_appearance, appearance_count, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                               (entry['source'], entry['indicator'], entry.get('description'), entry['created'], entry['threat'], entry.get('last_appearance'), entry['appearance_count'], entry['is_active']))
        conn.commit()

def send_email_alert(subject, new_entries):
    # Function to send email alerts with new threat entries in the database
    table_content = "<h2>New Threats:</h2>"
    table_content += "<table border='1' style='border-collapse: collapse; width: 100%;'>"
    table_content += "<tr><th>Source</th><th>Indicator</th><th>Description</th><th>Created</th><th>Threat</th><th>Last Appearance</th><th>Appearance Count</th></tr>"
    for entry in new_entries:
        if entry['is_active'] or entry['is_active'] is None:  # Notify only active or N/A IOC entries
            table_content += f"<tr><td>{entry['source']}</td><td>{entry['indicator']}</td><td>{entry.get('description', 'N/A')}</td><td>{entry['created']}</td><td>{entry['threat']}</td><td>{entry.get('last_appearance', 'N/A')}</td><td>{entry['appearance_count']}</td></tr>"
    table_content += "</table>"

    yag = yagmail.SMTP(GMAIL_USER, GMAIL_PASSWORD)
    yag.send(to=GMAIL_USER, subject=subject, contents=table_content)
    yag.close()

def main():
    new_entries = []
    for source_name, source_url in SOURCES.items():
        data = fetch_data_from_source(source_name, source_url)
        if data:
            if source_name == 'ThreatFox':
                normalized_data = normalize_threatfox_data(data)
            elif source_name == 'Any.run':
                normalized_data = normalize_anyrun_data(data)
            elif source_name == 'VirusTotal':
                normalized_data = normalize_virustotal_data(data)
            elif source_name == 'URLhaus':
                normalized_data = normalize_urlhaus_data(data)
            else:
                normalized_data = normalize_data(data, source_name)
            # save_data_to_database(normalized_data)
            new_entries.extend(normalized_data)

    if new_entries:
        print("New Threats Detected:")
        for entry in new_entries:
            print(entry)

    # if new_entries:
    #     send_email_alert("New Threats Detected", new_entries)

if __name__ == "__main__":
    main()
