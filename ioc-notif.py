########################################################################################################################
### Author: zp-4                                                                                                     ###
### Date: 26/05/2023                                                                                                 ###
### Description: This scripts notifies with mail when ExecuteMalware and pr0xylife add some IOC in their github repo ###
### Script: ioc-notif.py                                                                                             ###
########################################################################################################################

import os
import time
from git import Repo
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlparse

# Email configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = 'yyyyyyyyyyyy@gmail.com'
SENDER_PASSWORD = 'XXXXXXXXXX'
RECIPIENT_EMAIL = 'yyyyyyyyyy@gmail.com'

# Dictionary to store the last processed commit for each repository
last_commits = {}

def download_new_files(repo_dir):
    repo = Repo(repo_dir)
    origin = repo.remotes.origin
    origin.pull()

    # Get the list of modified files since the last check
    head_commit = repo.head.commit
    parent_commit = head_commit.parents[0] if head_commit.parents else None

    if parent_commit:
        diff_files = repo.git.diff('--name-only', parent_commit, head_commit).splitlines()
    else:
        diff_files = repo.git.diff('--name-only', head_commit).splitlines()

    # Check if any new files are added or modified
    new_files = []
    for file_path in diff_files:
        if os.path.isfile(os.path.join(repo_dir, file_path)):
            new_files.append(file_path)

    if new_files:
        for file_path in new_files:
            print(f"Downloaded file: {file_path}")
            send_notification_email(repo.remotes.origin.url, repo_dir, file_path)

        # Update the last processed commit for the repository
        last_commits[repo_dir] = head_commit

def send_notification_email(repo_url, repo_dir, file_path):
    repo_owner = urlparse(repo_url).path.split('/')[1]
    file_url = f"https://github.com/{repo_owner}/{repo_dir.split('/')[-1]}/blob/master/{file_path}"

    message = f"New file added/modified: {file_path}\n\n"
    message += f"Full file link: {file_url}"

    subject = f"GitHub Repository Change Notification: {repo_owner} -- {file_path}"

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        print("Email notification sent successfully")
    except Exception as e:
        print(f"Failed to send email notification: {e}")

def monitor_github_repos(repo_urls, repo_dirs):
    repos = []
    for i, repo_url in enumerate(repo_urls):
        repo_dir = repo_dirs[i]
        if not os.path.exists(repo_dir):
            Repo.clone_from(repo_url, repo_dir)
        repos.append(repo_dir)

    # Initialize last_commits dictionary with initial commits
    for repo_dir in repos:
        repo = Repo(repo_dir)
        last_commits[repo_dir] = repo.head.commit

    while True:
        for repo_dir in repos:
            repo = Repo(repo_dir)
            origin = repo.remotes.origin
            origin.pull()

            # Check if the current commit is different from the last processed commit
            if repo.head.commit != last_commits[repo_dir]:
                download_new_files(repo_dir)
                last_commits[repo_dir] = repo.head.commit

        time.sleep(60)  # Wait for 1 minute before checking again

# Usage example
github_repo_urls = [
    "https://github.com/executemalware/Malware-IOCs",
    "https://github.com/pr0xylife/Qakbot",
    "https://github.com/pr0xylife/Emotet",
    "https://github.com/pr0xylife/IcedID",
    "https://github.com/pr0xylife/Pikabot",
    "https://github.com/pr0xylife/Bumblebee",
    "https://github.com/pr0xylife/NetSupportRAT"
]
local_repo_dirs = [
    "exec_repo",
    "proxy_qakbot_repo",
    "proxy_emotet_repo",
    "proxy_icedid_repo",
    "proxy_pikabot_repo",
    "proxy_bumblebee_repo",
    "proxy_netsupport_repo"
]


monitor_github_repos(github_repo_urls, local_repo_dirs)
