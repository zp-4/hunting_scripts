import os
import requests
import csv
from io import StringIO
import argparse
from prettytable import PrettyTable

def fetch_feed(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def parse_csv(feed_text, header):
    csv_file = StringIO(feed_text)

    for _ in range(8):
        next(csv_file)

    column_names = header.strip().split(',')
    csv_file.seek(0)

    reader = csv.DictReader((line for line in csv_file if not line.startswith('#')), fieldnames=column_names, delimiter=',', quotechar='"')
    return list(reader)

def search_by_url(feed_data, search_string):
    return [entry for entry in feed_data if search_string.lower() in entry.get('url', '').lower()]

def get_urls(feed_data, tags=None, all_tags_required=False, url_status=None):
    filtered_data = feed_data

    if tags:
        tags_to_match = [tag.strip().lower() for tag in tags.split(',')]

        def contains_tags(entry_tags):
            return any(tag in entry_tags for tag in tags_to_match)

        if all_tags_required:
            filtered_data = [entry for entry in filtered_data if contains_tags(entry.get('tags', '').lower().split(','))]
        else:
            filtered_data = [entry for entry in filtered_data if any(tag in entry.get('tags', '').lower() for tag in tags_to_match)]

    if url_status:
        filtered_data = [entry for entry in filtered_data if entry.get('url_status') == url_status]

    return [entry.get('url', '') for entry in filtered_data]

def filter_by_tag(feed_data, tags, all_tags_required=False, search_string=None):
    tags_to_match = [tag.strip().lower() for tag in tags.split(',')]

    def contains_tags(entry_tags):
        return any(tag in entry_tags for tag in tags_to_match)

    if search_string:
        return [entry for entry in feed_data if search_string.lower() in entry.get('tags', '').lower() and contains_tags(entry.get('tags', '').lower().split(','))]
    elif all_tags_required:
        return [entry for entry in feed_data if contains_tags(entry.get('tags', '').lower().split(','))]
    else:
        return [entry for entry in feed_data if any(tag in entry.get('tags', '').lower() for tag in tags_to_match)]

def filter_by_url_status(feed_data, url_status):
    return [entry for entry in feed_data if entry.get('url_status') == url_status]

def print_table(entries, fields=None, url_only=False):
    if not entries:
        print("No matching entries found.")
        return

    if not fields:
        fields = ["Date Added", "URL", "URL Status", "Threat", "Tags"]

    if url_only:
        fields = ["Url"]

    table = PrettyTable()
    table.field_names = [field.lower() for field in fields]  # Convert field names to lowercase

    for entry in entries:
        if url_only:
            print(entry.get('url', ''))
        else:
            table.add_row([entry.get(field.lower(), '') for field in fields])  # Use lowercase field names for lookup

    if not url_only:
        print(table)

def export_to_csv(entries, filename, export_fields):
    if not entries:
        print("No entries to export.")
        return

    try:
        with open(filename, 'w+', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=export_fields)
            writer.writeheader()

            for entry in entries:
                filtered_entry = {key: entry.get(key.lower(), '') for key in export_fields}
                writer.writerow(filtered_entry)

        print(f"Results exported to {os.path.abspath(filename)}.")
    except Exception as e:
        print(f"Error exporting to CSV: {e}")

    if os.path.exists(filename):
        print(f"The file exists: {os.path.abspath(filename)}")
    else:
        print(f"The file does not exist: {os.path.abspath(filename)}")

def main():
    feed_url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
    feed_text = fetch_feed(feed_url)

    provided_header = "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter"
    feed_data = parse_csv(feed_text, provided_header)

    parser = argparse.ArgumentParser(description='Search URLhaus feed by URL and filter by tags and URL status.')
    parser.add_argument('--url', help='Search for a specific URL in the feed')
    parser.add_argument('--tag', help='Filter by a specific tag (multiple tags can be separated by commas)')
    parser.add_argument('--tags', help='Filter by multiple tags (all tags required)')
    parser.add_argument('--urlstatus', help='Filter by URL status')
    parser.add_argument('--export', help='Export results to a CSV file. Provide the filename after --export', nargs='?')
    parser.add_argument('--url-only', help='Return only URLs matching the criteria', action='store_true')

    args = parser.parse_args()

    if args.url:
        matching_urls = search_by_url(feed_data, args.url)
        print_table(matching_urls, url_only=args.url_only)

        if args.export:
            export_filename = args.export if args.export.endswith('.csv') else args.export + '.csv'
            export_fields = ["Date Added", "URL", "URL Status", "Threat", "Tags"]
            if args.url_only:
                export_fields = ["Url"]
            export_to_csv(matching_urls, export_filename, export_fields)

    elif args.tag:
        filtered_by_tag = filter_by_tag(feed_data, args.tag, search_string=args.url)
        print_table(filtered_by_tag, url_only=args.url_only)

        if args.export:
            export_filename = args.export if args.export.endswith('.csv') else args.export + '.csv'
            export_fields = ["Date Added", "URL", "URL Status", "Threat", "Tags"]
            if args.url_only:
                export_fields = ["Url"]
            export_to_csv(filtered_by_tag, export_filename, export_fields)

    elif args.tags:
        filtered_by_tags = filter_by_tag(feed_data, args.tags, all_tags_required=True, search_string=args.url)
        print_table(filtered_by_tags, url_only=args.url_only)

        if args.export:
            export_filename = args.export if args.export.endswith('.csv') else args.export + '.csv'
            export_fields = ["Date Added", "URL", "URL Status", "Threat", "Tags"]
            if args.url_only:
                export_fields = ["Url"]
            export_to_csv(filtered_by_tags, export_filename, export_fields)

    elif args.urlstatus:
        filtered_by_url_status = filter_by_url_status(feed_data, args.urlstatus)
        print_table(filtered_by_url_status, url_only=args.url_only)

        if args.export:
            export_filename = args.export if args.export.endswith('.csv') else args.export + '.csv'
            export_fields = ["Date Added", "URL", "URL Status", "Threat", "Tags"]
            if args.url_only:
                export_fields = ["Url"]
            export_to_csv(filtered_by_url_status, export_filename, export_fields)

    elif args.url_only:
        urls = get_urls(feed_data, tags=args.tag, all_tags_required=(args.tags is not None), url_status=args.urlstatus)
        for url in urls:
            print(url)

        if args.export:
            export_filename = args.export if args.export.endswith('.csv') else args.export + '.csv'
            export_fields = ["Url"]
            export_to_csv([{'url': url} for url in urls], export_filename, export_fields)

if __name__ == "__main__":
    main()
