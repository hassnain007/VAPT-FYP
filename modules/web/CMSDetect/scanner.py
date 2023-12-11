import re
import requests
import logging
from core.colors import *
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user_agents = {
    'User-Agent 1': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'User-Agent 2': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'User-Agent 3': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'User-Agent 4': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'User-Agent 5': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'User-Agent 6': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
    'User-Agent 7': 'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'User-Agent 8': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.37 Safari/537.36'
}



def get_content(url, headers):
    try:
        if headers:
            resp = requests.get(url, headers=headers, verify=False).text
        else:
            resp = requests.get(url, verify=False).text
        return resp
    except requests.RequestException as e:
        logging.error(f"Error making request: {e}")
        return None

def detect_by_regex(content):
    if content is None:
        return "Response is None"

    joomla_pattern = re.compile(r'<script type=\"text/javascript\" src=\"/media/system/js/mootools.js\"></script>|/media/system/js/|com_content|Joomla!')
    wordpress_pattern = re.compile(r'wp-content|wordpress|xmlrpc.php')
    drupal_pattern = re.compile(r'Drupal|drupal|sites/all|drupal.org')
    magento_pattern = re.compile(r'Log into Magento Admin Page|name=\"dummy\" id=\"dummy\"|Magento')

    if joomla_pattern.search(content):
        return 'CMS found Joomla'
    elif wordpress_pattern.search(content):
        return 'CMS found WordPress'
    elif drupal_pattern.search(content):
        return 'CMS found Drupal'
    elif magento_pattern.search(content):
        return 'CMS found Magento'
    else:
        return 'No CMS FOUND'

def detect_by_whatcms(url, api_key, headers):
    try:
        resp = requests.get(f'https://whatcms.org/API/Tech?key={api_key}&url={url}', headers=headers)
        res = resp.json()
        for key in res['results']:
            print(green + '[+]', 'Tech Detected:', key['name'])
    except Exception as e:
        print(red + str(e))

def scan_file(urlfile, headers):
    try:
         with open(urlfile, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('https'):
                    url = line
                    cms = detect_by_regex(get_content(url, headers))
                    print(green + f"CMS Found for {line}: {cms}")
    except Exception as e:
        logging.error(f"Error: {e}")

def full_scan(url, urlfile, outfile, api_key):
    headers = {
        'User-Agent': user_agents['User-Agent 1'],
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
    }

    if url:
        cms = detect_by_regex(get_content(url, headers))
        print(green + f"CMS Found for {url}: {cms}")
        detect_by_whatcms(url, api_key, headers)
    elif urlfile:
        scan_file(urlfile, headers)
    else:
        logging.error("Either URL or URL file must be provided for a full scan.")

if __name__ == '__main__':
    # this is for testing
    full_scan(url=None, urlfile='urls.txt', outfile=None, api_key='your_api_key')
