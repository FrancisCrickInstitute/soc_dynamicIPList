import ipdb
import os
import io
import sys
import requests
import datetime
import logging
import pandas as pd
from azure.identity import EnvironmentCredential # Used to quiry host system and get Credential Informatiob
from azure.keyvault.secrets import SecretClient # This is function that actually quries Azure to get the secrets
from azure.core.exceptions import HttpResponseError, AzureError # used for Error Handling

# Script Base Variable Generation
current_datetime = datetime.datetime.now()
timestamp = current_datetime.timestamp()
log_file = 'master_log.txt'

# Set up Logging
handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
if log_file:
    handlers.append(logging.FileHandler(log_file, mode="w"))
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=handlers,
)
log = logging.getLogger("ipBlockList_dump")

log.info("Script start time: %s", current_datetime)

# Azure Keyvault Credential and Client Setup
# 1. Get Vault URL from environment variable
try:
    VAULT_URL = os.environ["VAULT_URL"]
except KeyError:
    log.error("VAULT_URL environment variable is missing")
else:
    # 2. Create credential
    try:
        credential = EnvironmentCredential()
    except AzureError as error:
        log.error("Azure Identity error: %s", error)
    else:
        # 3. Create client
        try:
            client = SecretClient(vault_url=VAULT_URL, credential=credential)
        except AzureError as error:
            log.error.append("Azure SDK error: %s", error)
try:
    client.get_secret("test-secret")
except HttpResponseError as error:
    log.error("Vault HTTP error: %s", error)

# Function to download IP Blocklist from Crowdstrike
def download_IP_blocklist(client):

    csUserId = client.get_secret("pythonCsApiCid").value
    csSecret = client.get_secret("pythonCsApiCsc").value
    csBaseUrl = client.get_secret("pythonCsApiBaseUrl").value

    auth_url = f"{csBaseUrl}/oauth2/token"
    csIpBlocklistUrl = f"{csBaseUrl}/humio/api/v1/repositories/search-all/files/Dynamic_IP_BlockList.csv"

    # Generate Auth Token
    auth_headers = {
    'Content-type': 'application/x-www-form-urlencoded',
    'accept': 'application/json'
    }

    auth_creds = {}
    auth_creds['client_id'] = csUserId
    auth_creds['client_secret'] = csSecret
    auth_creds['grant_type'] = "client_credentials"

    try:
        auth_response = requests.post(auth_url, data=auth_creds, headers=auth_headers)
        auth_Token = auth_response.json()['access_token']
    except requests.exceptions.RequestException as error:
        log.error("Error occurred during authentication: %s", error)

    try:
        if auth_Token:
            send_headers = {
            'authorization':'bearer ' + auth_Token,
            }
    except NameError:
        log.error("Authentication token not found. Cannot proceed with file download.")

    # Download IP Blocklist file
    payload = {
    "queryString": "readFile(\"Dynamic_IP_BlockList.csv\")",
    "outputFormat": "csv"
    }

    try:
        response = requests.get(csIpBlocklistUrl, headers=send_headers, json=payload)
        if response.status_code == 200:
            log.info("File downloaded from CrowdStrike successfully.")
            csv_file = io.BytesIO(response.text.encode('utf-8'))
            df = pd.read_csv(csv_file)
            ips = df.to_dict(orient="records")

    except requests.exceptions.Timeout as error:
        log.error("Timed out: %s", error)
    except requests.exceptions.HTTPError as error:
        log.error("HTTP error: %s", error)
    except requests.exceptions.RequestException as error:
        log.error("Network/request error: %s", error)
    except (KeyError, ValueError) as error:
        log.error("Unexpected response shape:  %s", error)
    except Exception as error:
        log.error("Unspecified error:  %s", error)

    return ips



def abuseipdb_check(client, ips):

    abuseApiUrl = client.get_secret("abuseIpdbApiUrl").value
    abuseApiKey = client.get_secret("abuseIpdbApiKey").value

    url = f"{abuseApiUrl}check"

    headers = {
    'Accept': 'Application/json',
    'Key': abuseApiKey
    }

    results = []

    for ip in ips:


        querystring = {
        'ipAddress': ip,
        'maxAgeInDays': 90
        }

        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            response.raise_for_status()
            log.info(f"Checking for IP: {ip}, Status Code: {response.status_code}")
            info = response.json()

            if 'data' in info.keys():
                entry = {}
                entry['ip'] = ip
                entry['isWhitelisted'] = info['data'].get('isWhitelisted', False)
                entry['abuseConfidenceScore'] = info['data'].get('abuseConfidenceScore', 0)
                results.append(entry)

        except requests.exceptions.Timeout as error:
            log.error("Timed out: %s", error)
        except requests.exceptions.HTTPError as error:
            log.error("HTTP error: %s", error)
        except requests.exceptions.RequestException as error:
            log.error("Network/request error: %s", error)
        except (KeyError, ValueError) as error:
            log.error("Unexpected response shape:  %s", error)
        except Exception as error:
            log.error("Unspecified error:  %s", error)

    return results



try:
    ips = download_IP_blocklist(client)
except Exception as error:
    log.error("Error returned by function %s", error)

try:
    unique_ips = set()
    for entry in ips:
        unique_ips.add(entry['IP'])
except Exception as error:
    log.error("Error processing IPs dataset")

try:
    if unique_ips:
        results =  abuseipdb_check(client, unique_ips)
except Exception as error:
    log.error("Error returned by function %s", error)

try:
    with open("Dynamic_IP_BlockList.txt", "w") as file:
        for result in results:
            if result['abuseConfidenceScore'] > 0:
                file.write(f"{result['ip']}\n")
                log.info(f"Adding IP: {result['ip']} to output file")
            else:
                log.info(f"Omitting IP: {result['ip']}, Low Confidence")
except Exception as error:
    log.error("Error writing output file: %s", error)
