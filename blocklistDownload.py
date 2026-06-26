import ipdb
import json
import csv
import os
import io
import pandas as pd
import requests
import datetime
from azure.identity import EnvironmentCredential # Used to quiry host system and get Credential Informatiob
from azure.keyvault.secrets import SecretClient # This is function that actually quries Azure to get the secrets
from azure.core.exceptions import HttpResponseError, AzureError # used for Error Handling

current_datetime = datetime.datetime.now()
timestamp = current_datetime.timestamp()

master_status = True
master_log = []

master_log.append(f"Script started at {current_datetime}")

# Azure Keyvault Credential and Client Setup
# 1. Get Vault URL from environment variable
try:
    VAULT_URL = os.environ["VAULT_URL"]
except KeyError:
    master_status = False
    master_log.append("VAULT_URL environment variable is missing")
else:
    # 2. Create credential
    try:
        credential = EnvironmentCredential()
    except AzureError as error:
        master_status = False
        master_log.append(f"Azure Identity error: {error}")
    else:
        # 3. Create client
        try:
            client = SecretClient(vault_url=VAULT_URL, credential=credential)
        except AzureError as error:
            master_status = False
            master_log.append(f"Azure SDK error: {error}")
try:
    client.get_secret("test-secret")
except HttpResponseError as error:
    master_status = False
    master_log.append(f"Vault HTTP error: {error}")

# Get Secrets from Azure Keyvault
csUserId = client.get_secret("pythonCsApiCid").value
csSecret = client.get_secret("pythonCsApiCsc").value
csBaseUrl = client.get_secret("pythonCsApiBaseUrl").value

auth_url = f"{csBaseUrl}/oauth2/token"

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
    master_log.append(f"Error occurred during authentication: {error}")
    master_status = False

try:
    if auth_Token:
        send_headers = {
            'authorization':'bearer ' + auth_Token,
            }
except NameError:
    master_log.append("Authentication token not found. Cannot proceed with file download.")

csIpBlocklistUrl = f"{csBaseUrl}/humio/api/v1/repositories/search-all/files/Dynamic_IP_BlockList.csv"
csUrlBlocklistUrl = f"{csBaseUrl}/humio/api/v1/repositories/search-all/files/Dynamic_Domain_BlockList.csv"

# Script Functions
def download_IP_blocklist(csIpBlocklistUrl, send_headers):

    download_IP_blocklist_log = []
    download_IP_blocklist_status = True

    payload = {
    "queryString": "readFile(\"Dynamic_IP_BlockList.csv\")",
    "outputFormat": "csv"
    }

    response = requests.get(csIpBlocklistUrl, headers=send_headers, json=payload)
    if response.status_code == 200:
        download_IP_blocklist_log.append("File downloaded from CrowdStrike successfully.")
        csv_file = io.BytesIO(response.text.encode('utf-8'))
        df = pd.read_csv(csv_file)
        ips = df.to_dict(orient="records")
        try:
            with open("Dynamic_IP_BlockList.txt", "w") as file:
                for ip in ips:
                    file.write(f"{ip['IP']}\n")
            download_IP_blocklist_log.append("Dynamic_IP_BlockList.txt created successfully.")
        except Exception as error:
            download_IP_blocklist_log.append(f"Error occurred while writing to Dynamic_IP_BlockList.txt: {error}")
            download_IP_blocklist_status = False
    else:
        download_IP_blocklist_log.append(f"Failed to download file from CrowdStrike. Status code: {response.status_code}, Response: {response.text}")
        download_IP_blocklist_status = False

    return download_IP_blocklist_status, download_IP_blocklist_log



def download_Domain_blocklist(csUrlBlocklistUrl, send_headers):

    download_Domain_blocklist_log = []
    download_Domain_blocklist_status = True

    payload = {
    "queryString": "readFile(\"Dynamic_Domain_BlockList.csv\")",
    "outputFormat": "csv"
    }

    response = requests.get(csUrlBlocklistUrl, headers=send_headers, json=payload)
    if response.status_code == 200:
        download_Domain_blocklist_log.append("File downloaded from CrowdStrike successfully.")
        csv_file = io.BytesIO(response.text.encode('utf-8'))
        df = pd.read_csv(csv_file)
        domains = df.to_dict(orient="records")
        try:
            with open("Dynamic_Domain_BlockList.txt", "w") as file:
                for domain in domains:
                    file.write(f"{domain['Domain']}\n")
            download_Domain_blocklist_log.append("Dynamic_Domain_BlockList.txt created successfully.")
        except Exception as error:
            download_Domain_blocklist_log.append(f"Error occurred while writing to Dynamic_Domain_BlockList.txt: {error}")
            download_Domain_blocklist_status = False
    else:
        download_Domain_blocklist_log.append(f"Failed to download file from CrowdStrike. Status code: {response.status_code}, Response: {response.text}")
        download_Domain_blocklist_status = False

    return download_Domain_blocklist_status, download_Domain_blocklist_log



try:
    ip_status, ip_log = download_IP_blocklist(csIpBlocklistUrl, send_headers)
    master_log.extend(ip_log)
except Exception as error:
    master_log.append(f"Error occurred during IP blocklist download: {error}")

try:
    domain_status, domain_log = download_Domain_blocklist(csUrlBlocklistUrl, send_headers)
    master_log.extend(domain_log)
except Exception as error:
    master_log.append(f"Error occurred during Domain blocklist download: {error}")



with open("master_log.txt", "w") as log_file:
    for line in master_log:
        log_file.write(line + "\n")
