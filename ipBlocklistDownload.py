import ipdb
import json
import os
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

print(auth_Token)

try:
    send_headers = {
        'authorization':'bearer ' + auth_Token,
        }
    
    payload = {
    "queryString": "readFile(\"Dynamic_IP_BlockList.csv\")",
    "outputFormat": "csv"
    }

    cs_api_url = f"{csBaseUrl}/humio/api/v1/repositories/search-all/files/Dynamic_IP_BlockList.csv"

    response = requests.get(cs_api_url, headers=send_headers, json=payload)
    if response.status_code == 200:
        master_log.append("File downloaded from CrowdStrike successfully.")
        with open("Dynamic_IP_BlockList.csv", "wb") as f:
            f.write(response.content)
    else:
        master_log.append(f"Failed to download file from CrowdStrike. Status code: {response.status_code}, Response: {response.text}")
        master_status = False
except requests.exceptions.RequestException as error:
    master_log.append(f"Error occurred during file download: {error}")
    master_status = False

ipdb.set_trace()