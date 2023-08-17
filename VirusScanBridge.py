import virustotal_python # VirusTotal API
import os # For file path
import requests # For HTTP requests
from pprint import pprint # For pretty printing
from openpyxl import Workbook # For Excel
# VirusTotal API Key
API_KEY = '6bf043675b60ab5626d10857b580e9456e415bbff9223f88258b77b2e85dc85b'

# VirusTotal Instance
virusTotal = virustotal_python.Virustotal(API_KEY)

# Since its a directory with multiple files I need to iterate through the file
apk_directory = r'C:\Users\jalee\PycharmProjects\APK'

# Responsible for iterating through the directory
for filename in os.listdir(apk_directory):
    if filename.endswith('.apk'):
        apk_file_path = os.path.join(apk_directory, filename)

        try:
            # Will open the file and read it
            with open(apk_directory, 'rb') as file:
                files = {'file' : (os.path.basename(apk_directory), file)}
                response = virusTotal.request("files", files=files)

                if response.status_code == 200:
                    # Will print the response
                    response_data = response.json()

                    if response_data.get('response_code') == 200:
                        resource = response_data.get('resource')
                        print(f"File {filename} successfully uploaded.")
                        print(f"Scan ID: {resource}")

                        file_info_response = virusTotal.request("files/{resource}")
                        file_info = file_info_response.data
                        pprint(file_info)
                else:
                    print(f"File {filename} failed to upload.")

        except FileNotFoundError:
            print(f"File {filename} not found.")

        except requests.exceptions.RequestException as req_exc:
            print(f"Request failed: {req_exc}")

        # All-rounder error type
        except Exception as e:
            print(f"Unknown error: {e}")