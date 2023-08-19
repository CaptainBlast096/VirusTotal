import virustotal_python # VirusTotal API
import os # For file path
import requests # For HTTP requests
from pprint import pprint # For pretty printing
from openpyxl import Workbook # For Excel

# VirusTotal API Key
API_KEY = '6bf043675b60ab5626d10857b580e9456e415bbff9223f88258b77b2e85dc85b'
Collection_ID = '6fbcb4121a78476a77a6982498a1368624454c08bee9b597ba5d1ab1f1a06cbb'
upload_url = 'https://www.virustotal.com/gui/collection/6fbcb4121a78476a77a6982498a1368624454c08bee9b597ba5d1ab1f1a06cbb'
headers = {
    "x-apikey": "6bf043675b60ab5626d10857b580e9456e415bbff9223f88258b77b2e85dc85b"
}
response = requests.post(upload_url, headers=headers)
upload_data = response.json()

print(response.text)
# VirusTotal Instance
virusTotal = virustotal_python.Virustotal(API_KEY)

# Since its a directory with multiple files I need to iterate through the file
apk_directory = r'C:\Users\jalee\PycharmProjects\APK'

# Responsible for iterating through the directory
for filename in os.listdir(apk_directory):
    if filename.endswith('.apk'):
        apk_file_path = os.path.join(apk_directory, filename)
        try:
            # Open the APK file for reading and prepare it for upload
            with open(apk_file_path, 'rb') as apk_file:
                files = {'file': (os.path.basename(apk_file_path), apk_file)}

                # Make the POST request to upload the APK file using the provided upload URL
                response = requests.post(upload_url, files=files, headers={"x-apikey": API_KEY})

                if response.status_code == 200:
                    # Get the response data and process it
                    response_data = response.json()
                    resource_id = response_data.get('data', {}).get('id', '')
                    print(f"APK file {filename} successfully uploaded. Resource ID: {resource_id}")

                    # Add Resource ID to Collection
                    collection_url = f"https://www.virustotal.com/api/v3/collections/{Collection_ID}/items"
                    data = {
                        "items": [
                            {"type": "file", "id": resource_id}
                        ]
                    }
                    collection_response = requests.post(collection_url, json=data, headers=headers)
                    if collection_response.status_code == 200:
                        print(f"Resource added to collection {Collection_ID}")
                    else:
                        print(f"Failed to add resource to collection {Collection_ID}")

                else:
                    print(f"Failed to upload APK file {filename}. Status code: {response.status_code}")

        except FileNotFoundError:
            print(f"File {filename} not found.")
        except requests.exceptions.RequestException as req_exc:
            print(f"Request failed: {req_exc}")
        except Exception as e:
            print(f"Unknown error: {e}")