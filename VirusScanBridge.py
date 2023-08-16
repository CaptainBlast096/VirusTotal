import virustotal_python # VirusTotal API
import os # For file path

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
    # Will open the file and read it
    with open(apk_directory, 'rb') as file:
        files = {'file' : (os.path.basename(apk_directory), file)}
        response = virusTotal.request("files", files=files)
        # Print the responses
        print(response.json())
