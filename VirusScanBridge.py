import virustotal_python # VirusTotal API
import os # For file path

# VirusTotal API Key
API_KEY = '6bf043675b60ab5626d10857b580e9456e415bbff9223f88258b77b2e85dc85b'

# VirusTotal Instance
virusTotal = virustotal_python.Virustotal(API_KEY)

# Since its a directory with multiple files I need to iterate through the file
apk_directory = r'C:\Users\jalee\PycharmProjects\APK'
for filename in os.listdir(apk_directory):

