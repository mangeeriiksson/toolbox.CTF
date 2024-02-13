import requests

# Ersätt 'YOUR_API_KEY_HERE' med din faktiska VirusTotal API-nyckel
API_KEY = input("Ange API nyckel")

def search_virustotal(file_hash):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)

    # Kontrollera om begäran lyckades
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            # Filen finns i VirusTotal databasen
            detections = result.get('positives', 0)
            total = result.get('total', 0)
            print(f'File hash: {file_hash}')
            print(f'Detections: {detections}/{total}')
            print(f'Scan results: {result["scans"]}')
        else:
            print(f'File hash: {file_hash} not found in VirusTotal database.')
    else:
        print('Failed to fetch data from VirusTotal.')

# Exempel på användning
file_hash = input("Ange filehash")  # Ersätt detta med den faktiska hashsumman du vill söka efter
search_virustotal(file_hash)
