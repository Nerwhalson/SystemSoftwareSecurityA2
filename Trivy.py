import os
import json
from time import time

count = 0
data = []
with open('docker_images.txt', 'r') as file_list:
    start = time()
    for line in file_list:
        name = line.strip()
        trivy_command = f'trivy image --scanners vuln -f json -o result.json {name}'
        os.system(trivy_command)
        count += 1
        print(f'Finish detecting image {count}/10000.')
        
        with open(f'result.json', 'r') as file:
            image_data = {"Image": name, "Metadata": []}
            output = json.load(file)
            if 'Results' in output:
                for ele in output['Results']:
                    try:
                        for vuln in ele["Vulnerabilities"]:
                            vuln_data = {}
                            vuln_data["Vulnerability"] = vuln["VulnerabilityID"]
                            vuln_data["Severity"] = vuln["Severity"]
                            if vuln["Status"] == 'fixed':
                                vuln_data["Fixed"] = 1
                            else:
                                vuln_data["Fixed"] = 0
                            image_data["Metadata"].append(vuln_data)
                    except Exception as e:
                        print(name, e)
        data.append(image_data)
        if(count % 100 == 0):
            with open('trivy_5w.json', 'w') as file:
                json.dump(data, file, indent=4)
            
        end = time()
        print(f'Finish checking image {name}, took {end-start} seconds.')
    
    end = time()
    print(f"Checking 5k images takes {end-start} seconds.")