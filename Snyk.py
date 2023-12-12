import json
import subprocess
import time
import os
import sys


def deal_with_json(json_file_path):
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)
        vulnerabilities = {}
    
        for j in data["vulnerabilities"]:
            
            if j["id"] not in vulnerabilities and "CVE" in j["identifiers"].keys() and 'severityWithCritical' in j.keys():
                if j["identifiers"]["CVE"] == []:
                     continue
                v = {}
                v['Vulnerability'] = j["identifiers"]["CVE"][0]
                v['Severity'] = j["severityWithCritical"]
                if "fixedIn" in j and len(j["fixedIn"])!=0:
                    v['Fixed'] = 1
                else:
                    v['Fixed'] = 0
                
                vulnerabilities[j["id"]] = v
                continue
        
    return vulnerabilities


total_start = time.time()
timeout = 480
image_txt = '10Kimage_nodup.txt'
runtime_txt = '10k_runtime.txt'

with open(image_txt, 'r') as file:
    content = file.read().split('\n')

while(content):
    rerun = []
    for i in content:
        start = time.time()
        name = i.replace("/","-")
        json_file_path = '10k_jsons/' + name + '.json'
        
        cmd = ["snyk", "container", "test", "-json", i]
        with open(json_file_path, "w") as f:
            start_time = time.time()
            try:
                subprocess.run(cmd, stdout=f)
            except:
                result = i + str(time.time()-start) +  " runing program error"
                print(result)
                with open(runtime_txt, 'a') as f:
                    f.write(result + '\n')
                continue
            end_time = time.time()
            if end_time - start_time > timeout:
                result = i + " " + str(end_time - start_time) +" failed (stuck)" 
                print(result)
                with open(runtime_txt, 'a') as f:
                    f.write(result + '\n')
                continue
        
        with open(json_file_path,'r') as f:
                try:
                    data = json.load(f)
                except:
                    result = i + " " + str(time.time()-start) + " getting data error"
                    print(result)
                    with open(runtime_txt, 'a') as f:
                        f.write(result + '\n')
                    continue
                if "error" in data.keys():
                    if "You have reached your pull rate limit" in data["error"]:
                        print(i + " " + str(time.time()-start) + " rerun")
                        rerun.append(i)
                        time.sleep(100)
                        continue
                    else:
                        result = i + " " + str(time.time()-start) + " failed (can't analyze)"
                        print(result)

                    with open(runtime_txt, 'a') as f:
                        f.write(result + '\n')
                    continue

        vulnerabilities = deal_with_json(json_file_path)
        data = []
        for v in vulnerabilities.values():
            data.append(v)
        image = {}
        image["Image"] = i
        image["Metadata"] = data

        with open('snyk_result.json','a') as f:
            json.dump(image, f, indent=2)
            f.write(",\n")

        end = time.time()

        print(i, end-start)
        with open(runtime_txt, 'a') as f:
            f.write(i +" "+ str(end-start) + '\n')
    
    content = rerun
