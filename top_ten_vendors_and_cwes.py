
import argparse
import datetime
import json
import os
import pandas as pd
import re
import requests
from getpass import getpass
from requests.exceptions import ConnectionError

def parse_args():
    parser = argparse.ArgumentParser(description="Retrieve vulnerabilities from VulnCheck KEV.")
    parser.add_argument('-k', '--key', dest='token', help='Prompt for API key (do not enter at command line). This argument will take priority over the .env file', 
                        nargs='?', const=None, required=False, default=os.environ["VULNCHECK_API_TOKEN"])
    parser.add_argument('-p', '--path', help='Path to write file. This argument will take priority over the .env file', 
                        required=False, default=os.environ["SAVE_PATH"])
    parser.add_argument('-o', '--output', dest='output', help='output file format', choices=['json', 'csv', 'excel', 'html'], required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.1')
    return parser.parse_args()

def get_vulns(token):
    '''
        Retrieve data from VulnCheck Community API endpoint.
        
        :param token: A string, API Key.
        :returns: a dict, JSON object of vulnerabilities.
        :raises: ConnectionError: if unable to successfully make GET request.
    '''

    url = "https://api.vulncheck.com/v3/index/vulncheck-kev"
    headers = {'Accept': 'application/json',
               'Authorization': f'Bearer {token}'}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print('unable to retrieve Vulns from VulnCheck' + response)
            exit()
        content = response.content
        data = json.loads(content)
        return data
    except ConnectionError as error:
        content = "No Response"
        raise error
    
def parse_vendors(data):
    '''
        Parse top 10 vendors

        :param data: a dict: VulnCheck community API response.
        :returns: a dict: parsed VulnCheck vendor data.
    '''

    #Extract a list of all vendors present in the output
    vendors = sorted(set([entry.get('vendorProject') for entry in data]))
    #Create a dictionary of vendors starting at a zero count
    vendor_count = {}
    for vendor in vendors:
        vendor_count[vendor] = 0
    #Increment count of vendor for each occurrence of the vendor
    for entry in data:
        instance = entry.get('vendorProject', None)
        if instance:
            vendor_count[instance] += 1
    #Reorder vendorCount by value
    vendor_count = sorted(vendor_count.items(), key=lambda x:x[1], reverse=True)
    #Create a list of top 10 vendors
    top_ten  = vendor_count[:10]
    #Append to vendor list if value of last vendor is tied with others that didn't make the top ten cut
    final_value = top_ten[-1][1]
    for entry in vendor_count[11:]:
        if entry[1] == final_value:
            top_ten.append(entry)
    top_vendors = []
    for vendor in top_ten:
        entry = {}
        entry['rank'] = top_ten.index(vendor) + 1
        entry['name'] = vendor[0]
        entry['occurrences'] = vendor[1]
        top_vendors.append(entry) 
    return top_vendors

def parse_cwes(vendor_list, data):
    '''
        Parse CWEs for each of the provided vendors in the vendorList and append to the report.

        :param data: a dict: VulnCheck vendor data from parse_vendors function.
        :param data: a dict: VulnCheck community API response.
        :returns: a dict: VulnCheck vendor data with CWEs added.
    '''
    for vendor in vendor_list:
        vendor['cwes'] = []
        for entry in data:
            if entry.get('vendorProject', '') == vendor['name']:
                for cwe in entry.get('cwes', []):
                    vendor['cwes'].append(cwe)
    # Deduplicate CWE list for each vendor
    for vendor in vendor_list:
        vendor['cwes'] = sorted(set(vendor['cwes']))
    return vendor_list

def enrich_cwe(vendor_list):
    '''
        Call CWE API to add additonal context for each of the provided CWEs

        :param data: a dict: VulnCheck vendor and CWE data from parse_cwes function.
        :returns: a dict: VulnCheck vendor data with enriched CWE information.
    '''
    
    for entry in vendor_list:
        for cwe in entry['cwes']:
            cwe_id = re.findall('CWE-([0-9]+)', cwe)[0]
            url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id}"
            headers = {'Accept': 'application/json',
                       'Content-Type': 'application/json'}
            try:
                response = requests.get(url, headers=headers)
                content = response.content
                data = json.loads(content)
                cwe_name = data['Weaknesses'][0].get('Name', '')
                entry['cwes'][entry['cwes'].index(cwe)] = f"{cwe}: {cwe_name}"
            except ConnectionError as error:
                pass
    return vendor_list

def output_format(format, file_name, data):
    ''' 
        Determine output format and call function to write appropriate file.
        
        :param format: A String, the desired output format.
        :param fileName: A String, the filename, minus extension.
        :param data: json data, file contents
        :returns None: Calls another function to write the file or prints the output.
    '''
    
    if format == 'json':
        file_name = f'{file_name}.json'
        write_file(file_name, json.dumps(data))
    elif format in ('csv', 'excel', 'html'):
        write_df(format, file_name, data)  
    else:
        for line in data:
            print(json.dumps(line, indent=4))
    
def write_df(format, file_name, data):
    '''
        Write contents to output file. 
    
        :param format: a string, excel, csv, or html
        :param fileName: a string, the filename, excluding extension.
        :param contents: json data, file contents.
        :raises: IOError: if unable to write to file.
    '''
    
    df = pd.DataFrame(data)
    try:
        if format == "excel":
            df.to_excel(f'{file_name}.xlsx', freeze_panes=(1,0), na_rep='NA')
        elif format == 'csv':
            df.to_csv(f'{file_name}.csv', na_rep='NA')
        else:
            df.to_html(f'{file_name}.html', render_links=True, na_rep='NA')
    except IOError as error:
        raise error
    
def write_file(file_name, contents):
    '''
        Write contents to output file. 
    
        :param fileName: a string, name for file including (optionally) file extension.
        :param contents: anything, file contents.
        :raises: IOError: if unable to write to file.
    '''

    try:
        with open( file_name, 'w') as o:
                    o.write(contents)
    except IOError as error:
        raise error
    
def main():
    args = parse_args()
    #Output report name; default uses UTC time
    file_name = f'{args.path}Top_Ten_Vendors_and_CWEs_Report_{str(datetime.datetime.now(datetime.timezone.utc))}'
    token = args.token
    if token == None:
        token = getpass(prompt="Enter your VulnCheck API Key: ")
    results = get_vulns(token)
    vendor_list = parse_vendors(results['data'])
    top_cwes = parse_cwes(vendor_list, results['data'])
    enriched = enrich_cwe(top_cwes)
    output_format(args.output, file_name, enriched)

if __name__ == "__main__":
    main()