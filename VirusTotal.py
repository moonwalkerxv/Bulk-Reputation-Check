"""
Auther  : Amol Anant Pandhare
Email   : pandhareamol96@gmail.com
"""


import os
import sys
import requests
import time
import argparse
import webbrowser
import signal
from argparse import RawTextHelpFormatter


from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

virustotal_headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
                      'Accept':'application/json',
                      'Accept-Language':'en-US,en;q=0.5',
                      'Accept-Encoding':'gzip, deflate',
                      'content-type':'application/json',
                      'X-Tool':'vt-ui-main',
                      'x-app-version':'v1x52x1',
                      'Accept-Ianguage':'en-US,en;q=0.9,es;q=0.8',
                      'Sec-Fetch-Dest':'empty',
                      'Sec-Fetch-Mode':'cors',
                      'Sec-Fetch-Site':'same-origin',
                      'Referer':'https://www.virustotal.com/',
                      'X-VT-Anti-Abuse-Header':'MTQ0MTIxNDQ5OTgtWkc5dWRDQmlaU0JsZG1scy0xNjM3MTUzNDMzLjUwNQ==',
                      'Cookie':'_ga=GA1.2.1301540161.1628839274; _gid=GA1.2.631260150.1637128398; _gat=1'}

vt_url = 'https://www.virustotal.com/ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={}'
RATE_LIMITING_THRESHOLD = 990



def get_http_response(_arg):
    """
    Function to get and return http response
    param: _arg (String)
    return: response (HTTP response object)
    """
    response = requests.get(vt_url.format(_arg), headers = virustotal_headers,verify=False)
    return response
    

def get_json_data(_arg):
    """
    Function to get all the details for ip / hash / domain
    param: _arg (String)
    return: http response (json)
    """
    
    try:    
        response = get_http_response(_arg)
        if response.status_code == 200:
            return response.json()
        
        if response.status_code == 429:
            # Opening the url in browser to complete captcha.
            # VirusTital ask to solve the captcha if user made more than certain number of requests from same IP.
            webbrowser.open_new('https://www.virustotal.com/gui/search/{}'.format(_arg))
            val = input('Have you solved the captcha ? (n/y):')
            if val in ['YES','yes','Y','y']:
                pass
            else:
                sys.exit(0)

            response = get_http_response(_arg)
            if response.status_code == 200:
                return response.json()
            else:
                return None
    
        else:
            print("Found unhandeled response: status code - {response.status_code} - {response.text}")
            print("Need to handle this condition.")
            return None
    except Exception as ex:
        print(f"[-] Exception : {ex}")



def parse_virustotal_intel(http_response):
    """
    Function to parse the http response from virus total and
    collect ip intel.
    return: results {json}
    """
    results = {'found':'no', 'reported_count': 0}

    if not http_response:
        return results

    try:
        cnt = int(http_response['data'][0]['attributes']['last_analysis_stats']['malicious']) + int(http_response['data'][0]['attributes']['last_analysis_stats']['suspicious'])
    
        results.update({'found':'yes', 'reported_count': cnt})
    except IndexError:
        return results

    return results


def read_file(filename):
    """
    Function to read the input file.
    return: list of items in the file.
    """
    with open(filename,'r') as rf:
        data = rf.readlines()
        
    data = [x.strip('\n').strip(',').strip() for x in data ]
    
    return data
    
def check_for_rate_limit(c, start_time):
    """
    Function to wait for the required time when 1000 requests are made within an hour.
    This threshold might change in future. 
    """
    if c >= int(RATE_LIMITING_THRESHOLD):
        print("Warning : Allowed requeests /hr limit is about to exceed. checking for time window.")
        current_time = time.time()
        time_taken_to_reach_threshold = int(current_time) - int(start_time)
        if time_taken_to_reach_threshold < 3600:
            sleep_time = 3660 - (int(current_time) - int(start_time))
            print(f"Sleeping for {int(sleep_time/60)} minutes. You can press Ctrl + c and try after sleep time. Use -n <cnt> to skip the processed lines")
            time.sleep(sleep_time)
           
        c = 1
    return c

def signal_handler(sig, frame):
    print('You pressed Ctrl+c!')
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(description='\n\tExamples: python virus_total.py -f <text file>',
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument('-f','--file',dest='file', required=True, help='Input File path')
    parser.add_argument('-T','--threshold',dest='threshold',default=0,required=False,help='Output will be printed if it\'s reported count is more than threshold. Default is 0')
    parser.add_argument('-s','--sleep',dest='sleep',default=1,required=False,help='Sleep time between two requests. Default is 1 Sec.')
    parser.add_argument('-n','--skip-lines',dest='skip',default=0,required=False,help='Number of lines to be skipped from processing. This will be helpful if you have processed few lines successfully and then encounterd an error.')
    parser.add_argument('-M','--only-malicious',action='store_true',dest='only_malicious',default=False,required=False,help='Only prints malicious ips')
    
    
    args = parser.parse_args()
    
    print("Starting virus_total-1.1")
    print(args)
    
    if len(sys.argv) == 1:
        print(parser.print_help())
        sys.exit(0)
    
    data = list()
    
    if int(args.threshold) > 0:
        args.only_malicious = True
    
    if args.file:
        if not os.path.exists(args.file):
            print(f'[-] File not exist - {args.file}')
            sys.exit(0)
            
        data = read_file(args.file)
        

    if data:
        c = 0
        p = 1
        start_time = time.time()
        print("\nCnt, Category, Item, Reported By")
        for item in data:
            # Skipping the blank lines in the input file.
            if not item:
                continue
            c += 1
            if c <= int(args.skip):
                continue
            
            # Checking for rate limiting after each request.
            p = check_for_rate_limit(p, start_time)
            intel = None
            try:
                # Get all the intels about the IP/ Domain / Hash
                res = get_json_data(item)

                # Extract sum of suspicious and malicious reports.
                intel = parse_virustotal_intel(res)
            except Exception:
                print(f"{p}, Malicious, {item}, recheck")
                pass
            
            # Printing the results.
            if intel and 'reported_count' in intel:
                if int(intel['reported_count']) >= int(args.threshold) and int(intel['reported_count']) > 0:
                    print(f"{p}, Malicious, {item}, {intel['reported_count']}")
                elif not args.only_malicious and intel['found'] == 'yes':
                    print(f"{p}, Clean, {item}, 0")
                elif intel['found'] == 'no':
                    print(f"{p}, Not Found, {item}, -")
                
            time.sleep(args.sleep)
            p += 1
