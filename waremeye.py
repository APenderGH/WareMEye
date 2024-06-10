import requests
import sys
import argparse
from termcolor import colored
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(prog="WareMEye", description="Try all the IP spoofing headers at once.")
parser.add_argument("targets_file", type=argparse.FileType('r'), help="File containing a line separated list of targets.")
parser.add_argument("-i", dest="user_ip", help="The IP to spoof.")
parser.add_argument("-x", dest="user_proxy", help="Proxy to use.")
args = parser.parse_args()

spoofing_ip = args.user_ip if (args.user_ip != None) else '127.0.0.1'
ip_rewrite_headers_list = [
    "X-Originating-IP",
    "X-Forwarded-For",
    "X-Forwarded",
    "Forwarded-For",
    "X-Forwarded-Host",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-ProxyUser-Ip",
    "X-Original-URL",
    "Client-IP",
    "X-Client-IP",
    "X-Host",
    "True-Client-IP",
    "Cluster-Client-IP"
]
ip_rewrite_headers = {}
for ip_rewrite_header in ip_rewrite_headers_list:
    ip_rewrite_headers.update({ip_rewrite_header: spoofing_ip})

headers = {}
cookies = {}
proxies = {"http":args.user_proxy, "https":args.user_proxy} if (args.user_proxy != None) else {}

test_case_msg = r"{0}: Status codes ({1}) - Body lengths ({2})"

def get_request(url):
    return {
        "without_ip_headers": requests.get(url, headers=headers, cookies=cookies, proxies=proxies, verify=False),
        "with_ip_headers": requests.get(url, headers=headers | ip_rewrite_headers, cookies=cookies, proxies=proxies, verify=False)
    }

def run_standard_testcase(file):
    with open(file.name) as targets:
        for target in targets:
            target = target.strip()
            r = get_request(target)
            
            if (r["with_ip_headers"].status_code != r["without_ip_headers"].status_code):
                status_code_msg = colored(f"with: {r['with_ip_headers'].status_code}, without: {r['without_ip_headers'].status_code}", 'yellow')
            else:
                status_code_msg = colored(f"with: {r['with_ip_headers'].status_code}, without: {r['without_ip_headers'].status_code}", 'light_grey')
            
            if (len(r["with_ip_headers"].content) != len(r["without_ip_headers"].content)):
                blength_msg = colored(f"with: {len(r['with_ip_headers'].content)}, without: {len(r['without_ip_headers'].content)}", 'yellow')
            else:
                blength_msg = colored(f"with: {len(r['with_ip_headers'].content)}, without: {len(r['without_ip_headers'].content)}", 'light_grey')

            print(test_case_msg.format(target, status_code_msg, blength_msg))
    return


if __name__ == "__main__":
    run_standard_testcase(args.targets_file)
