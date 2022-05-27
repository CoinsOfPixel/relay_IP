from bs4 import BeautifulSoup
import requests
import json
import re
from shodan import Shodan

sho_api = Shodan('YOUR API')

#First we list everything
col_info_lst = []

#Then we clean it
last_utx_lst = []

#List with all the collected and cleaned IP's
relay_ip_list = []

#Prepare the IP's to get scanned by Shodan
prep_for_sho = {}

#List the IP's opened doors
open_doors_list = []

#Scrapping blockchain.com blockexplorer to get the last 10 transactions
blockchain_URL = "https://www.blockchain.com/btc/unconfirmed-transactions"

pg_bc = requests.get(blockchain_URL, headers={'User-Agent': 'Mozilla/5.0'})
soup = BeautifulSoup(pg_bc.text, 'html.parser')

"""
Number of utx to collect. Always showing the last 10 utx
Always put +1 above the amount you want. If you want 10, then put 11, if you want 100, then put 101 and so on.
But why 40 if you want only 10? Because it's returning more than just tx hash. It's showing:
7)Total in BTC
8)Value in $
9)5747545ffc035e81385904210aa9f91079274b65a9e3fab96c290dfc5344c7d1
10)Time
I tried 44, 43, 42, 41 and only got success with 40
"""
numer_of_tx = 40
#To the loop
tt_found = 0

#Scrappy assets list and get name
dv_utx = soup.find_all("div", {'class': 'PtIAf'})
col_info = soup.find('a')

for col_info in dv_utx:
    tt_found += 1
    if tt_found < numer_of_tx:
        txt_from_col_info = col_info.get_text()
        col_info_lst.append(txt_from_col_info)
    else:
        break

#Now, cleaning the finds with regex
rg_patter = "(^[a-fA-F0-9]{64}$)"
n_of_match = 0

for i in col_info_lst:
    rg_find = re.findall(rg_patter, i)
    if rg_find:
        #Now we can add the cleaned hash to the list. The * remove brackets from list
        last_utx_lst.append(*rg_find)
        n_of_match += 1

#Once collected all the IP's from the hash list, we then try to get the relay IP.
#I said "try to get" because not all the hashs will have the IP. Also, sometimes Blockcypher limits us for a certain period of
#time. We have to wait a few hours until we get whitelisted again. If you get blacklisted, the script will return nothing in the IP search
#step. If you enable the debug... I mean, the comments below, you gonna see "[] 0" as output in terminal.

for i in last_utx_lst:
    bc_URL = "https://api.blockcypher.com/v1/btc/main/txs/" + str(i)
    url_r = requests.get(bc_URL)
    text = url_r.text
    data = json.loads(text)
    try:
        has_ip = data['relayed_by']
        remove_ports = has_ip.split(':')[0]
        relay_ip_list.append(remove_ports)
    except KeyError:
        print("Oops")

#We now have the IP's. Time to scan them. I'm going to use Shodan API, but you can do a deep scan using free tools
#like Nmap, dir/gobuster, etc. Use your creativity to improve the code.
#PS: https://developer.shodan.io/api

for i in relay_ip_list:
    prep_for_sho[i] = [
        [80, "HTTP"],
        [443, "HTTPS"],
        [8080, "HTTP"],
        [9001, "Tor"],
        [9031, "Tor"],
        [22, "SSH"],
        [6667, "Tor"],
        [81, "Webserver"],
        [8545, "Eth node"],
        [3389, "RDP"],
        [8333, "Tor"],
    ],

for i in prep_for_sho:
    scan = sho_api.scan(ips=i, force=False)
    scan_rs = "IP -> " + str(i) + " = Scan result: " + str(scan)
    open_doors_list.append(scan_rs)

print(str(open_doors_list))

"""
sho_api_status = sho_api.info()
print("-> You have " + str(sho_api_status['scan_credits']) + " credits disponible.")

print("Information about collected UTX")
print(str(last_utx_lst))
print(len(last_utx_lst))
print("Information about IP's")
print(str(relay_ip_list))
print(len(relay_ip_list))
print("Information about Shodan")
print(str(prep_for_sho))
print(len(prep_for_sho))
print(str(open_doors_list))
print(len(open_doors_list))
"""

