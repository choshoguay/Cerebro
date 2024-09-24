import re

filename = 'U_MS_Windows_2012_Server_DNS_V2R11_STIG_28Jun2021_DDW.ckl'
pattern = r'\d{2}[A-Za-z]{3}\d{4}'

match = re.search(pattern, filename)

if match:
    print(f"Match found: {match.group()}")
else:
    print("No match found")