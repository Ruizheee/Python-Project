header = ['Group Name','CVE','CVSS Version','Severity','Description','Weakness Enumeration','Attack Vector','Attack Complexity','Privileges Required','User Interaction','Confidentiality','Integrity','Availability','CPE String','"Advisories,Solutions,Tools"']
separator = ','
headerCheck = separator.join(header) 
print(headerCheck)
with open(r'E:\\Python Project\\testetept.csv', 'r+', newline='') as fileWrite:
    content = fileWrite.read()
    if headerCheck in content:
        print('ok')
    else:
        print('ok2')