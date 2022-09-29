import requests, re, os
from bs4 import BeautifulSoup
from googlesearch import search

def get_ransomware_gang():
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}
    #Creates a list to store all the ransomware gang group names
    ransom_grouplist = [] 
    #Perform a request to ransom-db.com to get the list of group names
    ransom_db_page = requests.get("https://www.ransom-db.com/ransomware-groups", headers=headers) 
    #Retrieve the response
    ransom_db_response = ransom_db_page.content 
    #Use BeautifulSoup to parse the response into lxml format
    ransom_soup = BeautifulSoup(ransom_db_response,'lxml') 
    #Retrieve all data in the <h4> tag, with id: myLargeModalLabel
    get_ransom_groupnames = ransom_soup.findAll("h4",{"id":"myLargeModalLabel"}) 
    #Cleaning the data
    words_to_remove = ['<h4 class="modal-title" id="myLargeModalLabel">','</h4>','[ ',' ]'] 
    for words in words_to_remove:
        get_ransom_groupnames = str(get_ransom_groupnames).replace(words,' ')
    get_ransom_groupnames = get_ransom_groupnames.split(',') #Splitting the entire string into a list based on the ',' delimiter
    for groupnames in get_ransom_groupnames: #Using a for loop to strip all whitespaces in each element and appending it to the ransom_grouplist
        ransom_grouplist.append(groupnames.strip(' '))
    ransom_victimTable = ransom_soup.find('table',attrs={'class':'table table-striped table-bordered table-sm'}) #Finding how many victims there are
    ransom_tableData = ransom_victimTable.findAll('td') #Extracting the data from the table data 
    search_ransomVictimCount = re.findall(r'center;"\>\d+\<\/td>',str(ransom_tableData)) #Using regex to match the number of victims
    search_ransomVictimCount = ','.join(search_ransomVictimCount) #Joining them as a string, to clean up the html tags
    stringsToRemove = ['<td>','</td>','center;">'] #Removing the html tags
    for strings in stringsToRemove:
        search_ransomVictimCount = search_ransomVictimCount.replace(strings,'')
    search_ransomVictimCount = search_ransomVictimCount.split(',') #Convert back to a list
    #Now with a list filled with the keys (Ransomware Gang Names) and values (Number of Victims),
    #Zip both lists and create a dictionary with the corresponding key and values
    ransomware_dict = dict(zip(ransom_grouplist,search_ransomVictimCount)) 
    return ransom_grouplist, ransomware_dict

def search_Ransomware_gang(grouplist):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}
    os.system('cls')
    cve_number_list = []
    sites_to_ignore = ['facebook','reddit','twitter','instagram','youtube','ctf']
    for groupname in grouplist:
        ransomwareSearchString = 'intitle:"{name}" & "ransomware" & "cve-" after:2015'.format(name=groupname) 
        for results in search(ransomwareSearchString, tld="com", num=20, start=0, stop=10, pause=2):
            for sites in sites_to_ignore:
                if sites in results:
                    results = ''
            print(results)
            try:
                ransomware_search_results = requests.get(results, headers=headers)
                response = ransomware_search_results.content
                soup = BeautifulSoup(response,'lxml')
                find_cve_numbers = re.findall(r"(?i)cve-\d{4}-\d+",str(soup))
                for numbers in find_cve_numbers:
                    if numbers.upper() not in cve_number_list and numbers.upper != None:
                        cve_number_list.append(numbers.upper())
            except:
                pass
    return cve_number_list
