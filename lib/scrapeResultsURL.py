from bs4 import BeautifulSoup
from time import sleep
import requests, re
import lib.setRandomUserAgent as getRandomUserAgent
def scrape_URL(searchKeywords,pages):
    urlList = []
    nextPageList = []
    headers = getRandomUserAgent.random_userAgent()
    base = "https://www.google.com.sg"
    fullGroupLink = f"https://www.google.com/search?q=intitle%3A%22{searchKeywords}%22+%22ransomware%22+%22cve-%22&lr=lang_en&safe=images&biw=1920&bih=813&tbs=lr%3Alang_1en"
    res = requests.get(fullGroupLink, headers=headers)
    resSoup = BeautifulSoup(res.text,"lxml")
    findlinks = resSoup.findAll("div",{"class":"yuRUbf"})
    links = re.findall('href=\"https\:\/\/\S+',str(findlinks))
    words_to_remove = ['href="','"','><br/>','<h3','><span','amp;']
    for words in words_to_remove:
        for link_with_group in range(len(links)):
            links[link_with_group] = links[link_with_group].replace(words,'') 
    for url in links:
        urlList.append(url)
    table = resSoup.find('table',attrs={'class':'AaVjTc'})
    if pages > 1:
        for page in range(1,int(pages)+1):
            sleep(5)
            pageNumber = 'Page {}'.format(page)
            tableData = table.find_all(attrs={'aria-label':pageNumber})
            nextLink = re.findall('href=\"\/search\S+',str(tableData))
            if nextLink:
                for words in words_to_remove:
                    for index in range(len(nextLink)):
                        nextLink[index] = nextLink[index].replace(words,'')
                        nextFullLink = base + nextLink[index]
                nextPageList.append(nextFullLink)
        for nextURLs in nextPageList:
            sleep(10)
            headers = getRandomUserAgent.random_userAgent()
            nextReq = requests.get(nextURLs, headers=headers)
            nextSoup = BeautifulSoup(nextReq.text,'lxml')
            find_nextLinks = nextSoup.findAll("div",{"class":"yuRUbf"})
            nextLinks = re.findall('href=\"https\:\/\/\S+',str(find_nextLinks))
            for words in words_to_remove:
                for indexes in range(len(nextLinks)):
                    nextLinks[indexes] = nextLinks[indexes].replace(words,'')
            for nextURL in nextLinks:
                urlList.append(nextURL)
        return urlList
    else:
        return urlList


