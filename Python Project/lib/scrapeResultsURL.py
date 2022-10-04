from bs4 import BeautifulSoup
import requests, time, re

def scrape_URL(searchKeywords, pages):
    urlList = []
    nextPageList = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'
    }
    base = "https://www.google.com.sg"
    link = "https://www.google.com.sg/search?q="
    fullLink = link + searchKeywords
    res = requests.get(fullLink, headers=headers)
    resSoup = BeautifulSoup(res.text,"lxml")
    findlinks = resSoup.findAll("div",{"class":"yuRUbf"})
    links = re.findall('href=\"https\:\/\/\S+',str(findlinks))
    words_to_remove = ['href="','"','<br/>','<h3','><span','amp;']
    for words in words_to_remove:
        for number in range(len(links)):
            links[number] = links[number].replace(words,'')
    for url in links:
        urlList.append(url)
    table = resSoup.find('table',attrs={'class':'AaVjTc'})
    if pages > 1:
        for page in range(2,int(pages)):
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
            time.sleep(3)
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
    

