import random
def random_userAgent():
    user_agentList = [
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
            'Mozilla/5.0 (X11; Linux i686; rv:105.0) Gecko/20100101 Firefox/105.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36'
    ]
    user_agent = random.choice(user_agentList)
    headers = {'User-Agent': user_agent}
    return headers