import requests
from bs4 import BeautifulSoup
import pandas as pd
import re


url = "http://books.toscrape.com/catalogue/page-{}.html"

try:
    books_list = []

    for page_num in range(1,6):
        response = requests.get(url.format(page_num))

        if response.status_code != 200:
            print(f"Unexpected status code: {response.status_code}")
            break

        soup = BeautifulSoup(response.text, "html.parser")
        # print(soup.title.get_text())

        books = soup.find_all("article", class_="product_pod")
        # print(f"Found {len(books)} books")
        # print(books[0])

        for book in books:
            title = book.h3.a["title"]
            price_txt = book.find("p", class_="price_color").get_text()
            price_clean = float(re.sub(r'[^\d.]', '', price_txt))

            books_list.append({
                "Title": title,
                "Price": price_clean
            })

        print(f"Page {page_num}: scraped {len(books)} books")

    df = pd.DataFrame(books_list)
    print(df.head())

except Exception as e:
    print(f"Connection error: {e}")
    exit()
