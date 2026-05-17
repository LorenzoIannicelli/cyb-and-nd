import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
import matplotlib.pyplot as plt
import seaborn as sns
import time


url = "http://books.toscrape.com/catalogue/page-{}.html"

try:
    books_list = []

    for page_num in range(1,51):
        response = requests.get(url.format(page_num))
        time.sleep(0.5)

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

    avg_price = df["Price"].mean()
    min_price = df["Price"].min()
    max_price = df["Price"].max()

    print(f"Books analyzed: {len(df)}")
    print(f"Average price: £{avg_price:.2f}")
    print(f"Cheapest book: £{min_price:.2f}")
    print(f"Most expensive book: £{max_price:.2f}")

    fig, ax = plt.subplots(figsize=(10,6))

    sns.histplot(data=df, x="Price", bins=15, kde=True, color="skyblue", ax=ax)

    ax.axvline(avg_price, color="red", linestyle="--", linewidth=1.5, label=f"Average: £{avg_price:.2f}")

    ax.set_title("Distribution of Book Prices")
    ax.set_xlabel("Price (£)")
    ax.set_ylabel("Number of Books")
    ax.legend()

    plt.tight_layout()
    plt.show()

except Exception as e:
    print(f"Connection error: {e}")
    exit()
