import requests
from bs4 import BeautifulSoup
import pandas as pd
import json
import re

base_url = "http://books.toscrape.com/catalogue/page-{}.html"
books_data = []

for page in range(1, 51):  # There are 50 pages
    print(f"Scraping page {page}...")
    response = requests.get(base_url.format(page))
    soup = BeautifulSoup(response.text, 'html.parser')
    books = soup.select('.product_pod')

    for book in books:
        title = book.h3.a['title']
        price_raw = book.select_one('.price_color').text  # e.g. '£51.77'
        price_clean = re.sub(r'[^\d.]', '', price_raw)     # remove '£' or other symbols
        price = float(price_clean)

        availability = book.select_one('.availability').text.strip()
        rating = book.p['class'][1]  # class list: ['star-rating', 'Three']
        book_url = "http://books.toscrape.com/catalogue/" + book.h3.a['href']
        image_url = "http://books.toscrape.com/" + book.img['src'].replace('../', '')

        books_data.append({
            'Title': title,
            'Price': price,
            'Availability': availability,
            'Rating': rating,
            'Product Page URL': book_url,
            'Image URL': image_url
        })

# Save to CSV
df = pd.DataFrame(books_data)
df.to_csv('books_data.csv', index=False)

# Save to JSON
with open('books_data.json', 'w') as f:
    json.dump(books_data, f, indent=4)

print("Scraping completed and data saved to CSV and JSON.")