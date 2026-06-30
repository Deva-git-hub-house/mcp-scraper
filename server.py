import os
import requests
from bs4 import BeautifulSoup
from fastmcp import FastMCP

# Initialize FastMCP Server for Cloud Deployment
mcp = FastMCP("Live-Price-Scraper")

@mcp.tool()
def scrape_live_prices(url: str) -> str:
    """
    Scrapes the title and product price from a given e-commerce URL.
    Args:
        url: The full web page link of the product.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            return f'{{"error": "Failed to fetch page. HTTP Status Code: {response.status_code}"}}'
            
        soup = BeautifulSoup(response.text, "html.parser")
        
        # General selectors for scraping Title
        title_tag = soup.find("h1") or soup.find("span", {"id": "productTitle"})
        title = title_tag.get_text(strip=True) if title_tag else "Title Not Found"
        
        # General fallback placeholders for Price scraping
        price_tag = soup.find(class_="a-price-whole") or soup.find(class_="price") or soup.find(id="priceblock_ourprice")
        price = price_tag.get_text(strip=True) if price_tag else "Price Tag Not Detected"
        
        return f'{{"title": "{title}", "price": "{price}", "status": "Success"}}'
        
    except Exception as e:
        return f'{{"error": "Scraping loop exception: {str(e)}"}}'

if __name__ == "__main__":
    # Render cloud platform automatically injects a dynamic $PORT environment variable
    port = int(os.environ.get("PORT", 8000))
    # Run server using the standard 2026 Streamable HTTP infrastructure
    mcp.run(transport="http", host="0.0.0.0", port=port)
