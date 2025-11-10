import requests
import sys
from bs4 import BeautifulSoup

def get_port_info(port_number: int) -> dict | None:
    """
    Correctly scrape port information from speedguide.net.
    """
    url = f"https://www.speedguide.net/port.php?port={port_number}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find the correct table by class="port"
    table = soup.find('table', class_='port')
    if not table:
        print("Could not find table with class 'port'")
        return None

    # Extract all rows
    rows = table.find_all('tr')
    if len(rows) < 2:
        print("Not enough rows in table")
        return None

    # First row contains headers
    header_row = rows[0]
    headers = [th.get_text(strip=True).replace('(s)', '') for th in header_row.find_all('th')]
    # Result: ['Port', 'Protocol', 'Service', 'Details', 'Source']

    port_data = {}

    # Process each data row (skip the header)
    for i, row in enumerate(rows[1:]):
        cells = row.find_all('td')
        if len(cells) == len(headers):
            # Take the first row of data (or you can collect all)
            if i == 0:  # Use first result (SG) for simplicity
                for j, cell in enumerate(cells):
                    key = headers[j]
                    value = cell.get_text(separator=' ', strip=True)
                    port_data[key] = value
                break  # Only use first data row

    return port_data if port_data else None

# Test it
if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    
    port = sys.argv[1]
    info = get_port_info(port)
    print("Result:", info)
    if info:
        for key, value in info.items():
            print(f"{key}: {value}")