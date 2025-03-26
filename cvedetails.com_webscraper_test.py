from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

# Set up Chrome with the WebDriver Manager (automatically downloads and installs ChromeDriver)
service = Service(ChromeDriverManager().install())
options = webdriver.ChromeOptions()
options.add_argument('--headless')  # Run in headless mode (without opening a window)

# Create a WebDriver instance
driver = webdriver.Chrome(service=service, options=options)

# URL of the page you want to scrape
url = 'https://www.cvedetails.com/cve/CVE-2018-12896/'

# Navigate to the page
driver.get(url)

# Find the div by its ID and class
cve_summary_div = driver.find_element(By.ID, 'cvedetailssummary')

# Extract and print the text inside the div
cve_summary = cve_summary_div.text
print("CVE Summary: ", cve_summary)

# Close the browser
driver.quit()
