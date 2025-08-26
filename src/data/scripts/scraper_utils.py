from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By
import time

def scrape(url):
    # Set up the Firefox WebDriver
    service = Service("/opt/homebrew/bin/geckodriver")
    options = webdriver.FirefoxOptions()
    options.add_argument('--headless')
    driver = webdriver.Firefox(service=service, options=options)

    try:
        # Open the target page
        driver.get(url)

        # Wait for the page to load completely
        time.sleep(3)  # Adjust sleep time if necessary

        # Obtain all text from the page
        return driver.find_element(By.TAG_NAME, "body").text

        # Print the extracted text
        # print(page_text)

    finally:
        # Close the browser
        driver.quit()
