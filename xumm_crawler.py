from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.select import Select

import time


URL = 'https://xumm.community/tokens'
driver = webdriver.Edge(executable_path= 'd:\lsis\edgedriver_win64\msedgedriver.exe')
driver.get(url = URL)
element = None


time.sleep(10)

try:
    # element = WebDriverWait(driver, 5).until(
    #     EC.all_of(
    #         EC.presence_of_element_located((By.CLASS_NAME , 'ng-tns-c185-1'))
    #     )
    # )

    # check box click 
    check_box = driver.find_element(By.ID, 'mat-checkbox-1').click()
    # check_box.send_keys(Keys.ENTER)  # 대안 
    # driver.execute_script("arguments[0].click();", check_box) # 대안  

    # angular combobox 의 경우 combobox click, 후 메뉴 클릭 해줘야 함 
    # combobox click 
    WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.ID, "mat-select-0"))).click()
    # driver.find_element(By.ID, 'mat-select-0').click()

	# 100 선택 
    WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.ID, "mat-option-4"))).click()
    # driver.find_element(By.ID, 'mat-option-4').click()


    # token name 추출

    for i in range(2, 102):
        row = driver.find_element(By.CSS_SELECTOR,'#cdk-accordion-child-3 > div > div > div:nth-child(4) > mat-table > mat-row:nth-child({})'.format( i ) )
        currency_name = row.find_element(By.CSS_SELECTOR, 'mat-cell.mat-cell.cdk-cell.cdk-column-currency.mat-column-currency.ng-tns-c185-1.ng-star-inserted > span:nth-child(1) > label' ).text
        amount = row.find_element(By.CSS_SELECTOR, 'mat-cell cdk-cell cdk-column-amount mat-column-amount ng-tns-c185-1 ng-star-inserted > span:nth-child(1) > label' ).text
        num_of_trust_lines = row.find_element(By.CSS_SELECTOR, 'mat-cell cdk-cell cdk-column-trustlines mat-column-trustlines ng-tns-c185-1 ng-star-inserted >  span:nth-child(1) > label' ).text
        current_dex_offers = row.find_element(By.CSS_SELECTOR, 'mat-cell cdk-cell cdk-column-offers mat-column-offers ng-tns-c185-1 ng-star-inserted >  span:nth-child(1) > label' ).text
        link = ''
        # link = row.find_element(By.CSS_SELECTOR, 'mat-cell cdk-cell cdk-column-link mat-column-link ng-tns-c185-1 ng-star-inserted > label' ).text

        print(currency_name, amount, num_of_trust_lines, current_dex_offers, link)


    # issued value 추출

    # number of trustline 추출 

    # current dex offers 추출 

    # trustline 추출

    # explorers 추출 

    # select = Select(WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "mat-select-vaule-1"))))
    # select.select_by_value("100")


    pass
except Exception as e:
    print(e)
    pass

else:
    pass
    # driver.quit()
# if response.status_code == 200:
# 	html = response.text
# 	soup = BeautifulSoup(html, 'html.parser')
# 	data_list = soup.find_all('label', 'ng-tns-c185-1')
# 	print(title)
# else : 
# 	print(response.status_code)