#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Dec 20 22:55:06 2017

@author: Qubyte
"""

from selenium import webdriver as wd

def fill_ans(answer):
    fld = driver.find_element_by_name('answer')
    fld.send_keys(answer[:-1])
    fld.submit()
    return

driver = wd.Firefox()

driver.get('https://www.hackthis.co.uk/')

fld1 = driver.find_element_by_id('username')
fld1.send_keys('your uname')

fld2 = driver.find_element_by_id('password')
fld2.send_keys('your pass')

fld2.submit()

driver.get('https://www.hackthis.co.uk/levels/coding/1')

jumble = driver.find_elements_by_tag_name('textarea')[0].text

wlist = jumble.split(' ')

wlist.sort()
answer = ' '.join(wlist)
print answer

if answer[-1] == ',':   #if it ends with comma take comma out
    fill_ans(answer[:-1])
else:                   #otherwise submit as is
    fill_ans(answer)
