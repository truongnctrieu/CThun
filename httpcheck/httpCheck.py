# -*- coding: utf-8 -*-
# @File  : test.py
# @Date  : 2019/9/9
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import logging

import gevent
import requests
from bs4 import BeautifulSoup
from gevent.monkey import patch_all

from httpcheck.wappalyzer.wappalyzer import Wappalyzer, WebPage
from lib.config import logger


class HttpScanner(object):

    def __init__(self):
        self.wappalyzer = Wappalyzer.latest()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            "Connection": "keep-alive",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            "Accept-Language": "zh-CN,zh;q=0.8",
            # 'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }

    def check_website_alive(self, website=None):
        if website.startswith('https://') or website.startswith('http://'):
            entireUrl = website
        else:
            entireUrl = "http://{}".format(website)
        try:
            logging.captureWarnings(True)
            response = requests.get(entireUrl,
                                    verify=False,
                                    headers=self.headers,
                                    timeout=5
                                    )
            response.encoding = response.apparent_encoding
        except Exception as E:
            return False, None
        return True, response

    def logger_website(self, portScan_result, website, title, wappalyzer_list,response):
        tech_list = []
        for one in wappalyzer_list:
            tech_list.append("{}:{}".format(one.get("name"), one.get("version")))
        try:
            vendorproductname = portScan_result.get("data").get("versioninfo").get("vendorproductname")[0]
            if len(portScan_result.get("data").get("versioninfo").get("version")) > 0:
                version = portScan_result.get("data").get("versioninfo").get("version")[0]
            else:
                version = None
            tech_list.append("{}:{}".format(vendorproductname, version))
        except Exception as E:
            pass

        logger.warning("WebSite   : {}".format(website))
        logger.warning("StatusCode: {}".format(response.status_code))
        logger.warning("Title     : {}".format(title.encode("utf-8")))
        logger.warning("Tech      : {}".format(tech_list))
        logger.warning("----------------------------------------------")

    # ssl/http http
    def test(self, portScan_result):
        # 处理头
        if portScan_result.get("service") == "http":
            website = "http://{}:{}".format(portScan_result.get("ipaddress"), portScan_result.get("port"))
        elif portScan_result.get("service") == "ssl/http":
            website = "https://{}:{}".format(portScan_result.get("ipaddress"), portScan_result.get("port"))
        else:
            return
        flag, response = self.check_website_alive(website)
        if flag is not True:
            return

        # 解析title
        wappalyzer_list = []
        title = ""
        try:
            parsed_html = BeautifulSoup(response.text, 'html.parser')
            rew_title = parsed_html.find_all('title')
            title = rew_title[0].text
            try:
                webpage = WebPage(response)
                wappalyzer_list = self.wappalyzer.analyze_with_categories(webpage)
            except Exception as E:
                pass
        except Exception as E:
            pass
        self.logger_website(portScan_result=portScan_result, website=website, title=title,
                            wappalyzer_list=wappalyzer_list,response=response)


def http_interface(portScan_result_list, timeout, pool):
    patch_all()
    httpScanner = HttpScanner()
    tasks = []
    pool = pool
    for portScan_result in portScan_result_list:
        if portScan_result.get("service") in ["http", "ssl/http"]:
            task = pool.spawn(httpScanner.test, portScan_result)
            tasks.append(task)
    gevent.joinall(tasks)
