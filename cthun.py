# -*- coding: utf-8 -*-
# @File  : main.py
# @Date  : 2019/9/3
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import argparse
import sys
import time

from lib.RE_DATA import TOP_1000_PORTS_WITH_ORDER
from lib.bruteForce import main_interface
from lib.config import logger
from lib.portScan import GeventScanner

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="This script can scan port and service like nmap and bruteforce like hydra.result will store in result.log in same folder."
                    "progrem has default user/password dict inside,you can add extra users in user.txt and extra password in password.ext in same folder(one line one word)")
    parser.add_argument('-s', metavar='startip', help="Start IPaddress(e.g. '192.172.1.1')")
    parser.add_argument('-e', metavar='endip', help="End IPaddress(e.g. '192.172.1.255')")
    parser.add_argument('-t',
                        metavar='N',
                        help='Socket Timeout(second),default is 0.5', default=0.5, type=float)
    parser.add_argument('--maxsocket',
                        metavar='N',
                        help='Max sockets(100-1000),default is 1000', default=1000, type=int)

    parser.add_argument('--topports',
                        metavar='N',
                        help='The N most commonly used ports(e.g. 100)', default=0, type=int)
    parser.add_argument('--portlist', default=[],
                        metavar='N,N,N',
                        type=lambda s: [int(i) for i in s.split(",")],
                        help=("Port(s) to scan(e.g. '22,80,3389').Ports will add to topports args"),
                        )
    parser.add_argument('--bf', default=False,
                        metavar='1',
                        type=bool,
                        help=("Run brute force after portscan"),
                        )
    parser.add_argument('--no_default_dict', default=False,
                        metavar='1',
                        type=bool,
                        help=("do not use inside user/password dict,only user.txt,password.txt"),
                        )
    args = parser.parse_args()

    startip = args.s
    stopip = args.e

    if startip is None or stopip is None:
        print("[x] Please set Start IPaddress,End IPaddress.")
        parser.print_help()
        sys.exit(0)

    top_ports_count = args.topports
    if top_ports_count <= 0:
        top_ports_count = 0
    elif top_ports_count >= 1000:
        top_ports_count = 1000

    port_list = args.portlist

    if (len(port_list) == 0 or port_list is None) and top_ports_count == 0:
        print("[x] Please set topports or portlist.")
        sys.exit(0)

    top_port_list = TOP_1000_PORTS_WITH_ORDER[0:top_ports_count]
    for i in port_list:
        if i not in top_port_list:
            top_port_list.append(i)

    max_socket_count = args.maxsocket

    if max_socket_count <= 100:
        max_socket_count = 100
    elif max_socket_count >= 1000:
        top_ports_count = 1000
    timeout = args.t

    bf = args.bf
    no_default_dict = args.no_default_dict
    # 参数处理完成
    logger.info("----------------- Progrem Start ---------------------")
    logger.info("\nStartIP: {}\nEndIP: {}\nSocketTimeout: {}\nMaxsocket: {}\nPorts: {}".format(startip, stopip, timeout,
                                                                                               max_socket_count,
                                                                                               top_port_list))
    t1 = time.time()
    logger.info("----------------- PortScan Start --------------------")
    geventScanner = GeventScanner(max_socket_count=max_socket_count, timeout=timeout)
    portScan_result_list = geventScanner.aysnc_main(startip, stopip, top_port_list)
    t2 = time.time()

    logger.info("PortScan finish,time use : {}s".format(t2 - t1))
    logger.info("----------------- PortScan Finish --------------------")
    if bf:
        logger.info("----------------- BruteForce Start -------------------")
        main_interface(portScan_result_list, max_socket_count, timeout,no_default_dict)
        t3 = time.time()
        logger.info("BruteForce finish,time use : {}s".format(t3 - t2))
        logger.info("----------------- BruteForce Finish --------------------")
    logger.info("----------------- Progrem Finish ---------------------")
