# -*- coding: utf-8 -*-
# @File  : main.py
# @Date  : 2019/9/3
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import argparse
import datetime
import sys
import time

from gevent.pool import Pool

from lib.config import logger
from portscan.RE_DATA import TOP_1000_PORTS_WITH_ORDER

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="This script can scan port&service like nmap and bruteforce like hydra."
                    "result will store in result.log in same folder."
                    "progrem has default user/password dict inside,"
                    "you can add extra users in user.txt and extra password in password.ext in same folder"
                    "(one line one word)")
    parser.add_argument('-s', metavar='startip', help="Start IPaddress(e.g. '192.172.1.1')", required=True)
    parser.add_argument('-e', metavar='endip', help="End IPaddress(e.g. '192.172.1.255')", required=True)
    parser.add_argument('-p', '--ports',
                        default=[],
                        metavar='N,N',
                        type=lambda s: [i for i in s.split(",")],
                        help="Port(s) to scan(e.g. '22,80,1-65535').",
                        )
    parser.add_argument('-tp', '--topports',
                        metavar='N',
                        help='The N most commonly used ports(e.g. 100).',
                        default=0,
                        type=int)
    parser.add_argument('-t', '--sockettimeout',
                        metavar='N',
                        help='Socket Timeout(second),default is 0.5',
                        default=0.5,
                        type=float)
    parser.add_argument('-ms', '--maxsocket',
                        metavar='N',
                        help='Max sockets(100-1000),default is 1000',
                        default=1000,
                        type=int)
    parser.add_argument('-hs', '--http_scan', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Advance scan http(s) services,get title,status code and website techs",
                        )
    parser.add_argument('-bf', '--bruteforce',
                        default=[],
                        metavar='STR,STR',
                        type=lambda s: [i for i in s.split(",")],
                        help="Bruteforce Protocols after portscan.(e.g. 'all,ftp,ssh,rdp,vnc,smb,mysql,mssql,postgresql,redis,mongodb,memcached')",
                        )
    parser.add_argument('-nd', '--no_default_dict', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="do not use default user/password dict,only user.txt,password.txt",
                        )

    args = parser.parse_args()

    startip = args.s
    stopip = args.e

    # 端口扫描
    if startip is None or stopip is None:
        print("[x] Please set Start IPaddress,End IPaddress.")
        parser.print_help()
        sys.exit(0)

    top_ports_count = args.topports
    if top_ports_count <= 0:
        top_ports_count = 0
    elif top_ports_count >= 1000:
        top_ports_count = 1000

    port_list = []
    ports_str = args.ports
    for one in ports_str:
        try:
            if len(one.split("-")) == 2:
                start_port = int(one.split("-")[0])
                end_port = int(one.split("-")[1])
                for i in range(start_port, end_port + 1):
                    if i not in port_list and (0 < i <= 65535):
                        port_list.append(i)
            else:
                i = int(one)
                if i not in port_list and (0 < i <= 65535):
                    port_list.append(i)
        except Exception as E:
            pass

    top_port_list = TOP_1000_PORTS_WITH_ORDER[0:top_ports_count]
    for i in port_list:
        if i not in top_port_list:
            top_port_list.append(i)

    if len(top_port_list) <= 0:
        print("[x] Please set ports or topports.")
        parser.print_help()
        sys.exit(0)

    max_socket_count = args.maxsocket

    if max_socket_count <= 100:
        max_socket_count = 100
    elif max_socket_count >= 1000:
        top_ports_count = 1000
    timeout = args.sockettimeout

    logger.info("----------------- Progrem Start ---------------------")
    logger.info(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    logger.info("----------------- PortScan Start --------------------")
    logger.info("StartIP: {}\nEndIP: {}\nSocketTimeout: {}\nMaxsocket: {}\nPorts: {}".format(startip, stopip, timeout,
                                                                                             max_socket_count,
                                                                                             top_port_list))
    pool = Pool(max_socket_count)
    t1 = time.time()
    from portscan.portScan import GeventScanner

    geventScanner = GeventScanner(max_socket_count=max_socket_count, timeout=timeout)
    portScan_result_list = geventScanner.aysnc_main(startip, stopip, top_port_list, pool)
    t2 = time.time()

    logger.info("PortScan finish,time use : {}s".format(t2 - t1))
    logger.info("----------------- PortScan Finish --------------------")
    # web扫描
    http_scan = args.http_scan
    if http_scan is not False:
        from httpcheck.httpCheck import http_interface

        logger.info("----------------- HttpCheck Start ----------------------")
        t3 = time.time()
        http_interface(portScan_result_list, timeout, pool)
        t4 = time.time()
        logger.info("HttpCheck finish,time use : {}s".format(t4 - t3))
        logger.info("----------------- HttpCheck Finish ---------------------")
    # 暴力破解
    bf = args.bruteforce
    no_default_dict = args.no_default_dict
    if no_default_dict is not False:
        no_default_dict = True

    proto_list_all = ['ftp', 'ssh', 'rdp', 'smb', 'mysql', 'mssql', 'redis', 'mongodb', 'memcached',
                      'postgresql', 'vnc']
    proto_list = []
    for proto in bf:
        if proto.lower() == "all":
            proto_list = proto_list_all
            break
        elif proto.lower() in proto_list_all:
            proto_list.append(proto.lower())

    if len(proto_list) > 0:
        from bruteforce.bruteForce import bruteforce_interface

        t2 = time.time()
        logger.info("----------------- BruteForce Start -------------------")
        logger.info("Protocols: {}\nNo_default_dict: {}".format(proto_list, no_default_dict))
        bruteforce_interface(portScan_result_list, timeout, no_default_dict, proto_list, pool)
        t3 = time.time()
        logger.info("BruteForce finish,time use : {}s".format(t3 - t2))
        logger.info("----------------- BruteForce Finish --------------------")

    logger.info("----------------- Progrem Finish -----------------------\n\n")
