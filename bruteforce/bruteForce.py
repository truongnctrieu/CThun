# -*- coding: utf-8 -*-
# @File  : main.py
# @Date  : 2019/9/1
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf

import Queue
import binascii
import json
import threading
import time
from ftplib import FTP

from bruteforce.password import Password_total
from lib.config import *

SSL_FLAG = True

try:
    import bmemcached
    import pymongo
    import pymysql
    import redis
    from pssh.clients import ParallelSSHClient
    from impacket.smbconnection import SMBConnection
except Exception as E:
    logger.exception(E)
try:
    from bruteforce.rdp_check import check_rdp
    import psycopg2
except Exception as E:
    SSL_FLAG = False

import gevent
from Crypto.Cipher import DES
from gevent import socket
from gevent.monkey import patch_all


class SSH_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        parallel_logger = logging.getLogger("parallel")
        parallel_logger.setLevel('CRITICAL')
        for user_passwd_pair in user_passwd_pair_list:
            try:
                client = ParallelSSHClient(hosts=[ipaddress], port=port, user=user_passwd_pair[0],
                                           password=user_passwd_pair[1], num_retries=0, timeout=self.timeout)
                output = client.run_command('whoami', timeout=self.timeout)
                log_success("SSH", ipaddress, port, user_passwd_pair)
            except Exception as E:
                logger.debug('AuthenticationException: ssh')
                continue
            finally:
                pass


class FTP_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        fp = FTP(timeout=self.timeout)

        for user_passwd_pair in user_passwd_pair_list:
            try:
                banner = fp.connect(ipaddress, int(port))
            except Exception as E:
                logger.debug('ConnectException: %s' % E)
                return
            try:
                resp = fp.sendcmd('USER ' + user_passwd_pair[0])
                resp = fp.sendcmd('PASS ' + user_passwd_pair[1])
                resp = fp.sendcmd('PWD')
                log_success("FTP", ipaddress, port, user_passwd_pair)
            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue
            finally:
                fp.close()


class RDP_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        for user_passwd_pair in user_passwd_pair_list:
            try:
                flag = check_rdp(ipaddress, port, user_passwd_pair[0], user_passwd_pair[1], "", timeout=self.timeout)
                if flag:
                    log_success("RDP", ipaddress, port, user_passwd_pair)
            except Exception as E:
                logger.debug('ConnectException: {} {} {}'.format(E, ipaddress, port))
                return


class SMB_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        for user_passwd_pair in user_passwd_pair_list:
            try:
                fp = SMBConnection('*SMBSERVER', ipaddress, sess_port=int(port), timeout=self.timeout)
            except Exception as E:
                logger.debug('ConnectException: {} {} {}'.format(E, ipaddress, port))
                return
            try:
                if fp.login(user_passwd_pair[0], user_passwd_pair[1], ""):
                    if fp.isGuestSession() == 0:
                        log_success("SMB", ipaddress, port, user_passwd_pair)

            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
            finally:
                fp.getSMBServer().get_socket().close()


# class Oracle_login(object):
#     def __init__(self):
#         pass
#
#     def login(self, ipaddress, port, user_passwd_pair_list):
#         for user_passwd_pair in user_passwd_pair_list:
#             try:
#                 try:
#                     sid = user_passwd_pair[2]
#                 except Exception as E:
#                     sid = "orcl"
#                 dsn = cx_Oracle.makedsn(host=ipaddress, port=port, sid=sid)
#                 fp = cx_Oracle.connect(user_passwd_pair[0], user_passwd_pair[1], dsn)
#                 log_success("Oracle", ipaddress, port, user_passwd_pair)
#             except Exception as E:
#                 logger.debug('AuthenticationException: %s' % E)
#                 continue
#             finally:
#                 pass


class MySQL_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        for user_passwd_pair in user_passwd_pair_list:
            try:
                fp = pymysql.connect(host=ipaddress, port=int(port), user=user_passwd_pair[0],
                                     passwd=user_passwd_pair[1], connect_timeout=self.timeout)
                fp.get_server_info()
                log_success("MYSQL", ipaddress, port, user_passwd_pair)
            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue
            finally:
                pass


class MSSQL_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        for user_passwd_pair in user_passwd_pair_list:
            husername = binascii.b2a_hex(user_passwd_pair[0])
            lusername = len(user_passwd_pair[0])
            lpassword = len(user_passwd_pair[1])
            hpwd = binascii.b2a_hex(user_passwd_pair[1])
            address = binascii.b2a_hex(ipaddress) + '3a' + binascii.b2a_hex(str(port))
            data = '0200020000000000123456789000000000000000000000000000000000000000000000000000ZZ5440000000000000000000000000000000000000000000000000000000000X3360000000000000000000000000000000000000000000000000000000000Y373933340000000000000000000000000000000000000000000000000000040301060a09010000000002000000000070796d7373716c000000000000000000000000000000000000000000000007123456789000000000000000000000000000000000000000000000000000ZZ3360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000Y0402000044422d4c6962726172790a00000000000d1175735f656e676c69736800000000000000000000000000000201004c000000000000000000000a000000000000000000000000000069736f5f31000000000000000000000000000000000000000000000000000501353132000000030000000000000000'
            data1 = data.replace(data[16:16 + len(address)], address)
            data2 = data1.replace(data1[78:78 + len(husername)], husername)
            data3 = data2.replace(data2[140:140 + len(hpwd)], hpwd)
            if lusername >= 16:
                data4 = data3.replace('0X', str(hex(lusername)).replace('0x', ''))
            else:
                data4 = data3.replace('X', str(hex(lusername)).replace('0x', ''))
            if lpassword >= 16:
                data5 = data4.replace('0Y', str(hex(lpassword)).replace('0x', ''))
            else:
                data5 = data4.replace('Y', str(hex(lpassword)).replace('0x', ''))
            hladd = hex(len(ipaddress) + len(str(port)) + 1).replace('0x', '')
            data6 = data5.replace('ZZ', str(hladd))
            data7 = binascii.a2b_hex(data6)

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((ipaddress, port))
            except Exception as E:
                logger.debug('ConnectException: {} {} {}'.format(E, ipaddress, port))
                return

            try:
                s.send(data7)
                if 'master' in s.recv(1024):
                    log_success("MSSQL", ipaddress, port, user_passwd_pair)
                else:
                    logger.debug('AuthenticationFailed')
            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue


class PostgreSQL_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):

        for user_passwd_pair in user_passwd_pair_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(self.timeout)
                s.connect((ipaddress, port))
            except Exception as E:
                logger.debug('ConnectException: {} {} {}'.format(E, ipaddress, port))
                return
            finally:
                s.close()
            try:
                conn = psycopg2.connect(host=ipaddress,
                                        port=int(port),
                                        user=user_passwd_pair[0],
                                        password=user_passwd_pair[1],
                                        connect_timeout=self.timeout
                                        )

                log_success("PostgreSQL", ipaddress, port, user_passwd_pair)
                conn.close()
            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue
            finally:
                pass


class Redis_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        for user_passwd_pair in user_passwd_pair_list:
            try:
                r = redis.Redis(host=ipaddress, port=port, db=0, socket_connect_timeout=self.timeout)
            except Exception as E:
                logger.debug('ConnectException: {} {} {}'.format(E, ipaddress, port))
                return

            try:
                id = r.execute_command("AUTH {}".format(user_passwd_pair[1]))
                log_success("Redis", ipaddress, port, user_passwd_pair)
                return
            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue
            finally:
                pass


class MongoDB_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        for user_passwd_pair in user_passwd_pair_list:
            try:
                client = pymongo.MongoClient(
                    host=ipaddress,
                    port=port,
                    maxIdleTimeMS=int(self.timeout * 1000),
                    socketTimeoutMS=int(self.timeout * 1000),
                    connectTimeoutMS=int(self.timeout * 1000),
                    serverSelectionTimeoutMS=int(self.timeout * 1000),
                    waitQueueTimeoutMS=int(self.timeout * 1000),
                    wTimeoutMS=int(self.timeout * 1000),
                    socketKeepAlive=False,
                    connect=False
                )
            except Exception as E:
                logger.exception(E)
                logger.debug('ConnectException: {} {} {}'.format(E, ipaddress, port))
                return
            try:
                db = client.admin
                db.authenticate(user_passwd_pair[0], user_passwd_pair[1])
                log_success("MongoDB", ipaddress, port, user_passwd_pair)
            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue
            finally:
                client.close()
                pass


class Memcached_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        # 检查未授权访问功能
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(self.timeout)
            s.connect((ipaddress, port))
            s.send('stats\r\n')
            tmp = s.recv(1024)
            if 'version' in tmp or b"version" in tmp:
                log_success("Memcached", ipaddress, port, None)
                return
        except Exception as e:
            pass
        finally:
            s.close()

        for user_passwd_pair in user_passwd_pair_list:
            try:
                client = bmemcached.Client(('{}:{}'.format(ipaddress, port),),
                                           user_passwd_pair[0],
                                           user_passwd_pair[1],
                                           socket_timeout=self.timeout)
                status = client.stats()
                data = json.dumps(status.get("{}:{}".format(ipaddress, port)))
                if 'Auth failure' in data:
                    continue
                elif "version" in data:
                    log_success("Memcached", ipaddress, port, user_passwd_pair)
                else:
                    return

            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue
            finally:
                pass


class VNC_Error(Exception):
    pass


class VNC(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def connect(self, host, port):
        self.fp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.fp.settimeout(self.timeout)
        self.fp.connect((host, port))
        resp = self.fp.recv(99)  # banner
        logger.debug('banner: %r' % resp)
        self.version = resp[:11]

        if len(resp) > 12:
            raise VNC_Error('%s %r' % (self.version, resp[12:]))

        return self.version

    def login(self, password):
        logger.debug('Remote version: %r' % self.version)
        major, minor = self.version[6], self.version[10]

        if (major, minor) in [('3', '8'), ('4', '1')]:
            proto = 'RFB 003.008\n'

        elif (major, minor) == ('3', '7'):
            proto = 'RFB 003.007\n'

        else:
            proto = 'RFB 003.003\n'

        logger.debug('Client version: %r' % proto[:-1])
        self.fp.sendall(proto)

        time.sleep(0.5)

        resp = self.fp.recv(99)
        logger.debug('Security types supported: %r' % resp)

        if major == '4' or (major == '3' and int(minor) >= 7):
            code = ord(resp[0:1])
            if code == 0:
                raise VNC_Error('Session setup failed: %s' % resp)

            self.fp.sendall(b'\x02')  # always use classic VNC authentication
            resp = self.fp.recv(99)

        else:  # minor == '3':
            code = ord(resp[3:4])
            if code != 2:
                raise VNC_Error('Session setup failed: %s' % resp)

            resp = resp[-16:]

        if len(resp) != 16:
            raise VNC_Error('Unexpected challenge size (No authentication required? Unsupported authentication type?)')

        logger.debug('challenge: %r' % resp)
        pw = password.ljust(8, '\x00')[:8]  # make sure it is 8 chars long, zero padded

        key = self.gen_key(pw)
        logger.debug('key: %r' % key)

        des = DES.new(key, DES.MODE_ECB)
        enc = des.encrypt(resp)

        logger.debug('enc: %r' % enc)
        self.fp.sendall(enc)

        resp = self.fp.recv(99)
        logger.debug('resp: %r' % resp)

        code = ord(resp[3:4])
        mesg = resp[8:]

        if code == 1:
            # return code, mesg or 'Authentication failure'
            return False
        elif code == 0:
            # return code, mesg or 'OK'
            return True
        else:
            raise VNC_Error('Unknown response: %r (code: %s)' % (resp, code))

    def gen_key(self, key):
        newkey = []
        for ki in range(len(key)):
            bsrc = ord(key[ki])
            btgt = 0
            for i in range(8):
                if bsrc & (1 << i):
                    btgt = btgt | (1 << 7 - i)
            newkey.append(btgt)
        return ''.join(chr(c) for c in newkey)


class VNC_login(object):
    def __init__(self, timeout=1):
        self.timeout = timeout

    def login(self, ipaddress, port, user_passwd_pair_list):
        v = VNC(self.timeout)
        for user_passwd_pair in user_passwd_pair_list:
            try:
                version = v.connect(ipaddress, int(port))
                if v.login(user_passwd_pair[1]):
                    log_success("VNC", ipaddress, port, user_passwd_pair)
                    return
            except Exception as E:
                logger.debug('AuthenticationException: %s' % E)
                continue
            finally:
                pass


class Runer(object):
    def __init__(self, maxThreads):
        self.taskQueue = Queue.Queue()
        self.maxThreads = maxThreads

    def _run(self):
        while self.taskQueue.empty() is not True:
            try:
                oneTask = self.taskQueue.get(block=False)
                func = oneTask[0]
                args = oneTask[1]
                func(args[0], args[1], args[2])
            except Exception as E:
                logger.exception(E)

    def start(self):
        threads = []
        for i in range(self.maxThreads):
            t = threading.Thread(target=self._run)
            t.setDaemon(True)
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def bruteforce_interface(portScan_result_list, timeout, no_default_dict, proto_list, pool):
    password_total = Password_total()
    password_total.init(no_default_dict)
    try:
        import psycopg2
        tasksQueue = Queue.Queue()
        postgreSQL_login = PostgreSQL_login()
        for one_portscan_result in portScan_result_list:
            service = one_portscan_result.get("service").lower()
            ipaddress = one_portscan_result.get("ipaddress")
            port = one_portscan_result.get("port")
            if "postgresql" in service and "postgresql" in proto_list:
                tasksQueue.put(
                    (postgreSQL_login.login, (ipaddress, port, password_total.PostgreSQL_user_passwd_pair_list)))

        runner = Runer(100)
        runner.taskQueue = tasksQueue
        runner.start()
    except Exception as E:
        logger.warning("Can not import OpenSSL,PostgreSQL pass")

    # 协程扫描
    patch_all()
    try:
        import gevent_openssl
        gevent_openssl.monkey_patch()
        from bruteforce.rdp_check import check_rdp
        SSL_FLAG = True
    except Exception as E:
        logger.error("Can not import OpenSSL,RDP pass")
        SSL_FLAG = False

    if SSL_FLAG:
        rdp_login = RDP_login(timeout)  # 1.07500004768

    smb_login = SMB_login(timeout)  # 1.08800005913
    ssh_login = SSH_login(timeout)  # 30.617000103
    ftp_login = FTP_login(timeout)  # 9.10599994659
    mysql_login = MySQL_login(timeout)  # 15.7749998569
    mssql_login = MSSQL_login(timeout)  # 1.04799985886
    redis_login = Redis_login(timeout)  # 12.3710000515
    mongo_login = MongoDB_login(timeout)  # 12.9830000401
    memcached_login = Memcached_login(timeout)  # 2.07899999619
    vnc_login = VNC_login(timeout)  # 6.06700015068
    pool = pool
    tasks = []
    for one_portscan_result in portScan_result_list:
        service = one_portscan_result.get("service").lower()
        ipaddress = one_portscan_result.get("ipaddress")
        port = one_portscan_result.get("port")

        # 快的扫描
        if SSL_FLAG:
            if "ms-wbt-server" in service and "rdp" in proto_list:
                task = pool.spawn(rdp_login.login, ipaddress, port, password_total.RDP_user_passwd_pair_list)
                tasks.append(task)
        if "ssh" in service and "ssh" in proto_list:
            task = pool.spawn(ssh_login.login, ipaddress, port, password_total.SSH_user_passwd_pair_list)
            tasks.append(task)
        if "mongodb" in service and "mongodb" in proto_list:
            task = pool.spawn(mongo_login.login, ipaddress, port, password_total.MongoDB_user_passwd_pair_list)
            tasks.append(task)
        if "ftp" in service and "ftp" in proto_list:
            task = pool.spawn(ftp_login.login, ipaddress, port, password_total.FTP_user_passwd_pair_list)
            tasks.append(task)
        if "microsoft-ds" in service and "smb" in proto_list:
            task = pool.spawn(smb_login.login, ipaddress, port, password_total.SMB_user_passwd_pair_list)
            tasks.append(task)
        if "mysql" in service and "mysql" in proto_list:
            task = pool.spawn(mysql_login.login, ipaddress, port, password_total.MYSQL_user_passwd_pair_list)
            tasks.append(task)
        if "ms-sql-s" in service and "mssql" in proto_list:
            task = pool.spawn(mssql_login.login, ipaddress, port, password_total.MSSQL_user_passwd_pair_list)
            tasks.append(task)
        if "redis" in service and "redis" in proto_list:
            task = pool.spawn(redis_login.login, ipaddress, port, password_total.Redis_user_passwd_pair_list)
            tasks.append(task)
        if "memcached" in service and "memcached" in proto_list:
            task = pool.spawn(memcached_login.login, ipaddress, port, password_total.Memcached_user_passwd_pair_list)
            tasks.append(task)
        if "vnc" in service and "vnc" in proto_list:
            task = pool.spawn(vnc_login.login, ipaddress, port, password_total.VNC_user_passwd_pair_list)
            tasks.append(task)
    gevent.joinall(tasks)
