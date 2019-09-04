# -*- coding: utf-8 -*-
# @File  : config.py
# @Date  : 2019/8/28
# @Desc  :
# @license : Copyright(C), funnywolf
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import logging.config

# 错误码


logconfig = {
    'version': 1,
    'formatters': {
        'simple': {
            'format': '%(asctime)s - %(levelname)s - %(lineno)s - %(message)s',
        },
        'raw': {
            'format': '%(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'simple'
        },
        'release': {
            'class': 'logging.FileHandler',
            'filename': 'result.log',
            'level': 'INFO',
            'formatter': 'raw'
        },
    },
    'loggers': {
        'StreamLogger': {
            'handlers': ['console'],
            'level': "INFO",
        },
        'ReleaseLogger': {
            'handlers': ['release'],
            'level': "INFO",
        },
    }
}

logging.config.dictConfig(logconfig)

logging.raiseExceptions = False
logger = logging.getLogger("ReleaseLogger")


def log_success(service, ipaddress, port, user_passwd_pair):
    if user_passwd_pair is None:
        format_str = "{:<16}{:<16}{:<7}unauthorized access ".format(service, ipaddress, port)
    else:
        format_str = "{:<16}{:<16}{:<7}{:<20}{:<20}".format(service, ipaddress, port, user_passwd_pair[0],
                                                            user_passwd_pair[1])
    logger.warning(format_str)
