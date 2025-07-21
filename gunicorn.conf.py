#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import multiprocessing

# 服务器配置
bind = "127.0.0.1:5001"  # 确保使用5001端口
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
preload_app = True
timeout = 30
keepalive = 2

# 日志配置
accesslog = "/www/wwwroot/gpt/logs/access.log"
errorlog = "/www/wwwroot/gpt/logs/error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# 进程配置
pidfile = "/www/wwwroot/gpt/gunicorn.pid"
user = "www"
group = "www"

# 环境变量
raw_env = [
    "FLASK_ENV=production",
    "SECRET_KEY=gpt-system-secret-key-2024-change-this-in-production",
    "OPENAI_API_KEY=your-openai-api-key-here"
]

# 安全配置
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# 重启配置
reload = False
reload_engine = "auto" 