#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# 设置环境变量
os.environ.setdefault('FLASK_ENV', 'production')

from app import app

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5001, debug=False) 