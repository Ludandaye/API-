#!/bin/bash

# 设置项目路径
PROJECT_DIR="/www/wwwroot/gpt"
cd $PROJECT_DIR

# 创建必要的目录
mkdir -p logs
mkdir -p instance
mkdir -p uploads

# 设置环境变量
export FLASK_ENV=production
export SECRET_KEY="your-production-secret-key-here"
export OPENAI_API_KEY="your-openai-api-key-here"

# 安装依赖
pip install -r requirements.txt

# 初始化数据库
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('数据库初始化完成')
"

# 启动应用
echo "启动GPT随心用系统..."
gunicorn -c gunicorn.conf.py wsgi:app 