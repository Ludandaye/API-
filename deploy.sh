#!/bin/bash

# 部署脚本 - 宝塔面板专用
echo "开始部署GPT随心用系统..."

# 设置项目路径
PROJECT_DIR="/www/wwwroot/gpt"
cd $PROJECT_DIR

# 创建必要的目录
echo "创建目录..."
mkdir -p logs
mkdir -p instance
mkdir -p uploads
mkdir -p static

# 设置权限
echo "设置权限..."
chown -R www:www $PROJECT_DIR
chmod -R 755 $PROJECT_DIR
chmod +x start.sh
chmod +x deploy.sh

# 安装依赖
echo "安装Python依赖..."
pip install -r requirements.txt

# 初始化数据库
echo "初始化数据库..."
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('数据库初始化完成')
"

# 创建日志文件
touch logs/access.log
touch logs/error.log
touch logs/nginx_access.log
touch logs/nginx_error.log
chown www:www logs/*.log

echo "部署完成！"
echo "请执行以下步骤："
echo "1. 在宝塔面板中创建Python项目"
echo "2. 设置启动文件为: wsgi.py"
echo "3. 设置端口为: 5001"
echo "4. 配置Nginx反向代理"
echo "5. 设置环境变量" 