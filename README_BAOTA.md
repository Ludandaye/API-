# GPT随心用系统 - 宝塔面板部署指南

## 1. 环境准备

### 1.1 安装Python环境
在宝塔面板中安装Python 3.8+版本

### 1.2 创建项目目录
```bash
mkdir -p /www/wwwroot/gpt
cd /www/wwwroot/gpt
```

## 2. 上传项目文件

将所有项目文件上传到 `/www/wwwroot/gpt` 目录

## 3. 执行部署脚本

```bash
cd /www/wwwroot/gpt
chmod +x deploy.sh
./deploy.sh
```

## 4. 宝塔面板配置

### 4.1 创建Python项目
1. 登录宝塔面板
2. 进入"软件商店" -> "Python项目管理器"
3. 点击"添加项目"
4. 填写项目信息：
   - 项目名称：gpt
   - 项目路径：/www/wwwroot/gpt
   - 启动文件：wsgi.py
   - 端口：5001
   - Python版本：3.8+

### 4.2 设置环境变量
在Python项目设置中添加以下环境变量：
```
FLASK_ENV=production
SECRET_KEY=your-production-secret-key-here
OPENAI_API_KEY=your-openai-api-key-here
```

### 4.3 配置Nginx
1. 在宝塔面板中创建网站
2. 域名：您的域名
3. 根目录：/www/wwwroot/gpt
4. 在网站设置中添加反向代理：
   - 代理名称：gpt
   - 目标URL：http://127.0.0.1:5001

### 4.4 配置SSL证书（可选）
在网站设置中申请SSL证书

## 5. 启动项目

### 5.1 在宝塔面板中启动
1. 进入Python项目管理器
2. 找到gpt项目
3. 点击"启动"按钮

### 5.2 命令行启动
```bash
cd /www/wwwroot/gpt
./start.sh
```

## 6. 验证部署

访问您的域名，应该能看到GPT随心用系统的首页。

## 7. 默认账户

- 管理员：admin / admin123
- 测试用户：test / test123

## 8. 重要配置

### 8.1 修改密钥
请修改以下文件中的密钥：
- `.env` 文件中的 `SECRET_KEY`
- `gunicorn.conf.py` 中的 `SECRET_KEY`

### 8.2 设置OpenAI API
在环境变量中设置您的OpenAI API密钥

### 8.3 数据库位置
数据库文件位于：`/www/wwwroot/gpt/instance/chat_system.db`

## 9. 日志文件

- 应用日志：`/www/wwwroot/gpt/logs/error.log`
- 访问日志：`/www/wwwroot/gpt/logs/access.log`
- Nginx日志：`/www/wwwroot/gpt/logs/nginx_*.log`

## 10. 故障排除

### 10.1 端口被占用
```bash
lsof -i :5001
kill -9 <PID>
```

### 10.2 权限问题
```bash
chown -R www:www /www/wwwroot/gpt
chmod -R 755 /www/wwwroot/gpt
```

### 10.3 查看日志
```bash
tail -f /www/wwwroot/gpt/logs/error.log
```

## 11. 更新系统

```bash
cd /www/wwwroot/gpt
git pull  # 如果使用Git
./deploy.sh
```

## 12. 备份数据

```bash
cp /www/wwwroot/gpt/instance/chat_system.db /backup/chat_system_$(date +%Y%m%d).db
``` 