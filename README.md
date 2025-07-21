# GPT随心用 - 智能对话系统

一个基于Flask的智能对话系统，支持文字对话、图像识别、文件处理和批量JSON数据处理。

## 功能特色

- 🤖 **智能对话** - 与AI进行自然流畅的对话
- 🖼️ **图像识别** - 上传图片进行视觉对话
- 📄 **文件处理** - 支持PDF、DOC、TXT等文件分析
- 🔄 **批量处理** - JSON数据批量问答处理
- 👥 **用户管理** - 完整的用户注册登录系统
- 🎛️ **管理后台** - 管理员控制面板
- 📢 **公告系统** - 系统公告管理
- 💰 **Token管理** - 灵活的Token充值系统
- 📊 **数据统计** - 详细的使用统计信息

## 技术栈

- **后端**: Flask + SQLAlchemy + Flask-Login
- **数据库**: SQLite (可扩展至MySQL/PostgreSQL)
- **前端**: HTML + CSS + JavaScript
- **AI接口**: OpenAI API
- **部署**: Gunicorn + Nginx

## 快速开始

### 1. 克隆项目
```bash
git clone https://github.com/您的用户名/gpt-system.git
cd gpt-system
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 配置环境变量
```bash
# 复制环境变量模板
cp .env.example .env

# 编辑环境变量
vim .env
```

### 4. 初始化数据库
```bash
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('数据库初始化完成')
"
```

### 5. 运行应用
```bash
# 开发环境
python app.py

# 生产环境
gunicorn -c gunicorn.conf.py wsgi:app
```

## 环境变量配置

```bash
# Flask配置
FLASK_ENV=production
SECRET_KEY=your-secret-key-here

# 数据库配置
DATABASE_URL=sqlite:///instance/chat_system.db

# OpenAI配置
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-3.5-turbo

# 上传配置
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216
```

## 默认账户

- **管理员**: admin / admin123
- **测试用户**: test / test123

## 部署说明

### 宝塔面板部署
1. 上传项目文件到服务器
2. 创建Python项目
3. 配置反向代理
4. 设置环境变量

详细部署说明请参考：[宝塔部署指南](README_BAOTA.md)

### Docker部署
```bash
# 构建镜像
docker build -t gpt-system .

# 运行容器
docker run -d -p 5001:5001 gpt-system
```

## 项目结构

```
gpt-system/
├── app.py                 # 主应用文件
├── config.py              # 配置文件
├── wsgi.py               # WSGI入口
├── requirements.txt       # Python依赖
├── gunicorn.conf.py      # Gunicorn配置
├── templates/            # HTML模板
├── static/              # 静态文件
├── uploads/             # 上传文件目录
├── instance/            # 数据库文件
└── logs/               # 日志文件
```

## API接口

### 用户相关
- `POST /login` - 用户登录
- `POST /register` - 用户注册
- `GET /dashboard` - 用户控制台

### 对话相关
- `GET /api/conversations` - 获取对话列表
- `POST /api/conversations` - 创建新对话
- `POST /api/conversations/<id>/messages` - 发送消息

### 文件相关
- `POST /api/upload` - 上传文件
- `GET /api/upload` - 获取文件列表

### 管理相关
- `GET /admin` - 管理面板
- `GET /api/admin/stats` - 系统统计
- `POST /api/admin/announcements` - 管理公告

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 联系方式

- 项目链接: https://github.com/您的用户名/gpt-system
- 问题反馈: https://github.com/您的用户名/gpt-system/issues

## 更新日志

### v1.0.0 (2024-07-21)
- ✅ 基础对话功能
- ✅ 用户管理系统
- ✅ 文件上传处理
- ✅ 批量JSON处理
- ✅ 管理员后台
- ✅ 公告系统
- ✅ Token管理
- ✅ 数据统计 