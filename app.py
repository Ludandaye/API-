from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import datetime
import os
import json
import requests
from PIL import Image
import io
import base64
import uuid
from config import config

# 创建Flask应用
app = Flask(__name__)

# 根据环境变量选择配置
config_name = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[config_name])

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 确保instance目录存在（用于数据库）
os.makedirs('instance', exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    tokens = db.Column(db.Integer, default=100)
    total_tokens_used = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    
    # 关联关系
    conversations = db.relationship('Conversation', backref='user', lazy=True, cascade='all, delete-orphan')
    uploaded_files = db.relationship('UploadedFile', backref='user', lazy=True, cascade='all, delete-orphan')
    batch_tasks = db.relationship('BatchTask', backref='user', lazy=True, cascade='all, delete-orphan')
    user_logs = db.relationship('UserLog', backref='user', lazy=True, cascade='all, delete-orphan')
    payment_records = db.relationship('PaymentRecord', backref='user', lazy=True, cascade='all, delete-orphan')

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    total_messages = db.Column(db.Integer, default=0)
    total_tokens_used = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_message_at = db.Column(db.DateTime)
    
    # 关联关系
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # user, assistant, system
    content = db.Column(db.Text, nullable=False)
    content_length = db.Column(db.Integer, default=0)
    tokens_used = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(500))
    file_url = db.Column(db.String(500))
    processing_time = db.Column(db.Float)  # 处理时间（秒）
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))

class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64))  # 文件哈希值
    is_processed = db.Column(db.Boolean, default=False)
    processing_result = db.Column(db.Text)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))

class BatchTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_type = db.Column(db.String(50), nullable=False)  # json_processing, file_analysis
    task_name = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed
    input_data = db.Column(db.Text)
    output_data = db.Column(db.Text)
    progress = db.Column(db.Integer, default=0)  # 进度百分比
    total_items = db.Column(db.Integer, default=0)
    processed_items = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    processing_time = db.Column(db.Float)  # 处理时间（秒）
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    ip_address = db.Column(db.String(45))

class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(500))
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    priority = db.Column(db.Integer, default=0)  # 优先级
    view_count = db.Column(db.Integer, default=0)  # 查看次数
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class Price(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_amount = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    session_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # 日志类型分类
    LOGIN = 'login'
    LOGOUT = 'logout'
    REGISTER = 'register'
    CONVERSATION_CREATE = 'conversation_create'
    CONVERSATION_DELETE = 'conversation_delete'
    MESSAGE_SEND = 'message_send'
    FILE_UPLOAD = 'file_upload'
    FILE_DELETE = 'file_delete'
    TASK_CREATE = 'task_create'
    TASK_COMPLETE = 'task_complete'
    TOKEN_RECHARGE = 'token_recharge'
    PROFILE_UPDATE = 'profile_update'
    ADMIN_ACTION = 'admin_action'

class ConversationLog(db.Model):
    """对话活动日志"""
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # create, message, delete
    message_count = db.Column(db.Integer, default=0)
    tokens_used = db.Column(db.Integer, default=0)
    duration = db.Column(db.Float)  # 会话持续时间（分钟）
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class FileUsageLog(db.Model):
    """文件使用日志"""
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    action = db.Column(db.String(50), nullable=False)  # upload, download, delete, process
    result = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class PaymentRecord(db.Model):
    """支付记录"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token_amount = db.Column(db.Integer, nullable=False)
    price_per_token = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    payment_method = db.Column(db.String(50))  # wechat, alipay, etc.
    transaction_id = db.Column(db.String(100))  # 交易ID
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # 记录用户活动
    def log_payment_activity(self):
        log_user_activity(
            user_id=self.user_id,
            action='payment_record',
            details=f"支付记录：{self.token_amount} Token，总价 ¥{self.total_price}",
            ip_address=self.ip_address
        )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 工具函数
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except:
        return None

def get_openai_config():
    config = SystemConfig.query.filter_by(key='openai_api_key').first()
    return config.value if config else None

def call_openai_api(messages, model="gpt-3.5-turbo", temperature=0.7, max_tokens=1000):
    api_key = get_openai_config()
    if not api_key:
        return {"error": "OpenAI API key not configured"}
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature
    }
    
    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_user_activity(user_id, action, details=None, ip_address=None, user_agent=None):
    """记录用户活动"""
    try:
        log = UserLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address or request.remote_addr,
            user_agent=user_agent or request.headers.get('User-Agent'),
            session_id=session.get('session_id', '')
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"记录用户活动失败: {e}")

def log_conversation_activity(conversation_id, user_id, action, message_count=0, tokens_used=0):
    """记录对话活动"""
    try:
        log = ConversationLog(
            conversation_id=conversation_id,
            user_id=user_id,
            action=action,
            message_count=message_count,
            tokens_used=tokens_used
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"记录对话活动失败: {e}")

def log_file_usage(file_id, user_id, action, conversation_id=None, result=None):
    """记录文件使用情况"""
    try:
        log = FileUsageLog(
            file_id=file_id,
            user_id=user_id,
            action=action,
            conversation_id=conversation_id,
            result=result
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"记录文件使用失败: {e}")

def calculate_tokens(text):
    """简单估算token数量（实际应该使用tiktoken库）"""
    # 这是一个简化的估算，实际应该使用OpenAI的tiktoken库
    return len(text.split()) + len(text) // 4

def update_conversation_stats(conversation_id):
    """更新对话统计信息"""
    try:
        conversation = Conversation.query.get(conversation_id)
        if conversation:
            messages = Message.query.filter_by(conversation_id=conversation_id).all()
            conversation.total_messages = len(messages)
            conversation.total_tokens_used = sum(msg.tokens_used for msg in messages)
            conversation.last_message_at = max(msg.timestamp for msg in messages) if messages else conversation.created_at
            db.session.commit()
    except Exception as e:
        print(f"更新对话统计失败: {e}")

def update_user_stats(user_id):
    """更新用户统计信息"""
    try:
        user = User.query.get(user_id)
        if user:
            # 计算总token使用量
            total_tokens = db.session.query(db.func.sum(Message.tokens_used)).filter(
                Message.conversation_id.in_(
                    db.session.query(Conversation.id).filter_by(user_id=user_id)
                )
            ).scalar() or 0
            user.total_tokens_used = total_tokens
            db.session.commit()
    except Exception as e:
        print(f"更新用户统计失败: {e}")

# 路由
@app.route('/')
def index():
    announcements = Announcement.query.filter_by(is_active=True).order_by(Announcement.created_at.desc()).limit(5).all()
    return render_template('index.html', announcements=announcements)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.last_login = datetime.datetime.utcnow()
            user.login_count += 1
            db.session.commit()
            
            # 记录登录日志
            log_user_activity(
                user_id=user.id,
                action=UserLog.LOGIN,
                details=f"用户 {username} 登录成功",
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            
            return jsonify({'success': True, 'message': '登录成功'})
        else:
            # 记录失败的登录尝试
            if user:
                log_user_activity(
                    user_id=user.id,
                    action='login_failed',
                    details=f"用户 {username} 登录失败：密码错误",
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
            return jsonify({'success': False, 'message': '用户名或密码错误'})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': '用户名已存在'})
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': '邮箱已存在'})
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        # 记录注册活动
        log_user_activity(
            user_id=user.id,
            action=UserLog.REGISTER,
            details=f"新用户注册：{username} ({email})",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'success': True, 'message': '注册成功'})
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conversations = Conversation.query.filter_by(user_id=current_user.id).order_by(Conversation.updated_at.desc()).limit(10).all()
    files = UploadedFile.query.filter_by(user_id=current_user.id).order_by(UploadedFile.uploaded_at.desc()).limit(10).all()
    tasks = BatchTask.query.filter_by(user_id=current_user.id).order_by(BatchTask.created_at.desc()).limit(10).all()
    
    # 获取活跃的公告
    announcements = Announcement.query.filter_by(is_active=True).order_by(Announcement.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                         conversations=conversations,
                         files=files,
                         tasks=tasks,
                         announcements=announcements)

@app.route('/chat/<int:conversation_id>')
@login_required
def chat(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    if conversation.user_id != current_user.id:
        return redirect(url_for('dashboard'))
    
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
    return render_template('chat.html', conversation=conversation, messages=messages)

@app.route('/api/conversations', methods=['GET', 'POST'])
@login_required
def conversations():
    if request.method == 'POST':
        data = request.get_json()
        title = data.get('title', '新对话')
        
        conversation = Conversation(
            user_id=current_user.id,
            title=title,
            description=f"用户 {current_user.username} 创建的新对话"
        )
        db.session.add(conversation)
        db.session.commit()
        
        # 记录对话创建活动
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.CONVERSATION_CREATE,
            details=f"创建对话：{title}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        log_conversation_activity(
            conversation_id=conversation.id,
            user_id=current_user.id,
            action='create'
        )
        
        return jsonify({'success': True, 'conversation_id': conversation.id})
    
    conversations = Conversation.query.filter_by(user_id=current_user.id).order_by(Conversation.updated_at.desc()).all()
    return jsonify([{
        'id': c.id,
        'title': c.title,
        'created_at': c.created_at.isoformat(),
        'updated_at': c.updated_at.isoformat(),
        'total_messages': c.total_messages,
        'total_tokens_used': c.total_tokens_used
    } for c in conversations])

@app.route('/api/conversations/<int:conversation_id>/messages', methods=['GET', 'POST'])
@login_required
def messages(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    if conversation.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'POST':
        data = request.get_json()
        user_message = data.get('message')
        image_data = data.get('image')
        file_data = data.get('file')
        
        # 获取新的控制参数
        system_message = data.get('system_message', '你是一个有用的AI助手。')
        temperature = data.get('temperature', 0.7)
        max_tokens = data.get('max_tokens', 1000)
        model = data.get('model', 'gpt-3.5-turbo')
        
        start_time = datetime.datetime.utcnow()
        
        # 保存用户消息
        user_msg = Message(
            conversation_id=conversation_id,
            role='user',
            content=user_message,
            content_length=len(user_message),
            tokens_used=calculate_tokens(user_message),
            ip_address=request.remote_addr
        )
        db.session.add(user_msg)
        
        # 处理图片
        if image_data:
            try:
                image_data = image_data.split(',')[1]
                image_bytes = base64.b64decode(image_data)
                image = Image.open(io.BytesIO(image_bytes))
                
                filename = f"image_{uuid.uuid4()}.png"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(filepath)
                
                user_msg.image_url = filename
            except Exception as e:
                print(f"Image processing error: {e}")
        
        # 处理文件
        if file_data:
            try:
                file_data = file_data.split(',')[1]
                file_bytes = base64.b64decode(file_data)
                
                filename = f"file_{uuid.uuid4()}.txt"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                with open(filepath, 'wb') as f:
                    f.write(file_bytes)
                
                user_msg.file_url = filename
            except Exception as e:
                print(f"File processing error: {e}")
        
        db.session.commit()
        
        # 构建发送给OpenAI的消息
        messages = []
        messages.append({"role": "system", "content": system_message})
        
        # 获取对话历史
        history = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
        for msg in history:
            messages.append({"role": msg.role, "content": msg.content})
        
        # 调用OpenAI API，传递新的参数
        response = call_openai_api(messages, model=model, temperature=temperature, max_tokens=max_tokens)
        
        if 'error' in response:
            assistant_message = "抱歉，处理您的请求时出现错误。"
            assistant_tokens = 0
        else:
            assistant_message = response['choices'][0]['message']['content']
            assistant_tokens = response['usage']['total_tokens'] if 'usage' in response else calculate_tokens(assistant_message)
        
        # 保存助手回复
        assistant_msg = Message(
            conversation_id=conversation_id,
            role='assistant',
            content=assistant_message,
            content_length=len(assistant_message),
            tokens_used=assistant_tokens,
            processing_time=(datetime.datetime.utcnow() - start_time).total_seconds(),
            ip_address=request.remote_addr
        )
        db.session.add(assistant_msg)
        
        # 更新对话时间
        conversation.updated_at = datetime.datetime.utcnow()
        conversation.last_message_at = datetime.datetime.utcnow()
        
        # 更新统计信息
        update_conversation_stats(conversation_id)
        update_user_stats(current_user.id)
        
        # 记录消息发送活动
        total_tokens = user_msg.tokens_used + assistant_tokens
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.MESSAGE_SEND,
            details=f"发送消息到对话 {conversation.title}，使用 {total_tokens} tokens，模型：{model}，温度：{temperature}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        log_conversation_activity(
            conversation_id=conversation_id,
            user_id=current_user.id,
            action='message',
            message_count=2,  # 用户消息 + 助手回复
            tokens_used=total_tokens
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'assistant_message': assistant_message,
            'tokens_used': total_tokens
        })
    
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
    return jsonify([{
        'id': m.id,
        'role': m.role,
        'content': m.content,
        'timestamp': m.timestamp.isoformat(),
        'image_url': m.image_url,
        'file_url': m.file_url,
        'tokens_used': m.tokens_used,
        'processing_time': m.processing_time
    } for m in messages])

@app.route('/api/conversations/<int:conversation_id>/clear', methods=['POST'])
@login_required
def clear_conversation(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    if conversation.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # 删除所有消息
        Message.query.filter_by(conversation_id=conversation_id).delete()
        
        # 重置对话统计
        conversation.total_messages = 0
        conversation.total_tokens_used = 0
        conversation.updated_at = datetime.datetime.utcnow()
        
        db.session.commit()
        
        # 记录清空对话活动
        log_user_activity(
            user_id=current_user.id,
            action='conversation_clear',
            details=f"清空对话：{conversation.title}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'success': True, 'message': '对话已清空'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/conversations/<int:conversation_id>/export', methods=['GET'])
@login_required
def export_conversation(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    if conversation.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).all()
        
        # 生成导出内容
        export_content = f"对话标题：{conversation.title}\n"
        export_content += f"创建时间：{conversation.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
        export_content += f"消息数量：{len(messages)}\n"
        export_content += f"总Token使用量：{conversation.total_tokens_used}\n"
        export_content += "=" * 50 + "\n\n"
        
        for i, message in enumerate(messages, 1):
            role_name = "用户" if message.role == "user" else "AI助手"
            export_content += f"[{i}] {role_name} ({message.timestamp.strftime('%H:%M:%S')})\n"
            export_content += f"{message.content}\n"
            if message.tokens_used:
                export_content += f"[Token使用量：{message.tokens_used}]\n"
            export_content += "\n"
        
        # 记录导出活动
        log_user_activity(
            user_id=current_user.id,
            action='conversation_export',
            details=f"导出对话：{conversation.title}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # 返回文件下载
        from io import BytesIO
        from flask import send_file
        
        buffer = BytesIO()
        buffer.write(export_content.encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"对话_{conversation.title}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mimetype='text/plain'
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # 计算文件哈希值
        import hashlib
        file_hash = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
        
        uploaded_file = UploadedFile(
            user_id=current_user.id,
            filename=filename,
            original_filename=file.filename,
            file_path=filepath,
            file_type=file.content_type,
            file_size=os.path.getsize(filepath),
            file_hash=file_hash,
            ip_address=request.remote_addr
        )
        db.session.add(uploaded_file)
        db.session.commit()
        
        # 记录文件上传活动
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.FILE_UPLOAD,
            details=f"上传文件：{file.filename} ({uploaded_file.file_size} bytes)",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        log_file_usage(
            file_id=uploaded_file.id,
            user_id=current_user.id,
            action='upload',
            result=f"文件上传成功，大小：{uploaded_file.file_size} bytes"
        )
        
        return jsonify({
            'success': True,
            'filename': filename,
            'file_id': uploaded_file.id,
            'file_size': uploaded_file.file_size
        })
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/api/batch', methods=['GET', 'POST'])
@login_required
def batch_processing():
    if request.method == 'GET':
        # 获取当前用户的任务列表
        tasks = BatchTask.query.filter_by(user_id=current_user.id).order_by(BatchTask.created_at.desc()).all()
        return jsonify([{
            'id': task.id,
            'task_type': task.task_type,
            'task_name': task.task_name,
            'status': task.status,
            'created_at': task.created_at.isoformat(),
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'processing_time': task.processing_time
        } for task in tasks])
    
    # POST 请求处理
    data = request.get_json()
    task_type = data.get('type')
    input_data = data.get('data')
    task_name = data.get('name', f'{task_type}任务')
    
    start_time = datetime.datetime.utcnow()
    
    # 创建任务记录
    task = BatchTask(
        user_id=current_user.id,
        task_type=task_type,
        task_name=task_name,
        input_data=json.dumps(input_data),
        status='processing',
        started_at=start_time,
        ip_address=request.remote_addr
    )
    db.session.add(task)
    db.session.commit()
    
    try:
        # 根据任务类型处理数据
        if task_type == 'json_processing':
            # JSON数据处理 - 问答形式
            result = process_json_qa(input_data)
        else:
            result = {'error': '不支持的任务类型'}
        
        # 更新任务状态
        task.status = 'completed'
        task.output_data = json.dumps(result)
        task.completed_at = datetime.datetime.utcnow()
        task.processing_time = (task.completed_at - start_time).total_seconds()
        task.progress = 100
        
        db.session.commit()
        
        # 记录任务完成活动
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.TASK_COMPLETE,
            details=f"完成批量任务：{task_name} ({task_type})",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'result': result,
            'message': '任务处理完成'
        })
        
    except Exception as e:
        # 更新任务状态为失败
        task.status = 'failed'
        task.error_message = str(e)
        task.completed_at = datetime.datetime.utcnow()
        task.processing_time = (task.completed_at - start_time).total_seconds()
        db.session.commit()
        
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '任务处理失败'
        })

@app.route('/api/batch/<int:task_id>', methods=['GET'])
@login_required
def get_batch_task_result(task_id):
    """获取批量任务结果"""
    task = BatchTask.query.get_or_404(task_id)
    
    # 检查权限
    if task.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if task.status == 'completed':
        try:
            result = json.loads(task.output_data) if task.output_data else {}
            return jsonify({
                'success': True,
                'result': result,
                'task': {
                    'id': task.id,
                    'name': task.task_name,
                    'type': task.task_type,
                    'status': task.status,
                    'created_at': task.created_at.isoformat(),
                    'processing_time': task.processing_time
                }
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'解析结果失败: {str(e)}'
            })
    else:
        return jsonify({
            'success': False,
            'message': f'任务状态: {task.status}'
        })

def process_json_qa(json_data):
    """处理JSON数据的问答形式，支持用户提问，AI只返回JSON格式答案"""
    try:
        # 解析JSON数据
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data

        # 从JSON数据中提取用户问题
        user_question = ""
        analysis_data = data
        
        if isinstance(data, dict):
            # 如果数据包含question字段，使用它作为问题
            if 'question' in data:
                user_question = data['question']
                # 从数据中移除question，保留其他数据作为分析对象
                analysis_data = {k: v for k, v in data.items() if k != 'question'}
            else:
                # 如果没有question字段，使用默认问题
                user_question = "请分析这个JSON数据并给出详细的分析结果"
                analysis_data = data
        elif isinstance(data, list):
            # 如果是数组，检查是否包含问题对象
            questions = []
            other_data = []
            
            for item in data:
                if isinstance(item, dict) and 'question' in item:
                    questions.append(item['question'])
                    # 保留context等信息
                    other_data.append({k: v for k, v in item.items() if k != 'question'})
                else:
                    other_data.append(item)
            
            if questions:
                # 如果有问题，合并所有问题
                user_question = "请回答以下问题：" + "；".join(questions)
                analysis_data = other_data
            else:
                user_question = "请分析这个JSON数据并给出详细的分析结果"
                analysis_data = data
        else:
            user_question = "请分析这个JSON数据并给出详细的分析结果"
            analysis_data = data

        # 构建发送给AI的消息，要求返回JSON格式
        messages = [
            {"role": "system", "content": "你是一个专业的AI助手。请根据用户的问题分析提供的JSON数据，并以JSON格式返回答案。只输出一个有效的JSON对象，不要包含任何其他文本或解释。答案应该直接、准确、结构化。"},
            {"role": "user", "content": f"问题：{user_question}\n\n数据：{json.dumps(analysis_data, ensure_ascii=False, indent=2)}\n\n请以JSON格式回答，只输出JSON对象。"}
        ]

        response = call_openai_api(messages)
        
        # 获取AI回复并尝试解析为JSON
        ai_answer = ""
        ai_json_answer = {}
        
        if isinstance(response, dict) and 'choices' in response and response['choices']:
            ai_answer = response['choices'][0]['message']['content']
            
            # 尝试解析AI回复为JSON
            try:
                # 清理可能的markdown代码块标记
                cleaned_answer = ai_answer.strip()
                if cleaned_answer.startswith('```json'):
                    cleaned_answer = cleaned_answer[7:]
                if cleaned_answer.startswith('```'):
                    cleaned_answer = cleaned_answer[3:]
                if cleaned_answer.endswith('```'):
                    cleaned_answer = cleaned_answer[:-3]
                
                ai_json_answer = json.loads(cleaned_answer.strip())
            except json.JSONDecodeError:
                # 如果无法解析为JSON，创建一个包含原始答案的对象
                ai_json_answer = {
                    "answer": ai_answer,
                    "format": "text",
                    "note": "AI返回的内容无法解析为JSON格式"
                }
        else:
            ai_answer = "抱歉，处理您的请求时出现错误。"
            ai_json_answer = {
                "error": "处理失败",
                "message": ai_answer
            }

        return {
            'question': user_question,
            'input_data': analysis_data,
            'answer': ai_answer,
            'json_answer': ai_json_answer,  # 新增：JSON格式的答案
            'data_structure': analyze_json_structure(analysis_data),
            'summary': generate_json_summary(analysis_data)
        }

    except Exception as e:
        return {'error': f'JSON处理失败: {str(e)}'}

def analyze_json_structure(data):
    """分析JSON数据结构"""
    def analyze_item(item, path=""):
        if isinstance(item, dict):
            return {
                'type': 'object',
                'keys': list(item.keys()),
                'children': {k: analyze_item(v, f"{path}.{k}" if path else k) for k, v in item.items()}
            }
        elif isinstance(item, list):
            if item:
                return {
                    'type': 'array',
                    'length': len(item),
                    'sample_type': analyze_item(item[0], f"{path}[0]")
                }
            else:
                return {'type': 'array', 'length': 0}
        else:
            return {'type': type(item).__name__, 'value': str(item)[:100]}
    
    return analyze_item(data)

def generate_json_summary(data):
    """生成JSON数据摘要"""
    summary = {
        'total_items': 0,
        'data_types': {},
        'max_depth': 0,
        'estimated_size': 0
    }
    
    def count_items(item, depth=0):
        summary['max_depth'] = max(summary['max_depth'], depth)
        summary['estimated_size'] += len(str(item))
        
        if isinstance(item, dict):
            summary['total_items'] += len(item)
            for k, v in item.items():
                count_items(v, depth + 1)
        elif isinstance(item, list):
            summary['total_items'] += len(item)
            for v in item:
                count_items(v, depth + 1)
        else:
            summary['total_items'] += 1
            data_type = type(item).__name__
            summary['data_types'][data_type] = summary['data_types'].get(data_type, 0) + 1
    
    count_items(data)
    return summary

@app.route('/api/admin/config', methods=['GET', 'POST'])
@login_required
def admin_config():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'POST':
        data = request.get_json()
        key = data.get('key')
        value = data.get('value')
        
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            config.value = value
            config.updated_at = datetime.datetime.utcnow()
        else:
            config = SystemConfig(key=key, value=value)
            db.session.add(config)
        
        db.session.commit()
        return jsonify({'success': True})
    
    configs = SystemConfig.query.all()
    return jsonify([{
        'key': c.key,
        'value': c.value,
        'updated_at': c.updated_at.isoformat()
    } for c in configs])

@app.route('/api/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'is_admin': u.is_admin,
        'tokens': u.tokens,
        'created_at': u.created_at.isoformat(),
        'last_login': u.last_login.isoformat() if u.last_login else None
    } for u in users])

@app.route('/api/announcements')
def public_announcements():
    """公开的公告API，不需要登录"""
    announcements = Announcement.query.filter_by(is_active=True).order_by(Announcement.created_at.desc()).all()
    return jsonify([{
        'id': a.id,
        'title': a.title,
        'content': a.content,
        'created_at': a.created_at.isoformat()
    } for a in announcements])

@app.route('/api/admin/announcements', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def admin_announcements():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'POST':
        data = request.get_json()
        announcement = Announcement(
            title=data.get('title'),
            content=data.get('content'),
            is_active=data.get('is_active', True)
        )
        db.session.add(announcement)
        db.session.commit()
        return jsonify({'success': True, 'message': '公告创建成功'})
    
    elif request.method == 'PUT':
        data = request.get_json()
        announcement_id = data.get('id')
        announcement = Announcement.query.get_or_404(announcement_id)
        
        announcement.title = data.get('title', announcement.title)
        announcement.content = data.get('content', announcement.content)
        announcement.is_active = data.get('is_active', announcement.is_active)
        
        db.session.commit()
        return jsonify({'success': True, 'message': '公告更新成功'})
    
    elif request.method == 'DELETE':
        data = request.get_json()
        announcement_id = data.get('id')
        announcement = Announcement.query.get_or_404(announcement_id)
        
        db.session.delete(announcement)
        db.session.commit()
        return jsonify({'success': True, 'message': '公告删除成功'})
    
    # GET 请求 - 获取所有公告
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return jsonify([{
        'id': a.id,
        'title': a.title,
        'content': a.content,
        'is_active': a.is_active,
        'created_at': a.created_at.isoformat()
    } for a in announcements])

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    # 更新用户信息
    if 'email' in data:
        # 检查邮箱是否已被其他用户使用
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'success': False, 'message': '邮箱已被其他用户使用'})
        user.email = data['email']
    
    if 'tokens' in data:
        user.tokens = int(data['tokens'])
    
    if 'is_admin' in data:
        user.is_admin = bool(data['is_admin'])
    
    if 'is_active' in data:
        user.is_active = bool(data['is_active'])
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': '用户信息更新成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if current_user.id == user_id:
        return jsonify({'success': False, 'message': '不能删除自己的账户'})
    
    user = User.query.get_or_404(user_id)
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': '用户删除成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'})

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    return render_template('admin.html')

@app.route('/subscribe')
def subscribe():
    """订阅页面"""
    return render_template('subscribe.html')

@app.route('/api/payment', methods=['POST'])
def create_payment():
    """创建支付记录"""
    data = request.get_json()
    token_amount = data.get('token_amount')
    price_per_token = data.get('price_per_token')
    total_price = data.get('total_price')
    
    if not all([token_amount, price_per_token, total_price]):
        return jsonify({'success': False, 'message': '缺少必要参数'}), 400
    
    try:
        # 创建支付记录
        payment = PaymentRecord(
            user_id=current_user.id if current_user.is_authenticated else None,
            token_amount=token_amount,
            price_per_token=price_per_token,
            total_price=total_price,
            ip_address=request.remote_addr
        )
        
        db.session.add(payment)
        db.session.commit()
        
        # 记录支付活动
        payment.log_payment_activity()
        
        return jsonify({
            'success': True,
            'payment_id': payment.id,
            'message': '支付记录创建成功'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'创建支付记录失败: {str(e)}'}), 500

@app.route('/api/payment/<int:payment_id>/complete', methods=['POST'])
def complete_payment(payment_id):
    """完成支付"""
    payment = PaymentRecord.query.get_or_404(payment_id)
    
    # 检查权限
    if current_user.is_authenticated and payment.user_id != current_user.id:
        return jsonify({'success': False, 'message': '无权限操作此支付记录'}), 403
    
    try:
        payment.payment_status = 'completed'
        payment.completed_at = datetime.datetime.utcnow()
        payment.payment_method = 'manual'  # 手动确认支付
        
        db.session.commit()
        
        # 记录完成支付活动
        log_user_activity(
            user_id=payment.user_id or 0,
            action='payment_completed',
            details=f"支付完成：{payment.token_amount} Token，总价 ¥{payment.total_price}",
            ip_address=request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'message': '支付完成'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'完成支付失败: {str(e)}'}), 500

@app.route('/api/payment/records')
@login_required
def get_payment_records():
    """获取用户的支付记录"""
    records = PaymentRecord.query.filter_by(user_id=current_user.id).order_by(PaymentRecord.created_at.desc()).all()
    
    return jsonify([{
        'id': record.id,
        'token_amount': record.token_amount,
        'price_per_token': record.price_per_token,
        'total_price': record.total_price,
        'payment_status': record.payment_status,
        'payment_method': record.payment_method,
        'created_at': record.created_at.isoformat(),
        'completed_at': record.completed_at.isoformat() if record.completed_at else None
    } for record in records])

@app.route('/api/admin/stats')
@login_required
def admin_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # 用户统计
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        admin_users = User.query.filter_by(is_admin=True).count()
        
        # 对话统计
        total_conversations = Conversation.query.count()
        recent_conversations = Conversation.query.filter(
            Conversation.created_at >= datetime.datetime.utcnow() - datetime.timedelta(days=7)
        ).count()
        
        # 消息统计
        total_messages = Message.query.count()
        user_messages = Message.query.filter_by(role='user').count()
        assistant_messages = Message.query.filter_by(role='assistant').count()
        
        # 文件统计
        total_files = UploadedFile.query.count()
        recent_files = UploadedFile.query.filter(
            UploadedFile.uploaded_at >= datetime.datetime.utcnow() - datetime.timedelta(days=7)
        ).count()
        
        # Token统计
        total_tokens = db.session.query(db.func.sum(User.tokens)).scalar() or 0
        used_tokens = db.session.query(db.func.sum(Message.tokens_used)).scalar() or 0
        
        # 批量任务统计
        total_tasks = BatchTask.query.count()
        completed_tasks = BatchTask.query.filter_by(status='completed').count()
        pending_tasks = BatchTask.query.filter_by(status='pending').count()
        
        # 最近活动
        recent_activities = []
        
        # 最近登录的用户
        recent_logins = User.query.filter(
            User.last_login.isnot(None)
        ).order_by(User.last_login.desc()).limit(5).all()
        
        for user in recent_logins:
            recent_activities.append({
                'type': 'login',
                'user': user.username,
                'time': user.last_login.isoformat(),
                'description': f'{user.username} 登录了系统'
            })
        
        # 最近创建的对话
        recent_convs = Conversation.query.order_by(Conversation.created_at.desc()).limit(5).all()
        for conv in recent_convs:
            user = User.query.get(conv.user_id)
            recent_activities.append({
                'type': 'conversation',
                'user': user.username if user else '未知用户',
                'time': conv.created_at.isoformat(),
                'description': f'{user.username if user else "未知用户"} 创建了新对话'
            })
        
        # 最近上传的文件
        recent_uploads = UploadedFile.query.order_by(UploadedFile.uploaded_at.desc()).limit(5).all()
        for file in recent_uploads:
            user = User.query.get(file.user_id)
            recent_activities.append({
                'type': 'file',
                'user': user.username if user else '未知用户',
                'time': file.uploaded_at.isoformat(),
                'description': f'{user.username if user else "未知用户"} 上传了文件 {file.filename}'
            })
        
        # 按时间排序最近活动
        recent_activities.sort(key=lambda x: x['time'], reverse=True)
        recent_activities = recent_activities[:10]  # 只取前10个
        
        # 每日注册用户统计（最近7天）
        daily_registrations = []
        for i in range(7):
            date = datetime.datetime.utcnow() - datetime.timedelta(days=i)
            start_date = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = start_date + datetime.timedelta(days=1)
            
            count = User.query.filter(
                User.created_at >= start_date,
                User.created_at < end_date
            ).count()
            
            daily_registrations.append({
                'date': start_date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        daily_registrations.reverse()
        
        # 每日消息统计（最近7天）
        daily_messages = []
        for i in range(7):
            date = datetime.datetime.utcnow() - datetime.timedelta(days=i)
            start_date = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = start_date + datetime.timedelta(days=1)
            
            count = Message.query.filter(
                Message.timestamp >= start_date,
                Message.timestamp < end_date
            ).count()
            
            daily_messages.append({
                'date': start_date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        daily_messages.reverse()
        
        stats = {
            'users': {
                'total': total_users,
                'active': active_users,
                'admin': admin_users,
                'daily_registrations': daily_registrations
            },
            'conversations': {
                'total': total_conversations,
                'recent': recent_conversations
            },
            'messages': {
                'total': total_messages,
                'user_messages': user_messages,
                'assistant_messages': assistant_messages,
                'daily_messages': daily_messages
            },
            'files': {
                'total': total_files,
                'recent': recent_files
            },
            'tokens': {
                'total_balance': total_tokens,
                'used': used_tokens,
                'available': total_tokens - used_tokens
            },
            'tasks': {
                'total': total_tasks,
                'completed': completed_tasks,
                'pending': pending_tasks
            },
            'recent_activities': recent_activities
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': f'统计失败: {str(e)}'}), 500

@app.route('/api/admin/prices', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def admin_prices():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'GET':
        prices = Price.query.order_by(Price.token_amount).all()
        return jsonify([{
            'id': price.id,
            'token_amount': price.token_amount,
            'price': price.price,
            'is_active': price.is_active,
            'description': price.description,
            'created_at': price.created_at.isoformat()
        } for price in prices])
    
    elif request.method == 'POST':
        data = request.get_json()
        token_amount = data.get('token_amount')
        price = data.get('price')
        description = data.get('description', '')
        
        if not token_amount or not price:
            return jsonify({'error': 'Token数量和价格不能为空'}), 400
        
        new_price = Price(
            token_amount=token_amount,
            price=price,
            description=description
        )
        db.session.add(new_price)
        db.session.commit()
        
        # 记录管理员活动
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.ADMIN_ACTION,
            details=f"添加价格方案：{token_amount} tokens = ¥{price}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'success': True, 'message': '价格方案添加成功'})
    
    elif request.method == 'PUT':
        data = request.get_json()
        price_id = data.get('id')
        token_amount = data.get('token_amount')
        price = data.get('price')
        description = data.get('description', '')
        is_active = data.get('is_active', True)
        
        price_obj = Price.query.get(price_id)
        if not price_obj:
            return jsonify({'error': '价格方案不存在'}), 404
        
        price_obj.token_amount = token_amount
        price_obj.price = price
        price_obj.description = description
        price_obj.is_active = is_active
        db.session.commit()
        
        # 记录管理员活动
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.ADMIN_ACTION,
            details=f"更新价格方案：{token_amount} tokens = ¥{price}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'success': True, 'message': '价格方案更新成功'})
    
    elif request.method == 'DELETE':
        data = request.get_json()
        price_id = data.get('id')
        
        price_obj = Price.query.get(price_id)
        if not price_obj:
            return jsonify({'error': '价格方案不存在'}), 404
        
        # 记录删除信息
        token_amount = price_obj.token_amount
        price_value = price_obj.price
        
        db.session.delete(price_obj)
        db.session.commit()
        
        # 记录管理员活动
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.ADMIN_ACTION,
            details=f"删除价格方案：{token_amount} tokens = ¥{price_value}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'success': True, 'message': '价格方案删除成功'})

@app.route('/api/token-price')
def get_token_price():
    """获取当前Token价格（公开API）"""
    # 从数据库获取Token价格设置
    config = SystemConfig.query.filter_by(key='token_price').first()
    if config:
        try:
            price_data = json.loads(config.value)
            return jsonify({
                'token_amount': price_data.get('token_amount', 1),
                'price': price_data.get('price', 0.01),
                'description': price_data.get('description', ''),
                'is_active': price_data.get('is_active', True)
            })
        except:
            pass
    
    # 返回默认价格
    return jsonify({
        'token_amount': 1,
        'price': 0.01,
        'description': '默认Token价格',
        'is_active': True
    })

@app.route('/api/admin/token-price', methods=['GET', 'POST', 'PUT'])
@login_required
def admin_token_price():
    """管理员Token价格管理API"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'GET':
        # 获取当前Token价格设置
        config = SystemConfig.query.filter_by(key='token_price').first()
        if config:
            try:
                price_data = json.loads(config.value)
                return jsonify({
                    'id': 1,
                    'token_amount': price_data.get('token_amount', 1),
                    'price': price_data.get('price', 0.01),
                    'description': price_data.get('description', ''),
                    'is_active': price_data.get('is_active', True),
                    'updated_at': config.updated_at.isoformat()
                })
            except:
                pass
        
        # 返回默认价格
        return jsonify({
            'id': 1,
            'token_amount': 1,
            'price': 0.01,
            'description': '默认Token价格',
            'is_active': True,
            'updated_at': datetime.datetime.utcnow().isoformat()
        })
    
    elif request.method in ['POST', 'PUT']:
        data = request.get_json()
        token_amount = data.get('token_amount', 1)
        price = data.get('price', 0.01)
        description = data.get('description', '')
        is_active = data.get('is_active', True)
        
        # 保存Token价格设置
        price_data = {
            'token_amount': token_amount,
            'price': price,
            'description': description,
            'is_active': is_active
        }
        
        config = SystemConfig.query.filter_by(key='token_price').first()
        if config:
            config.value = json.dumps(price_data)
            config.updated_at = datetime.datetime.utcnow()
        else:
            config = SystemConfig(
                key='token_price',
                value=json.dumps(price_data),
                description='Token价格设置'
            )
            db.session.add(config)
        
        db.session.commit()
        
        # 记录管理员活动
        action = 'POST' if request.method == 'POST' else 'PUT'
        log_user_activity(
            user_id=current_user.id,
            action=UserLog.ADMIN_ACTION,
            details=f"{'设置' if action == 'POST' else '更新'}Token价格：{token_amount} token = ¥{price}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({'success': True, 'message': f'Token价格{"设置" if action == "POST" else "更新"}成功'})

@app.route('/debug')
def debug():
    return render_template('debug.html')

@app.route('/test')
def test():
    return render_template('test.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # 创建默认管理员用户
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True,
                tokens=1000
            )
            db.session.add(admin)
            print("✅ 创建管理员用户: admin/admin123")
        
        # 创建测试用户
        test_user = User.query.filter_by(username='test').first()
        if not test_user:
            test_user = User(
                username='test',
                email='test@example.com',
                password_hash=generate_password_hash('test123'),
                is_admin=False,
                tokens=500
            )
            db.session.add(test_user)
            print("✅ 创建测试用户: test/test123")
        
        # 添加测试公告
        announcements_count = Announcement.query.count()
        if announcements_count == 0:
            test_announcements = [
                {
                    'title': '欢迎使用智能对话系统',
                    'content': '欢迎使用我们的智能对话系统！您可以与AI进行文字对话、上传图片进行视觉对话、上传文档进行问答，以及进行批量对话处理。',
                    'is_active': True
                },
                {
                    'title': '系统功能更新',
                    'content': '我们新增了图像识别功能，现在您可以上传图片与AI进行视觉对话。支持JPG、PNG、GIF等常见图片格式。',
                    'is_active': True
                },
                {
                    'title': 'Token充值说明',
                    'content': '用户可以通过管理员充值Token，用于AI对话服务。每次对话都会消耗一定的Token，具体消耗量取决于对话长度和复杂度。',
                    'is_active': True
                },
                {
                    'title': '文件上传功能',
                    'content': '系统支持多种文件格式上传，包括PDF、DOC、DOCX、TXT等。AI可以分析文件内容并回答相关问题。',
                    'is_active': True
                },
                {
                    'title': '批量处理功能',
                    'content': '新增批量JSON数据处理功能，可以一次性处理大量数据，提高工作效率。适合大规模数据处理需求。',
                    'is_active': True
                }
            ]
            
            for announcement_data in test_announcements:
                announcement = Announcement(**announcement_data)
                db.session.add(announcement)
            
            print(f"✅ 添加了 {len(test_announcements)} 条测试公告")
        
        # 添加系统配置
        openai_config = SystemConfig.query.filter_by(key='openai_api_key').first()
        if not openai_config:
            openai_config = SystemConfig(
                key='openai_api_key',
                value='your-openai-api-key-here'
            )
            db.session.add(openai_config)
            print("⚠️ 请设置OpenAI API密钥")
        
        try:
            db.session.commit()
            print("🎉 系统初始化完成！")
            print("📋 默认账户:")
            print("  管理员: admin/admin123")
            print("  测试用户: test/test123")
            print("🌐 访问地址: http://localhost:5002")
        except Exception as e:
            print(f"❌ 初始化失败: {e}")
            db.session.rollback()
    
    app.run(debug=True, host='0.0.0.0', port=5001)