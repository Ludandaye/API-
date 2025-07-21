// 主要JavaScript文件
class Utils {
    // 显示消息
    static showMessage(message, type = 'info') {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            ${message}
        `;
        
        // 添加到页面顶部
        const mainContent = document.querySelector('.main-content');
        if (mainContent) {
            mainContent.insertBefore(messageDiv, mainContent.firstChild);
        }
        
        // 3秒后自动移除
        setTimeout(() => {
            messageDiv.remove();
        }, 3000);
    }
    
    // 格式化日期
    static formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
    
    // 格式化文件大小
    static formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // 防抖函数
    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    // 节流函数
    static throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
    
    // 验证邮箱
    static isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    // 验证密码强度
    static checkPasswordStrength(password) {
        let strength = 0;
        if (password.length >= 8) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        
        if (strength < 2) return 'weak';
        if (strength < 4) return 'medium';
        return 'strong';
    }
    
    // 复制到剪贴板
    static async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showMessage('已复制到剪贴板', 'success');
        } catch (err) {
            console.error('复制失败:', err);
            this.showMessage('复制失败', 'error');
        }
    }
    
    // 下载文件
    static downloadFile(data, filename, type = 'text/plain') {
        const blob = new Blob([data], { type });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }
    
    // 生成随机ID
    static generateId() {
        return Math.random().toString(36).substr(2, 9);
    }
    
    // 检查网络状态
    static checkOnlineStatus() {
        return navigator.onLine;
    }
    
    // 监听网络状态变化
    static onNetworkChange(callback) {
        window.addEventListener('online', () => callback(true));
        window.addEventListener('offline', () => callback(false));
    }
}

// API请求类
class API {
    static async request(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin'
        };
        
        const finalOptions = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, finalOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }
            
            return await response.text();
        } catch (error) {
            console.error('API请求失败:', error);
            throw error;
        }
    }
    
    static async get(url) {
        return this.request(url);
    }
    
    static async post(url, data) {
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
    
    static async put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
    
    static async delete(url) {
        return this.request(url, {
            method: 'DELETE'
        });
    }
}

// 本地存储类
class Storage {
    static set(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (error) {
            console.error('存储失败:', error);
        }
    }
    
    static get(key, defaultValue = null) {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (error) {
            console.error('读取失败:', error);
            return defaultValue;
        }
    }
    
    static remove(key) {
        try {
            localStorage.removeItem(key);
        } catch (error) {
            console.error('删除失败:', error);
        }
    }
    
    static clear() {
        try {
            localStorage.clear();
        } catch (error) {
            console.error('清空失败:', error);
        }
    }
}

// 表单验证类
class FormValidator {
    constructor(formElement) {
        this.form = formElement;
        this.errors = [];
        this.init();
    }
    
    init() {
        this.form.addEventListener('submit', (e) => {
            if (!this.validate()) {
                e.preventDefault();
                this.showErrors();
            }
        });
    }
    
    validate() {
        this.errors = [];
        const inputs = this.form.querySelectorAll('input, textarea, select');
        
        inputs.forEach(input => {
            if (input.hasAttribute('required') && !input.value.trim()) {
                this.errors.push(`${input.name || '字段'}不能为空`);
            }
            
            if (input.type === 'email' && input.value && !Utils.isValidEmail(input.value)) {
                this.errors.push('邮箱格式不正确');
            }
            
            if (input.type === 'password' && input.value) {
                const strength = Utils.checkPasswordStrength(input.value);
                if (strength === 'weak') {
                    this.errors.push('密码强度太弱');
                }
            }
        });
        
        return this.errors.length === 0;
    }
    
    showErrors() {
        this.errors.forEach(error => {
            Utils.showMessage(error, 'error');
        });
    }
}

// 模态框类
class Modal {
    constructor(modalId) {
        this.modal = document.getElementById(modalId);
        this.init();
    }
    
    init() {
        // 关闭按钮
        const closeBtn = this.modal.querySelector('.close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.close());
        }
        
        // 点击外部关闭
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.close();
            }
        });
        
        // ESC键关闭
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen()) {
                this.close();
            }
        });
    }
    
    open() {
        this.modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }
    
    close() {
        this.modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
    
    isOpen() {
        return this.modal.style.display === 'block';
    }
}

// 文件上传类
class FileUploader {
    constructor(options = {}) {
        this.options = {
            maxSize: 16 * 1024 * 1024, // 16MB
            allowedTypes: ['image/*', 'text/*', 'application/pdf'],
            ...options
        };
    }
    
    validateFile(file) {
        if (file.size > this.options.maxSize) {
            throw new Error(`文件大小不能超过${Utils.formatFileSize(this.options.maxSize)}`);
        }
        
        const isValidType = this.options.allowedTypes.some(type => {
            if (type.endsWith('/*')) {
                return file.type.startsWith(type.replace('/*', ''));
            }
            return file.type === type;
        });
        
        if (!isValidType) {
            throw new Error('不支持的文件类型');
        }
        
        return true;
    }
    
    async uploadFile(file, url) {
        try {
            this.validateFile(file);
            
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch(url, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error('上传失败');
            }
            
            return await response.json();
        } catch (error) {
            console.error('文件上传失败:', error);
            throw error;
        }
    }
    
    async uploadImage(file, url) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    
                    // 压缩图片
                    const maxWidth = 800;
                    const maxHeight = 600;
                    let { width, height } = img;
                    
                    if (width > height) {
                        if (width > maxWidth) {
                            height *= maxWidth / width;
                            width = maxWidth;
                        }
                    } else {
                        if (height > maxHeight) {
                            width *= maxHeight / height;
                            height = maxHeight;
                        }
                    }
                    
                    canvas.width = width;
                    canvas.height = height;
                    ctx.drawImage(img, 0, 0, width, height);
                    
                    canvas.toBlob((blob) => {
                        const compressedFile = new File([blob], file.name, {
                            type: 'image/jpeg',
                            lastModified: Date.now()
                        });
                        
                        this.uploadFile(compressedFile, url)
                            .then(resolve)
                            .catch(reject);
                    }, 'image/jpeg', 0.8);
                };
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);
        });
    }
}

// 聊天功能类
class ChatManager {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.options = {
            autoScroll: true,
            showTyping: true,
            ...options
        };
        this.messages = [];
        this.isTyping = false;
        this.init();
    }
    
    init() {
        if (this.options.autoScroll) {
            this.scrollToBottom();
        }
    }
    
    addMessage(content, role = 'user', timestamp = new Date()) {
        const message = {
            id: Utils.generateId(),
            content,
            role,
            timestamp
        };
        
        this.messages.push(message);
        this.renderMessage(message);
        
        if (this.options.autoScroll) {
            this.scrollToBottom();
        }
        
        return message;
    }
    
    renderMessage(message) {
        const messageElement = document.createElement('div');
        messageElement.className = `message ${message.role}`;
        messageElement.dataset.messageId = message.id;
        
        const avatar = message.role === 'user' ? 
            '<i class="fas fa-user"></i>' : 
            '<i class="fas fa-robot"></i>';
        
        const time = message.timestamp.toLocaleTimeString('zh-CN', {
            hour: '2-digit',
            minute: '2-digit'
        });
        
        messageElement.innerHTML = `
            <div class="message-avatar">${avatar}</div>
            <div class="message-content">
                <div class="message-text">${message.content}</div>
                <div class="message-time">${time}</div>
            </div>
        `;
        
        this.container.appendChild(messageElement);
    }
    
    showTyping() {
        if (this.isTyping) return;
        
        this.isTyping = true;
        const typingElement = document.createElement('div');
        typingElement.className = 'message assistant typing';
        typingElement.innerHTML = `
            <div class="message-avatar"><i class="fas fa-robot"></i></div>
            <div class="message-content">
                <div class="typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
        `;
        
        this.container.appendChild(typingElement);
        this.scrollToBottom();
    }
    
    hideTyping() {
        const typingElement = this.container.querySelector('.typing');
        if (typingElement) {
            typingElement.remove();
        }
        this.isTyping = false;
    }
    
    scrollToBottom() {
        this.container.scrollTop = this.container.scrollHeight;
    }
    
    clear() {
        this.container.innerHTML = '';
        this.messages = [];
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    // 初始化表单验证
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        new FormValidator(form);
    });
    
    // 初始化模态框
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        new Modal(modal.id);
    });
    
    // 网络状态监听
    Utils.onNetworkChange((isOnline) => {
        if (!isOnline) {
            Utils.showMessage('网络连接已断开', 'error');
        } else {
            Utils.showMessage('网络连接已恢复', 'success');
        }
    });
    
    // 添加页面加载动画
    const pageLoader = document.createElement('div');
    pageLoader.className = 'page-loader';
    pageLoader.innerHTML = '<div class="loader-spinner"></div>';
    document.body.appendChild(pageLoader);
    
    window.addEventListener('load', () => {
        setTimeout(() => {
            pageLoader.style.opacity = '0';
            setTimeout(() => {
                pageLoader.remove();
            }, 300);
        }, 500);
    });
});

// 导出到全局
window.Utils = Utils;
window.API = API;
window.Storage = Storage;
window.FormValidator = FormValidator;
window.Modal = Modal;
window.FileUploader = FileUploader;
window.ChatManager = ChatManager; 