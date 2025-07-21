document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    const messageDiv = document.getElementById('message');

    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        // 验证输入
        if (!username || !email || !password || !confirmPassword) {
            Utils.showMessage('请填写所有字段', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            Utils.showMessage('两次输入的密码不一致', 'error');
            return;
        }
        
        if (password.length < 6) {
            Utils.showMessage('密码长度至少6位', 'error');
            return;
        }
        
        // 验证邮箱格式
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            Utils.showMessage('请输入有效的邮箱地址', 'error');
            return;
        }
        
        try {
            // 显示加载状态
            const submitBtn = registerForm.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '注册中...';
            submitBtn.disabled = true;
            
            // 发送注册请求
            const response = await Utils.apiRequest('/api/register', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    email: email,
                    password: password
                })
            });
            
            // 显示成功消息
            Utils.showMessage('注册成功！请登录', 'success');
            
            // 跳转到登录页面
            setTimeout(() => {
                Utils.redirect('/login');
            }, 1500);
            
        } catch (error) {
            Utils.showMessage(error.message || '注册失败', 'error');
        } finally {
            // 恢复按钮状态
            const submitBtn = registerForm.querySelector('button[type="submit"]');
            submitBtn.textContent = '注册';
            submitBtn.disabled = false;
        }
    });
}); 