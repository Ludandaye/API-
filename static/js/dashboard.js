document.addEventListener('DOMContentLoaded', function() {
    // 检查登录状态
    if (!Utils.isLoggedIn()) {
        Utils.redirect('/login');
        return;
    }
    
    // 加载用户信息
    loadUserProfile();
    
    // 绑定事件
    bindEvents();
});

// 加载用户信息
async function loadUserProfile() {
    try {
        const response = await Utils.apiRequest('/api/user/profile');
        
        // 更新用户信息显示
        document.getElementById('username').textContent = response.username;
        document.getElementById('email').textContent = response.email;
        document.getElementById('createdAt').textContent = new Date(response.created_at).toLocaleString('zh-CN');
        document.getElementById('tokenCount').textContent = response.tokens;
        
    } catch (error) {
        Utils.showMessage('加载用户信息失败: ' + error.message, 'error');
        // 如果token无效，跳转到登录页
        if (error.message.includes('token')) {
            Utils.clearToken();
            Utils.redirect('/login');
        }
    }
}

// 绑定事件
function bindEvents() {
    // 登出按钮
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    
    // 使用token按钮
    document.getElementById('useTokenBtn').addEventListener('click', handleUseToken);
    
    // 添加token按钮
    document.getElementById('addTokenBtn').addEventListener('click', toggleAddTokenForm);
    
    // 确认添加token按钮
    document.getElementById('confirmAddTokenBtn').addEventListener('click', handleAddToken);
    
    // 测试API按钮
    document.getElementById('testApiBtn').addEventListener('click', handleTestApi);
}

// 处理登出
async function handleLogout() {
    try {
        await Utils.apiRequest('/api/logout', {
            method: 'POST'
        });
        
        Utils.clearToken();
        localStorage.removeItem('user');
        Utils.showMessage('登出成功', 'success');
        
        setTimeout(() => {
            Utils.redirect('/');
        }, 1000);
        
    } catch (error) {
        Utils.showMessage('登出失败: ' + error.message, 'error');
    }
}

// 处理使用token
async function handleUseToken() {
    try {
        const response = await Utils.apiRequest('/api/user/use-token', {
            method: 'POST'
        });
        
        // 更新token显示
        document.getElementById('tokenCount').textContent = response.remaining_tokens;
        Utils.showMessage(response.message, 'success');
        
    } catch (error) {
        Utils.showMessage(error.message, 'error');
    }
}

// 切换添加token表单显示
function toggleAddTokenForm() {
    const form = document.querySelector('.add-token-form');
    const isVisible = form.style.display !== 'none';
    
    if (isVisible) {
        form.style.display = 'none';
        document.getElementById('addTokenBtn').textContent = '添加Token';
    } else {
        form.style.display = 'flex';
        document.getElementById('addTokenBtn').textContent = '取消';
    }
}

// 处理添加token
async function handleAddToken() {
    const amount = document.getElementById('addTokenAmount').value;
    
    if (!amount || amount <= 0) {
        Utils.showMessage('请输入有效的token数量', 'error');
        return;
    }
    
    try {
        const response = await Utils.apiRequest('/api/user/add-tokens', {
            method: 'POST',
            body: JSON.stringify({
                amount: parseInt(amount)
            })
        });
        
        // 更新token显示
        document.getElementById('tokenCount').textContent = response.total_tokens;
        Utils.showMessage(response.message, 'success');
        
        // 隐藏表单并清空输入
        document.querySelector('.add-token-form').style.display = 'none';
        document.getElementById('addTokenAmount').value = '';
        document.getElementById('addTokenBtn').textContent = '添加Token';
        
    } catch (error) {
        Utils.showMessage(error.message, 'error');
    }
}

// 处理API测试
async function handleTestApi() {
    const apiResult = document.getElementById('apiResult');
    
    try {
        apiResult.textContent = '测试中...';
        
        const response = await Utils.apiRequest('/api/test');
        
        apiResult.textContent = JSON.stringify(response, null, 2);
        Utils.showMessage('API测试成功', 'success');
        
    } catch (error) {
        apiResult.textContent = 'API测试失败: ' + error.message;
        Utils.showMessage('API测试失败', 'error');
    }
} 