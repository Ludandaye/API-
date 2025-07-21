document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const rememberMeCheckbox = document.getElementById('rememberMe');
    const togglePasswordBtn = document.getElementById('togglePassword');
    const form = document.getElementById('loginForm');

    // 加载本地存储中的用户名和密码
    const savedUsername = localStorage.getItem('username');
    const savedPassword = localStorage.getItem('password');
    const remember = localStorage.getItem('remember') === 'true';

    if (remember && savedUsername && savedPassword) {
        usernameInput.value = savedUsername;
        passwordInput.value = savedPassword;
        rememberMeCheckbox.checked = true;
    }

    // 显示/隐藏密码
    togglePasswordBtn.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type');
        if (type === 'password') {
            passwordInput.setAttribute('type', 'text');
            togglePasswordBtn.textContent = '🙈';
        } else {
            passwordInput.setAttribute('type', 'password');
            togglePasswordBtn.textContent = '👁️';
        }
    });

    // 提交时保存密码（如果勾选了“记住我”）
    form.addEventListener('submit', (e) => {
        e.preventDefault();

        if (rememberMeCheckbox.checked) {
            localStorage.setItem('username', usernameInput.value);
            localStorage.setItem('password', passwordInput.value);
            localStorage.setItem('remember', true);
        } else {
            localStorage.removeItem('username');
            localStorage.removeItem('password');
            localStorage.setItem('remember', false);
        }

        // 实际项目中：此处应提交数据到服务器
        alert('Login submitted (模拟提交)');
    });
});
