document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('signup-form');
    const usernameInput = document.getElementById('username');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const passwordStrength = document.getElementById('password-strength');
    const submitBtn = document.getElementById('submit-btn');

    function validatePassword() {
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        let strength = 0;
        let message = 'Password strength: ';

        // Password strength checks
        if (password.length >= 8) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;

        // Update strength message and styling
        if (strength === 0) {
            message += 'None';
            passwordStrength.className = '';
        } else if (strength <= 2) {
            message += 'Weak';
            passwordStrength.className = 'strength-weak';
        } else if (strength <= 4) {
            message += 'Medium';
            passwordStrength.className = 'strength-medium';
        } else {
            message += 'Strong';
            passwordStrength.className = 'strength-strong';
        }

        passwordStrength.textContent = message;

        // Check if passwords match and strength is sufficient
        const passwordsMatch = password === confirmPassword;
        const isStrongEnough = strength >= 3; // Require at least medium strength
        const allFieldsFilled = usernameInput.value && emailInput.value && password;
        submitBtn.disabled = !passwordsMatch || !isStrongEnough || !allFieldsFilled;

        // Provide feedback if passwords don't match
        if (confirmPassword && !passwordsMatch) {
            confirmPasswordInput.setCustomValidity('Passwords do not match');
        } else {
            confirmPasswordInput.setCustomValidity('');
        }
    }

    // Event listeners
    passwordInput.addEventListener('input', validatePassword);
    confirmPasswordInput.addEventListener('input', validatePassword);
    usernameInput.addEventListener('input', validatePassword);
    emailInput.addEventListener('input', validatePassword);

    form.addEventListener('submit', (e) => {
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        if (password !== confirmPassword) {
            e.preventDefault();
            alert('Passwords do not match!');
            return false;
        }
    });
});