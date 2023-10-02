    const emailField = document.getElementById('id_email');
    const emailValidOut = document.querySelector('.email-valid-out');
    const emailFeedbackField = document.querySelector('.email-feedback');

    emailField.addEventListener('keyup', (e) => {
            console.log("hi");
            const emailValue = e.target.value;
            emailValidOut.style.display = 'block';
            emailField.classList.remove('is-invalid');
            emailFeedbackField.style.display = 'none';

            if (emailValue.length > 0) {
                emailValidOut.textContent = `Checking Email ${emailValue}`;
                fetch('email-validate/', {
                    body: JSON.stringify({ email: emailValue }),
                    method: "POST",
                    credentials: "same-origin",
                    headers: {
                        "X-CSRFToken": getCookie("csrftoken"),
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    },
                })
                .then((res) => res.json())
                .then(data => {
                    emailValidOut.style.display = 'none';
                    if (data.email_error) {
                        emailField.classList.add('is-invalid');
                        emailFeedbackField.style.display = 'block';
                        emailFeedbackField.innerHTML = `<p>${data.email_error}</p>`;
                    }
                });
            }
        });