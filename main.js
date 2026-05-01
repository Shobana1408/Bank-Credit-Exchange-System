function togglePassword(inputId, element) {
    const input = document.getElementById(inputId);

    if (input.type === "password") {
        input.type = "text";
        element.textContent = "Hide";
    } else {
        input.type = "password";
        element.textContent = "Show";
    }
}