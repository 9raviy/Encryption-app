// script.js

document.addEventListener("DOMContentLoaded", function () {
  // Add event listener to the encryption form
  const encryptionForm = document.getElementById("encryptionForm");
  if (encryptionForm) {
    encryptionForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      const text = document.getElementById("text").value;
      const algorithm = document.getElementById("algorithm").value;
      const user = document.getElementById("user").value;

      const response = await fetch("/encrypt", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ text, algorithm, user }),
      });

      const result = await response.json();
      if (response.ok) {
        // Display the encrypted text
        document.getElementById("displayEncryptedText").innerText =
          result.encrypted_text;
      } else {
        alert(result.error);
      }
    });
  }

  // Add event listener to the logout button
  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async function (event) {
      event.preventDefault();
      const response = await fetch("/logout", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      const result = await response.json();
      if (response.ok) {
        // Redirect to login page
        window.location.href = "/login";
      } else {
        console.error("Logout error:", result.error);
      }
    });
  }
});
