document
  .getElementById("encryptionForm")
  .addEventListener("submit", async function (event) {
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
      document.getElementById("encryptedText").innerText =
        result.encrypted_text;
    } else {
      alert(result.error);
    }
  });
