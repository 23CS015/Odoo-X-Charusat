chrome.runtime.onInstalled.addListener(() => {
    console.log("Click Shield installed and running.");
});
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "sendData") {
        fetch("http://127.0.0.1:8000/fetch-links/", {  // Change this to your Django API when ready
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(message.data)
        })
        .then(response => response.json())
        .then(data => console.log("Data sent successfully:", data))
        .catch(error => console.error("Error sending data:", error));
    }
});
