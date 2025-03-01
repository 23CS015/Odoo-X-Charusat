chrome.runtime.onInstalled.addListener(() => {
    console.log("Click Shield installed and running.");
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "sendData") {
        fetch("http://127.0.0.1:8000/fetch-links/", {  // Django API URL
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(message.data)
        })
        .then(response => response.json())
        .then(data => {
            console.log("Data received from Django:", data);
            sendResponse({ status: "success", results: data.results });
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            sendResponse({ status: "error", message: "Failed to fetch scan results." });
        });

        return true;  // IMPORTANT: Keeps the message port open for async response
    }
});
