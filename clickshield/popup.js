document.getElementById("scanButton").addEventListener("click", () => {
    document.getElementById("status").innerText = "Scanning...";


    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            function: extractLinksAndClickables
        }, (results) => {
            if (chrome.runtime.lastError) {
                console.error("Script execution error:", chrome.runtime.lastError);
                document.getElementById("status").innerText = "Error extracting links.";
                return;
            }

            let extractedData = results[0].result;

            // Send extracted links to background.js
            chrome.runtime.sendMessage({ action: "sendData", data: extractedData }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Message passing error:", chrome.runtime.lastError);
                    document.getElementById("status").innerText = "Error sending request.";
                    return;
                }

                if (response && response.status === "success") {
                    displayResults(response.results);
                } else {
                    document.getElementById("status").innerText = "Error fetching scan results.";
                }
            });
        });
    });
});

function extractLinksAndClickables() {
    let elements = document.querySelectorAll("a, button, input[type=submit], [onclick]");
    let extractedData = [];

    elements.forEach(element => {
        let link = element.href || element.getAttribute("onclick") || "No direct link";
        extractedData.push({
            text: element.innerText || "No Text",
            link: link
        });
    });

    return extractedData;
}

function displayResults(results) {
    // Update the status
    document.getElementById("status").innerText = "Scan Completed";
    console.log(results);

    // Display Summary Section
    if (results.Summary) {
        let summarySection = document.getElementById("stats-container");
        summarySection.innerHTML = `
            <h4>Scan Summary</h4>
            <p><strong>Total Links:</strong> ${results.Summary["Total Links"]}</p>
            <p><strong>Safe Count:</strong> ${results.Summary["Safe Count"]}</p>
            <p><strong>Undetected Count:</strong> ${results.Summary["Undetected Count"]}</p>
            <p><strong>Malicious Count:</strong> ${results.Summary["Malicious Count"]}</p>
            <hr>
        `;
    }

    // Clear previous lists before adding new ones
    document.getElementById("safe-links").innerHTML = '';
    document.getElementById("undetected-links").innerHTML = '';
    document.getElementById("malicious-links").innerHTML = '';

    // Categorize and Display Links in their respective sections
    ["Safe", "Undetected", "Malicious"].forEach(category => {
        if (results[category].length > 0) {
            let container = document.getElementById(`${category.toLowerCase()}-links`);
            results[category].forEach(item => {
                let listItem = document.createElement("li");
                listItem.innerHTML = `<a href="${item.URL}" target="_blank">${item.URL}</a>`;
                container.appendChild(listItem);
            });
        }
    });
}


