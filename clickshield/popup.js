document.getElementById("scanButton").addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            function: extractLinksAndClickables
        }, (results) => {
            if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError);
                return;
            }
            let extractedData = results[0].result;
            chrome.runtime.sendMessage({ action: "sendData", data: extractedData });
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
            link: link,
            tag: element.tagName.toLowerCase()
        });
    });

    return extractedData;
}
