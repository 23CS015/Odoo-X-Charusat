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

// Send extracted data to background.js
chrome.runtime.sendMessage({
    action: "sendData",
    data: extractLinksAndClickables()
});
