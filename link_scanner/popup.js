document.addEventListener("DOMContentLoaded", function () {
    let button = document.getElementById("scanLinks");

    button.addEventListener("click", async () => {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        chrome.scripting.executeScript({
            target: { tabId: tab.id },
            function: () => {
                let links = [];

                // Get all <a> tags with href attributes
                document.querySelectorAll("a[href]").forEach(link => {
                    links.push({ text: link.innerText, url: link.href });
                });

                // Get all clickable elements (buttons, inputs)
                document.querySelectorAll("button, input[type='button'], input[type='submit']").forEach(btn => {
                    links.push({ text: btn.innerText || btn.value, url: "N/A" });
                });

                return links;
            }
        }, (result) => {
            let links = result[0].result;
            document.getElementById("output").textContent = JSON.stringify(links, null, 2);
        });
    });
});
