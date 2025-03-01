// Create an icon element
const icon = document.createElement("img");
icon.src = chrome.runtime.getURL("hover-icon.png"); // Add your icon here
icon.style.position = "absolute";
icon.style.width = "20px";
icon.style.height = "20px";
icon.style.pointerEvents = "none"; // Prevents interference with clicks
icon.style.display = "none"; // Hide initially
document.body.appendChild(icon);

// Function to show the icon near the cursor
function showIcon(event) {
    icon.style.left = `${event.pageX + 10}px`; // Offset to avoid overlap
    icon.style.top = `${event.pageY + 10}px`;
    icon.style.display = "block";
}

// Function to hide the icon
function hideIcon() {
    icon.style.display = "none";
}

// Add hover event listeners for all clickable elements
document.addEventListener("mouseover", (event) => {
    if (event.target.tagName === "A" || event.target.onclick || event.target.tagName === "BUTTON") {
        showIcon(event);
    }
});

document.addEventListener("mousemove", showIcon);
document.addEventListener("mouseout", hideIcon);
