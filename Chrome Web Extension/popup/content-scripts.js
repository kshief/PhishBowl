// Function to extract the messageId from the Gmail interface
(function() {
function getMessageIdFromDom() {
    const messageElement = document.querySelector("[data-legacy-message-id]");
    return messageElement ? messageElement.getAttribute("data-legacy-message-id") : null;
  }
  
  // Get the messageId either from the URL or from the DOM
  const messageId = getMessageIdFromDom();
  
  if (messageId) {
    // Send the messageId back to the popup script
    chrome.runtime.sendMessage({ messageId });
  } else {
    console.error('No messageId found');
  }
})();
