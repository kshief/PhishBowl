// Written  by Kashief Lika
// Created: Sept 14, 2024
// This JavaScript file contains the main programming functionality for the Chrome Extension
// Utilizes two other JS files called "content-script.js" and "background.js"

// content-script.js handles the content the user sees (e.g. gets the current selected email from the DOM)
// background.js handles the background API calls for VirusTotal

document.addEventListener("DOMContentLoaded", function() {
  const fetchDataButton = document.getElementById("extractButtonId");
  
  // Event listeners for user-selected options/settings
  const autoRetrieveToggle = document.getElementById("autoButtonId");
  const checkGrammarCheckbox = document.getElementById("grammarButtonId");
  const checkSentimentCheckbox = document.getElementById("sentimentButtonId");
  const checkLinksCheckbox = document.getElementById("linkCheckButtonId");


  // The question mark icon and the tooltip div
  const questionMark = document.getElementById("questionMarkPNG");
  const tooltip = document.getElementById("tooltip");

  // Toggle the tooltip on hover
  questionMark.addEventListener("mouseover", () => {
    tooltip.classList.add("show");
});
// Remove tooltip on mouse leave
questionMark.addEventListener("mouseleave", () => {
    if (!tooltip.classList.contains("clicked")) {
        tooltip.classList.remove("show");
    }
});

    // Event listener for the auto-retrieve checkbox
    autoRetrieveToggle.addEventListener("change", function() {
      const autoSettingStatus = autoRetrieveToggle.checked;
      // Save the state of the checkbox
      chrome.storage.sync.set({ autoSettingStatus }, function () {
        console.log("Auto-retrieve setting saved:", autoSettingStatus);
      });
    });

    // Event listener for the grammar checkbox
    checkGrammarCheckbox.addEventListener("change", function() {
      const grammarSettingStatus = checkGrammarCheckbox.checked;
      // Save the state of the checkbox
      chrome.storage.sync.set({ grammarSettingStatus }, function () {
      console.log("Grammar setting saved:", grammarSettingStatus);
    });
  });

    // Event listener for the sentiment checkbox
    checkSentimentCheckbox.addEventListener("change", function() {
      const sentimentSettingStatus = checkSentimentCheckbox.checked;
      // Save the state of the checkbox
      chrome.storage.sync.set({ sentimentSettingStatus }, function () {
      console.log("Sentiment setting saved:", sentimentSettingStatus);
    });
  });

    // Event listener for the link checkbox
    checkLinksCheckbox.addEventListener("change", function() {
      const linkSettingStatus = checkLinksCheckbox.checked;
      // Save the state of the checkbox
      chrome.storage.sync.set({ linkSettingStatus }, function () {
      console.log("Link setting saved:", linkSettingStatus);
    });
  });


  // Load the saved state of the extension from Chrome's storage and execute accordingly
  chrome.storage.sync.get(
    ["autoSettingStatus", "grammarSettingStatus", "sentimentSettingStatus", "linkSettingStatus"], 
    function(data) {
  const { 
    autoSettingStatus = false, 
    sentimentSettingStatus = false, 
    linkSettingStatus = false, 
    grammarSettingStatus = false 
  } = data;
  // Ensure these are boolean values before setting the checkbox checked state
  if (autoRetrieveToggle) autoRetrieveToggle.checked = Boolean(autoSettingStatus);
  if (checkSentimentCheckbox) checkSentimentCheckbox.checked = Boolean(sentimentSettingStatus);
  if (checkLinksCheckbox) checkLinksCheckbox.checked = Boolean(linkSettingStatus);
  if (checkGrammarCheckbox) checkGrammarCheckbox.checked = Boolean(grammarSettingStatus);

    if (autoSettingStatus) {
    // Auto-retrieve is enabled, so fetch the email data automatically
    // Get the active Gmail tab
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      const activeTab = tabs[0];

      // Inject the content script to extract messageId from the active Gmail tab
      chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        files: ['popup/content-scripts.js'] // Injects the content script
      });

      // Listen for the message containing the messageId
      chrome.runtime.onMessage.addListener(async function(message, sender, sendResponse) {
        if (message.messageId) {
          console.log('Message ID:', message.messageId);
          const token = await getAuthToken();
          await getEmailData(token, message.messageId); // Fetch and display email data
        } else {
          console.error('No messageId found');
        }
      });
    });
  }
});
    // Event listener for the manual button
  fetchDataButton.addEventListener("click", async function() {
    // Get the active Gmail tab
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      const activeTab = tabs[0];

      // Inject the content script to extract messageId from the active Gmail tab
      chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        files: ['popup/content-scripts.js'] // Injects the content script
      });

      // Listen for the message containing the messageId
      chrome.runtime.onMessage.addListener(async function(message, sender, sendResponse) {
        if (message.messageId) {
          console.log('MessageId:', message.messageId);
          const token = await getAuthToken();
          await getEmailData(token, message.messageId); // Fetch and display email data
        } else {
          console.error('No messageId found');
        }
      });
    });
  });
});

// Function to get OAuth2 token
function getAuthToken() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, (token) => {
      if (token) resolve(token);
      else reject('Failed to retrieve OAuth token');
    });
  });
}

// Function to fetch the email data the user currently has opened
async function getEmailData(token, messageId) {
  if (!messageId) {
    console.error('MessageId is null');
    return;
  }
  try {
    const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch email');
    }

    const email = await response.json();
    console.log('Email data:', email);

    displayExtractionResults(email);

  } catch (error) {
    console.error('Error fetching email data:', error);
  }
}

// Function to extract the DKIM, SPF, and DMARC results from the email headers
function extractAuthenticationResults(headers) {
  let dkim = 'None';
  let spf = 'None';
  let dmarc = 'None';

  headers.forEach(header => {
    if (header.name === 'Authentication-Results') {
      const authResults = header.value.split(';');
      authResults.forEach(result => {
        if (result.trim().startsWith('dkim=')) {
          // Extract result after 'dkim='
          dkim = result.split('=')[1].split(' ')[0].trim();
        } else if (result.trim().startsWith('spf=')) {
          // Extract result after 'spf='
          spf = result.split('=')[1].split(' ')[0].trim();
        } else if (result.trim().startsWith('dmarc=')) {
          // Extract result after 'dmarc='
          dmarc = result.split('=')[1].split(' ')[0].trim();
        }
      });
    }
  });
  console.log("original arc: ", dkim, spf, dmarc )
  return { dkim, spf, dmarc };
}

// Function to convert raw email text into plain text
function sanitizeHTML(bodyAndSubjectText) {
  // Ensure the input is a string
  if (typeof bodyAndSubjectText !== 'string') {
    bodyAndSubjectText = String(bodyAndSubjectText || '');
  }

  // Remove <style> and <script> blocks along with their content
  bodyAndSubjectText = bodyAndSubjectText.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');
  bodyAndSubjectText = bodyAndSubjectText.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');

  // Remove all HTML tags
  bodyAndSubjectText = bodyAndSubjectText.replace(/<[^>]*>/g, '');

  // Remove any remaining inline CSS or media queries
  bodyAndSubjectText = bodyAndSubjectText.replace(/@media[^{]*\{[\s\S]*?\}/gi, '');

  return bodyAndSubjectText.trim();
}

// Function to generate a session id using current timestamp (Required by Sapling API)
function generateSessionId() {
  return 'session_' + Date.now();  // Simple session id using timestamp
}

// Function to generate a grammar check request to Sapling API
async function checkGrammarWithSapling(text) {

  const saplingApiKey = 'YOUR_SAPLING_API_KEY_HERE'; 
  const saplingUrl = 'https://api.sapling.ai/api/v1/edits';

  const sessionId = generateSessionId();

  const requestData = {
    text: text,
    key: saplingApiKey,
    session_id: sessionId  // Include the session ID
  };

  try {
    const response = await fetch(saplingUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestData)
    });
  
    if (!response.ok) {

      const errorText = await response.text();
      console.error('Error from Sapling API:', errorText);  // Log detailed error response
      
      throw new Error('Failed to check grammar ' + response.status);
    }

    // Read and parse the response as JSON (only once)
    const result = await response.json();
    
    return result.edits; // Return the grammar edits

  } catch (error) {
    console.error('Error checking grammar:', error.message || error);
    return [];
  }
}

// Function to analyze sentiment via Sapling API
async function analyzeSentimentWithSapling(text) {
  const saplingApiKey = 'YOUR_SAPLING_API_KEY_HERE'; 
  const saplingUrl = 'https://api.sapling.ai/api/v1/sentiment';

  const sessionId = generateSessionId();

  const requestData = {
    text: text,
    key: saplingApiKey,
    session_id: sessionId
  };

  console.log("Request data:", requestData);

  try {
    const response = await fetch(saplingUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestData)
    });

    console.log("API response status:", response.status);

    const result = await response.json();
    console.log(result);

    // Extract the overall sentiment from the first element of the array
    const overallSentimentArray = result.overall; // Assuming 'overall' contains the sentiment array
    if (Array.isArray(overallSentimentArray) && overallSentimentArray.length > 0) {
      const [score, sentimentLabel] = overallSentimentArray[0]; // Extract the first element
      console.log("Overall Sentiment:", sentimentLabel, "Score:", score);
      return sentimentLabel; // Return the label ("POSITIVE", "NEGATIVE", "NEUTRAL")
    }
  } catch (error) {
    console.error('Error analyzing sentiment:', error);
    return 'Unknown';
  }
}

// Function to check link(s) with VirusTotal, utilizes background script to avoid CORS related issues
async function checkLinkWithVirusTotal(link) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { action: 'checkLinkWithVirusTotal', url: link },
      (response) => {
        console.log('VirusTotal response:', response);
        resolve(response);
      }
    );
  });
}

// Function that extracts links from raw text data, calls checkLinkWithVirusTotal 
async function analyzeLinksForSuspicion(emailText) {

  // Use a regex to extract valid URLs
  const urlRegex = /(https?:\/\/[^"'>\s]+)/gi; // Match URLs and avoid trailing HTML attributes

  const links = emailText.match(urlRegex) || [];
  console.log('Extracted link(s):', links);

  const suspiciousLinks = [];

  for (const link of links) {
    let isSuspicious = false;
    let reason = '';

    // VirusTotal API check for URL reputation
    const vtResult = await checkLinkWithVirusTotal(link);
    if (vtResult.isMalicious) {
      isSuspicious = true;
      reason = vtResult.reason || 'Flagged by VirusTotal';
    }

    if (isSuspicious) {
      suspiciousLinks.push({ link, reason });
    }
  }

  return suspiciousLinks;
}

// Function to calculate Social Engineering likeness score, 10 point scale
function calculatePhishingScore({ 
  dkim, 
  spf, 
  dmarc, 
  linkSetting, 
  grammarSetting, 
  sentimentSetting, 
  linkCheckResults, 
  grammarEdits, 
  sentimentScore 
}) {
  let score = 0;

  // DKIM evaluation (weight: 2)
  if (dkim === "pass") {
    score += 2;
  } else if (dkim === "neutral" || dkim === "None") {
    score += 1;
  } else if (dkim === "fail" || dkim === "softfail" || dkim === "temperror" || dkim === "permerror") {
    score += 0;
  }

  // SPF evaluation (weight: 2)
  if (spf === "pass") {
    score += 2;
  } else if (spf === "neutral" || spf === "None") {
    score += 1;
  } else if (spf === "softfail" || spf === "temperror" || spf === "permerror") {
    score += 0;
  }

  // DMARC evaluation (weight: 2)
  if (dmarc === "pass") {
    score += 2;
  } else if (dmarc === "neutral" || dmarc === "None") {
    score += 1;
  } else if (dmarc === "fail" || dmarc === "softfail" || dmarc === "temperror" || dmarc === "permerror") {
    score += 0;
  }

  // Link verification (weight: 2)
  if (!linkSetting) {
    // User didn't select link verification, so it gets full points
    score += 2;
  } else {
    // If any malicious findings, no points; otherwise, full points
    score += linkCheckResults.length === 0 ? 2 : 0;
  }

  // Grammar check (weight: 1)
  if (!grammarSetting) {
    // User didn't select grammar check, so it gets full points
    score += 1;
  } else {
    // If there are grammar errors, no points; otherwise, full points
    score += grammarEdits.length === 0 ? 1 : 0;
  }

  // Sentiment analysis (weight: 1)
  if (!sentimentSetting) {
    // User didn't select sentiment analysis, so it gets full points
    score += 1;
  } else {
    // Assign points based on sentiment score
    if (sentimentScore === "POSITIVE") {
      score += 1;
    } else if (sentimentScore === "NEUTRAL") {
      score += 0.5; // Half points for neutral sentiment
    }
    // No points for negative sentiment
  }

  // Return a score scaled to a percentage
  return Math.round((score / 10) * 100);
}


// Function to display results from DKIM, SPF, DMARC, From, and grammar/connotation results data of email message
async function displayExtractionResults(email) {

  const checkGrammarCheckbox = document.getElementById("grammarButtonId");
  const checkSentimentCheckbox = document.getElementById("sentimentButtonId");
  const checkLinksCheckbox = document.getElementById("linkCheckButtonId");
  const resultDiv = document.getElementById("result");

  const subject = email.payload.headers.find(header => header.name === 'Subject')?.value || 'No Subject';
  
  // Extract DKIM, SPF, DMARC from Authentication-Results header
  const { dkim, spf, dmarc } = extractAuthenticationResults(email.payload.headers);

  let body = 'No Body';
  if (email.payload.parts) {
    const part = email.payload.parts.find(p => p.mimeType === 'text/html'); // Get HTML part
    if (part && part.body && part.body.data) {
      body = decodeURIComponent(escape(window.atob(part.body.data.replace(/-/g, '+').replace(/_/g, '/'))));
    }
  }

  // Combine subject and body for analysis
  const emailText = `${subject} ${body}`;
  console.log(`Raw body and subject text length: ${emailText.length}`);

  const plainText = sanitizeHTML(emailText);
  console.log(`Plain body and subject text length: ${plainText.length}`);
  console.log("Plain body and subject:", plainText);
  
  // Initialize variables as empty/null
  let grammarEdits = []; 
  let sentimentScore = null; 
  let linkCheckResults = []; 

    // Check Grammar if the user has selected it
  if (checkGrammarCheckbox.checked) {
      grammarEdits = await checkGrammarWithSapling(plainText);
      console.log(grammarEdits);
  }
    // Check for sentiment if the user has selected it
    // Returns the overall tone if there is more than one sentence
    if (checkSentimentCheckbox.checked) {
      sentimentScore = await analyzeSentimentWithSapling(plainText);
      console.log(sentimentScore);
  }
  // Analyze links with VirusTotal and display results if the user has it selected
  if (checkLinksCheckbox.checked) {
      linkCheckResults = await analyzeLinksForSuspicion(emailText);
      console.log("Log links here:", linkCheckResults);
  }

  // Gather user-selected options
  const grammarSetting = checkGrammarCheckbox.checked;
  const sentimentSetting = checkSentimentCheckbox.checked;
  const linkSetting = checkLinksCheckbox.checked;
  console.log(grammarSetting, sentimentSetting, linkSetting);

  // Calculate phishing score
  const phishingScore = calculatePhishingScore({
    dkim,
    spf,
    dmarc,
    linkSetting,
    grammarSetting,
    sentimentSetting,
    linkCheckResults,
    grammarEdits,
    sentimentScore
});

  // Display results
  resultDiv.innerHTML = `
    <hr>
    <div><strong>DKIM:</strong> ${dkim}</div>
    <div><strong>SPF:</strong> ${spf}</div>
    <div><strong>DMARC:</strong> ${dmarc}</div>
    <br>
    <div><strong>Score:</strong> 
      <span style="color: ${phishingScore > 70 ? 'green' : phishingScore > 40 ? 'orange' : 'red'};">
        ${phishingScore}%
      </span>
    </div>
    <br>
  `;

  // Optionally, display detailed grammar errors, sentiment, or link results
  if (checkGrammarCheckbox.checked) displayGrammarErrors(grammarEdits);
  if (checkSentimentCheckbox.checked) {
    resultDiv.innerHTML += `<div><strong>Text Sentiment:</strong> ${sentimentScore}</div>`;
  }
  if (checkLinksCheckbox.checked) {
    if (linkCheckResults.length > 0) {
      resultDiv.innerHTML += `
        <div><strong>Suspicious Links:</strong>
        ${linkCheckResults.map(link => `${link.link} - ${link.reason}`).join('')}</div>
      `;
    } else {
      resultDiv.innerHTML += `<div><strong>No suspicious links detected.</strong></div>`;
    }
  }
}

// Function to display grammar error summary
function displayGrammarErrors(edits) {
  
  const resultDiv = document.getElementById("result");
  
  if (edits.length > 0) {
    const errorTypes = edits.reduce((acc, edit) => {
      const type = edit.type || 'Unknown Error';
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {});

    const errorSummary = Object.entries(errorTypes)
      .map(([type, count]) => `<div><strong>${type}:</strong> ${count} occurrence(s)</div>`)
      .join('');

    resultDiv.innerHTML += `
    <br>
      <div>
        <strong>Total Grammar Errors Found:</strong> ${edits.length}
      </div>
      ${errorSummary}
    `;
  } else {
    resultDiv.innerHTML += `
      <div>
        <strong>No grammar errors detected.</strong>
      </div>
    `;
  }
}