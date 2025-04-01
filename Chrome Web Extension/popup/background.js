chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkLinkWithVirusTotal') {
      const vtApiKey = 'YOUR_VIRUSTOTAL_API_KEY_HERE';
    
      // Encode the URL into Base64 (Required by VirusTotal)
      const urlToEncode = request.url.trim(); // Remove any leading/trailing whitespace
      const encodedUrl = base64UrlEncode(urlToEncode);
      console.log("Base64 Encoded URL:", encodedUrl);
  
      // Step 2: Use the Base64 encoded URL in the VirusTotal API call
      const vtUrl = `https://www.virustotal.com/api/v3/urls/${encodedUrl}`;
  
      fetch(vtUrl, {
        method: 'GET',
        headers: {
          accept: 'application/json',
          'x-apikey': vtApiKey
        }
      })
        .then(response => response.json())
        .then(data => {
          console.log('VirusTotal API Response:', data); // Log full response
          const maliciousVotes = data.data.attributes.last_analysis_stats.malicious || 0;
          sendResponse({
            isMalicious: maliciousVotes > 0,
            reason: maliciousVotes > 0 ? `Detected by VirusTotal (${maliciousVotes} malicious votes)` : ''
          });
        })
        .catch(error => {
          console.error('VirusTotal fetch error:', error);
          sendResponse({ isMalicious: false });
        });
      return true; // Keeps the message channel open for async sendResponse
    }
  });

  // VirusTotal requires that a URL be encoded before verifications
  function base64UrlEncode(input) {
    // Encode input into a UTF-8 byte array
    const encoder = new TextEncoder();
    const bytes = encoder.encode(input);
  
    // Convert to Base64 string
    const base64String = btoa(String.fromCharCode(...bytes));
  
    // Make Base64 URL-safe by replacing characters and trimming '='
    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
