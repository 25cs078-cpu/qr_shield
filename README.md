# QR Shield — QR Safety Scanner

A front-end academic prototype for Product Development Lab. It decodes QR images locally in the browser, previews the payload without opening it, and runs explainable rule-based checks on URL content.

## Requirements
- VS Code
- Chrome or Edge
- Internet connection when first opening the page, because `jsQR` and `QRCode.js` are loaded from public CDNs
- Camera use requires `localhost` or HTTPS and browser permission

## Run it
1. Extract `QR_Shield_Website.zip`.
2. Open the extracted `qr_shield_website` folder in VS Code.
3. Recommended: install the **Live Server** extension.
4. Right-click `index.html` → **Open with Live Server**.
5. If you do not want to install an extension, you can open `index.html` directly for image-upload scanning. Camera access may not work from a `file://` page.
6. Click one of the demo buttons, then click **Analyze this QR**, or upload a QR image of your own.

## Files
- `index.html` — page structure and library CDN references
- `styles.css` — responsive dark cybersecurity UI
- `app.js` — QR decoding, camera scanning, URL rules, risk scoring, and findings

## Implemented features
- Upload or drag-and-drop an image
- QR decoding with `jsQR`
- Optional live camera scan
- Payload preview and copy action
- Rule-based URL checks with a risk score and explanation
- Demo QR generation for a sample URL, a synthetic suspicious URL, and plain text
- No automatic navigation to decoded destinations
- Image analysis and URL rules run in the browser; no backend is used

## Important limitations
- This is a rule-based prototype, not a trained AI model or a live threat-intelligence service.
- It does not check domain age, live reputation, redirect chains, or current phishing lists.
- HTTPS alone does not mean a website is trustworthy.
- A low score means only that these basic rules found few obvious indicators; it does not certify a URL as safe.
- The suspicious demo is synthetic and is not intended to be opened.
- The demo URL and rules are for educational demonstration only, not a replacement for a dedicated security product.

## Demo flow for lab
1. Click **Example URL** → **Analyze this QR**. Explain that HTTPS is a positive transport signal, not a safety guarantee.
2. Click **Suspicious URL** → **Analyze this QR**. Explain the IP-address host, HTTP, and account-related path indicators.
3. Click **Plain text** → **Analyze this QR**. Explain that the QR payload is decoded but not treated as a web URL.
4. Upload an image QR from your computer and show that the payload is displayed without navigating to it.
