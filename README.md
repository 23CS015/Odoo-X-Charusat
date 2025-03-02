# ClickShield

ClickShield is a comprehensive Chrome extension that provides real-time security analysis of links and clickable elements as you browse the web. The extension helps you identify potentially malicious links before you click on them, protecting you from phishing attempts, malware, and other web-based threats.

![ClickShield Logo](icon.png)

## Features

- **Automated Link Scanning**: Automatically scans all links on a webpage to identify potential security threats
- **Manual URL Checking**: Enter any URL to check its security status
- **Detailed Security Reports**: Generate comprehensive security reports that can be saved or shared
- **Local Cache**: Stores scan results locally for quick access, even when offline
- **Real-time Analysis**: Get immediate feedback on link safety with color-coded indicators
- **Threat Intelligence**: Leverages multiple security databases to provide accurate threat assessments
- **Malicious Link Blocking**: Option to automatically block known malicious links
- **User-friendly Interface**: Clean and intuitive design for easy navigation

## Demo

[Watch the Demo Video](https://drive.google.com/file/d/1L7z43LoqWQEnTcPVPWaNZSYrL2VUgjYT/view?usp=sharing)

## Installation

### Prerequisites

- Google Chrome Browser
- Python 3.8 or higher
- Django 4.0 or higher
- pip (Python package manager)

### Backend Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/clickshield.git
   cd clickshield
   ```

2. Create a virtual environment (recommended):
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```
     source venv/bin/activate
     ```

4. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Set up the Django project:
   ```
   cd clickshield_backend
   python manage.py migrate
   ```

6. Start the Django development server:
   ```
   python manage.py runserver
   ```
   The server will start on http://127.0.0.1:8000/

### Chrome Extension Setup

1. Open Google Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" by toggling the switch in the top-right corner
3. Click "Load unpacked" and select the `extension` directory from the cloned repository
4. The ClickShield extension should now be installed and visible in your extensions toolbar

## Usage

### Scanning Links on a Page

1. Navigate to any webpage
2. Click the ClickShield icon in the extensions toolbar
3. Click the "Auto Scan Links" button
4. View the categorized links (Safe, Undetected, Malicious) in the popup

### Manually Checking a URL

1. Click the ClickShield icon
2. Enter a URL in the search box
3. Click "Check"
4. View the detailed security report for the URL

### Generating a Report

1. After scanning a page or checking URLs manually
2. Click the "Generate Report" button
3. A detailed HTML report will be generated
4. Click "View Detailed Report" to open the report in a new tab
5. The report can be saved or printed for future reference

## Project Structure

```
clickshield/
├── extension/               # Chrome extension files
│   ├── background.js        # Background script
│   ├── popup.html           # Extension popup interface
│   ├── popup.js             # Popup functionality
│   └── icon.png             # Extension icon
├── clickshield_backend/     # Django backend
│   ├── clickshield_api/     # API application
│   │   ├── views.py         # API endpoints
│   │   ├── urls.py          # URL routing
│   │   └── models.py        # Data models
│   ├── static/              # Static files
│   │   └── reports/         # Generated reports
│   └── manage.py            # Django management script
└── requirements.txt         # Python dependencies
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Considerations

ClickShield is designed to help identify potentially malicious links, but it should not be considered a replacement for comprehensive security practices. Always exercise caution when clicking on links from unknown sources, even if ClickShield indicates they are safe.

## Acknowledgments

- [VirusTotal API](https://developers.virustotal.com/reference/overview) for security intelligence
- [Django REST framework](https://www.django-rest-framework.org/) for API development
- [Chrome Extensions API](https://developer.chrome.com/docs/extensions/) for browser integration

## Support

For support, feature requests, or bug reports, please open an issue in the GitHub repository or contact the project maintainers.