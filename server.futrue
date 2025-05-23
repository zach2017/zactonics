const express = require('express');
const app = express();
const port = 3000;

// Static JSON data for the dashboard
const threatData = {
  systems: [
    { id: 1, name: 'Web Server 01', status: 'Critical', threatLevel: 'High', vulnerabilities: ['CVE-2025-1234', 'CVE-2025-5678'], lastScan: '2025-05-22' },
    { id: 2, name: 'Database Server', status: 'Stable', threatLevel: 'Low', vulnerabilities: [], lastScan: '2025-05-21' },
    { id: 3, name: 'File Server', status: 'Warning', threatLevel: 'Medium', vulnerabilities: ['CVE-2025-9012'], lastScan: '2025-05-20' }
  ],
  applications: [
    { id: 1, name: 'CRM App', version: '2.1.3', status: 'Exposed', threats: ['SQL Injection', 'XSS'], lastUpdate: '2025-05-15' },
    { id: 2, name: 'HR Portal', version: '1.4.0', status: 'Secure', threats: [], lastUpdate: '2025-05-10' }
  ],
  buildPipelines: [
    { id: 1, name: 'Frontend CI/CD', status: 'Running', securityIssues: ['Unsecured API Key'], lastRun: '2025-05-23 08:00' },
    { id: 2, name: 'Backend CI/CD', status: 'Failed', securityIssues: ['Hardcoded Credentials'], lastRun: '2025-05-22 14:30' }
  ],
  cloudServices: [
    { id: 1, name: 'AWS S3 Bucket', status: 'Public', risks: ['Misconfigured Permissions'], lastChecked: '2025-05-22' },
    { id: 2, name: 'Azure VM', status: 'Secure', risks: [], lastChecked: '2025-05-21' }
  ],
  threatCategories: [
    { category: 'Malware', count: 12, severity: 'High', description: 'Detected malicious software attempts' },
    { category: 'Phishing', count: 25, severity: 'Medium', description: 'Suspicious email campaigns' },
    { category: 'DDoS', count: 3, severity: 'Critical', description: 'Distributed denial-of-service attacks' },
    { category: 'Insider Threats', count: 5, severity: 'Low', description: 'Unauthorized internal access attempts' }
  ]
};

// Middleware to enable CORS (optional, for cross-origin requests)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// API Endpoints
app.get('/api/systems', (req, res) => {
  res.json(threatData.systems);
});

app.get('/api/applications', (req, res) => {
  res.json(threatData.applications);
});

app.get('/api/build-pipelines', (req, res) => {
  res.json(threatData.buildPipelines);
});

app.get('/api/cloud-services', (req, res) => {
  res.json(threatData.cloudServices);
});

app.get('/api/threat-categories', (req, res) => {
  res.json(threatData.threatCategories);
});

app.get('/api/details', (req, res) => {
  res.json({ details: 'a detail is come'});
});

// Root endpoint for API status
app.get('/', (req, res) => {
  res.json({
    message: 'Threat Intelligence API',
    endpoints: [
      '/api/systems',
      '/api/applications',
      '/api/build-pipelines',
      '/api/cloud-services',
      '/api/threat-categories'
    ]
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});