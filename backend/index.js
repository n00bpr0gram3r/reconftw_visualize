const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const xml2js = require('xml2js'); // Import xml2js

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json());

// Serve static files from the Recon directory
app.use('/recon_data', express.static(path.join(__dirname, '../../Recon')));

// Basic route
app.get('/', (req, res) => {
  res.send('Hello from the ReconFTW Visualizer backend!');
});

// Route to get scan directories
app.get('/api/scans', (req, res) => {
  const reconDir = path.join(__dirname, '../../Recon');
  fs.readdir(reconDir, { withFileTypes: true }, (err, files) => {
    if (err) {
      console.error('Error reading Recon directory:', err);
      if (err.code === 'ENOENT') {
        return res.status(404).json({ error: 'Recon directory not found' });
      }
      return res.status(500).json({ error: 'Failed to read scan directory' });
    }

    const scans = files
      .filter(dirent => dirent.isDirectory())
      .map(dirent => dirent.name);

    res.json(scans);
  });
});

// Route to get subdomains for a specific scan
app.get('/api/scans/:scanName/subdomains', (req, res) => {
  const { scanName } = req.params;
  const subdomainsFilePath = path.join(__dirname, '../../Recon', scanName, 'subdomains', 'subdomains.txt');

  fs.readFile(subdomainsFilePath, 'utf8', (err, data) => {
    if (err) {
      console.error(`Could not read subdomains for ${scanName}, returning empty array. Error: ${err.code}`);
      return res.json([]);
    }
    const subdomains = data.split('\n').filter(line => line.trim() !== '');
    res.json(subdomains);
  });
});

// Helper function to sanitize URL for screenshot filename
const sanitizeUrlForFilename = (url) => {
  return url.replace(/https?:\/\//, '').replace(/[:/.]/g, '_') + '.png';
};

// Route to get hosts (web_full_info) for a specific scan, including screenshots
app.get('/api/scans/:scanName/hosts', (req, res) => {
  const { scanName } = req.params;
  const hostsFilePath = path.join(__dirname, '../../Recon', scanName, 'webs', 'web_full_info.txt');
  const screenshotsDir = path.join(__dirname, '../../Recon', scanName, 'screenshots');

  fs.readFile(hostsFilePath, 'utf8', (err, data) => {
    if (err) {
      console.error(`Could not read hosts for ${scanName}, returning empty array. Error: ${err.code}`);
      return res.json([]);
    }

    try {
      // Handle the JSON stream format (multiple JSON objects not in an array)
      const jsonString = `[${data.trim().replace(/}\s*{/g, '},{')}]`;
      const hostsData = JSON.parse(jsonString);

      const hostsWithScreenshots = hostsData.map(host => {
        if (!host.url) return host; // Skip if no URL

        // Construct potential screenshot filename
        const screenshotFilename = sanitizeUrlForFilename(host.url);
        const screenshotPath = path.join(screenshotsDir, screenshotFilename);

        // Check if screenshot exists and add its path
        if (fs.existsSync(screenshotPath)) {
          host.screenshot = `/recon_data/${scanName}/screenshots/${screenshotFilename}`;
        } else {
          // Try alternative filename format (e.g., for https without port)
          const altScreenshotFilename = host.url.replace(/https?:\/\//, 'https:__').replace(/\//g, '_') + '.png';
          const altScreenshotPath = path.join(screenshotsDir, altScreenshotFilename);
          if (fs.existsSync(altScreenshotPath)) {
            host.screenshot = `/recon_data/${scanName}/screenshots/${altScreenshotFilename}`;
          }
        }
        return host;
      });

      res.json(hostsWithScreenshots);
    } catch (parseError) {
      console.error('Error parsing the entire hosts file JSON:', parseError);
      // If parsing fails, return an empty array to prevent frontend crash
      return res.json([]);
    }
  });
});

// Route to get vulnerabilities for a specific scan
app.get('/api/scans/:scanName/vulnerabilities', (req, res) => {
  const { scanName } = req.params;
  const vulnsFilePath = path.join(__dirname, '../../Recon', scanName, 'nuclei_output', 'info_json.txt');

  fs.readFile(vulnsFilePath, 'utf8', (err, data) => {
    if (err) {
      // If the file doesn't exist or there's any other error, log it and return an empty array.
      console.error(`Could not read vulnerabilities for ${scanName}, returning empty array. Error: ${err.code}`);
      return res.json([]);
    }

    const vulnerabilities = data.split('\n').filter(line => line.trim() !== '').map(line => {
      try {
        return JSON.parse(line);
      } catch (parseError) {
        console.error('Error parsing vulnerability JSON line:', line, parseError);
        return null;
      }
    }).filter(Boolean); // Filter out any nulls from parsing errors

    res.json(vulnerabilities);
  });
});

// Route to get OSINT data for a specific scan
app.get('/api/scans/:scanName/osint', (req, res) => {
  const { scanName } = req.params;
  const osintDir = path.join(__dirname, '../../Recon', scanName, 'osint');
  
  const osintData = {
    emails: [],
    dorks: [],
  };

  const emailsFilePath = path.join(osintDir, 'emails.txt');
  const dorksFilePath = path.join(osintDir, 'dorks.txt');

  try {
    if (fs.existsSync(emailsFilePath)) {
      osintData.emails = fs.readFileSync(emailsFilePath, 'utf8').split('\n').filter(line => line.trim() !== '');
    }
    if (fs.existsSync(dorksFilePath)) {
      osintData.dorks = fs.readFileSync(dorksFilePath, 'utf8').split('\n').filter(line => line.trim() !== '');
    }
    res.json(osintData);
  } catch (err) {
    console.error(`Error reading OSINT data for ${scanName}:`, err);
    res.status(500).json({ error: 'Failed to read OSINT data.' });
  }
});

// Route to get port scan data for a specific scan
app.get('/api/scans/:scanName/ports', (req, res) => {
  const { scanName } = req.params;
  const portsFilePath = path.join(__dirname, '../../Recon', scanName, 'hosts', 'portscan_active.xml');

  fs.readFile(portsFilePath, 'utf8', (err, data) => {
    if (err) {
      console.error(`Could not read ports for ${scanName}, returning empty array. Error: ${err.code}`);
      return res.json([]);
    }

    xml2js.parseString(data, (parseErr, result) => {
      if (parseErr) {
        console.error(`Error parsing Nmap XML for ${scanName}:`, parseErr);
        return res.json([]);
      }

      const hosts = result.nmaprun.host || [];
      const parsedPorts = [];

      hosts.forEach(host => {
        const ipAddress = host.address && host.address[0].$.addr;
        const hostnames = host.hostnames && host.hostnames[0].hostname ? host.hostnames[0].hostname.map(h => h.$.name) : [];
        const ports = host.ports && host.ports[0].port ? host.ports[0].port : [];

        ports.forEach(port => {
          parsedPorts.push({
            ip: ipAddress,
            hostnames: hostnames,
            portid: port.$.portid,
            protocol: port.$.protocol,
            state: port.state && port.state[0].$.state,
            service: port.service && port.service[0].$.name,
            product: port.service && port.service[0].$.product,
            version: port.service && port.service[0].$.version,
          });
        });
      });
      res.json(parsedPorts);
    });
  });
});

app.listen(port, () => {
  console.log(`Backend server listening at http://localhost:${port}`);
});
