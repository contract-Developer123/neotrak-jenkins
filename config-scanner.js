// trivyScan.js

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const apiKey = process.env.X_API_KEY;
const secretKey = process.env.X_SECRET_KEY;
const tenantKey = process.env.X_TENANT_KEY;
const projectId = process.env.PROJECT_ID;
const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-configs/${projectId}`;

const scanDir = process.env.SCAN_DIR || process.cwd();  // Can be set in Jenkins
const reportPath = path.join(scanDir, `trivy_report_${Date.now()}.json`);

// Run the Trivy scan
function runTrivyScan() {
  return new Promise((resolve, reject) => {
    const command = `trivy config --format json --output ${reportPath} ${scanDir}`;
    console.log(`🔍 Running Trivy scan on directory: ${scanDir}`);

    exec(command, { shell: '/bin/bash', maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
      if (stderr && stderr.trim()) console.warn('⚠️ STDERR:', stderr);
      if (error) {
        return reject(new Error(`❌ Trivy scan failed: ${error.message}`));
      }
      resolve();
    });
  });
}

// Parse the Trivy JSON report
function parseReport(reportPath) {
  return new Promise((resolve, reject) => {
    fs.readFile(reportPath, 'utf8', (err, data) => {
      if (err) return reject(err);

      try {
        const report = JSON.parse(data);
        const results = Array.isArray(report.Results) ? report.Results : [];

        const structuredReport = {
          ArtifactName: report.ArtifactName || 'unknown-artifact',
          ArtifactType: report.ArtifactType || 'config',
          Results: results.map(result => ({
            Target: result.Target,
            Class: result.Class,
            Type: result.Type,
            Misconfigurations: (result.Misconfigurations || []).map(m => ({
              ID: m.ID,
              Title: m.Title,
              Description: m.Description,
              Severity: m.Severity,
              PrimaryURL: m.PrimaryURL,
              Query: m.Query
            }))
          }))
        };

        resolve(structuredReport);
      } catch (e) {
        reject(new Error(`❌ Failed to parse Trivy report JSON: ${e.message}`));
      }
    });
  });
}

// Send the parsed report to the API
async function sendToAPI(payload) {
  if (!apiKey || !secretKey || !tenantKey || !projectId) {
    console.error("❌ Missing API credentials or project ID.");
    return;
  }

  const headers = {
    'Content-Type': 'application/json',
    'X-API-KEY': apiKey,
    'X-SECRET-KEY': secretKey,
    'X-TENANT-KEY': tenantKey,
  };

  try {
    const response = await axios.post(apiUrl, payload, { headers });
    console.log(`✅ Config report successfully sent. Status: ${response.status}`);
  } catch (error) {
    if (error.response) {
      console.error('❌ API responded with an error:', error.response.status, error.response.statusText);
      console.error('Response data:', error.response.data);
    } else if (error.request) {
      console.error('❌ No response received from API. Request details:', error.request);
    } else {
      console.error('❌ Error setting up API request:', error.message);
    }
    process.exit(1);
  }
}

// Run Trivy scan, process the report, and send it to the API
async function run() {
  try {
    // Step 1: Run the Trivy scan
    await runTrivyScan();
    console.log(`✅ Trivy scan completed. Report saved to: ${reportPath}`);

    // Step 2: Parse the Trivy JSON report
    const report = await parseReport(reportPath);
    console.log("📦 Trivy Scan Result:");
    console.log(JSON.stringify(report, null, 2));

    // Step 3: Send the parsed report to the API
    await sendToAPI(report);

    // Step 4: Check if any critical issues were found
    const flatIssues = report.Results.flatMap(r => r.Misconfigurations || []);
    if (flatIssues.some(i => i.Severity === 'CRITICAL')) {
      console.error("❌ Critical misconfigurations found.");
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(`❌ Error during scan process: ${error.message}`);
    process.exit(1);
  }
}

// Execute the function
run();
