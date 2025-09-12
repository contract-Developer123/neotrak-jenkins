const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function ensureDependencyInstalled(packageName) {
  try {
    require.resolve(packageName);
  } catch (e) {
    console.warn(`📦 '${packageName}' not found. Installing...`);
    try {
      execSync(`npm install ${packageName}`, { stdio: 'inherit' });
      console.log(`✅ '${packageName}' installed successfully.`);
    } catch (installErr) {
      console.error(`❌ Failed to install '${packageName}':`, installErr);
      process.exit(1);
    }
  }
}

ensureDependencyInstalled('axios');

const axios = require('axios');

const apiKey = process.env.X_API_KEY;
const secretKey = process.env.X_SECRET_KEY;
const tenantKey = process.env.X_TENANT_KEY;
const projectId = process.env.PROJECT_ID;
const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-configs/${projectId}`;

const scanDir = process.env.SCAN_DIR || process.cwd();  // Can be set in Jenkins
const reportPath = path.join(scanDir, `trivy_report_${Date.now()}.json`);

// Function to check if Trivy is installed
function checkTrivyInstalled() {
  return new Promise((resolve, reject) => {
    const command = os.platform() === 'win32' ? 'where trivy' : 'which trivy';
    exec(command, (error, stdout, stderr) => {
      if (error || stderr) {
        reject(new Error("❌ Trivy is not installed or not found in PATH."));
      } else {
        resolve(stdout);
      }
    });
  });
}

// Function to install Trivy (based on OS)
function installTrivy() {
  return new Promise((resolve, reject) => {
    const isWindows = os.platform() === 'win32';
    let installCommand = '';

    if (isWindows) {
      // Windows installation using Chocolatey or winget
      installCommand = 'choco install trivy -y';
      console.log('🔄 Installing Trivy on Windows...');
    } else if (os.platform() === 'linux') {
      // Linux installation (Debian/Ubuntu)
      installCommand = 'sudo apt-get install -y wget && wget https://github.com/aquasecurity/trivy/releases/download/v0.34.0/trivy_0.34.0_Linux-64bit.deb && sudo dpkg -i trivy_0.34.0_Linux-64bit.deb';
      console.log('🔄 Installing Trivy on Linux...');
    } else if (os.platform() === 'darwin') {
      // macOS installation using Homebrew
      installCommand = 'brew install aquasecurity/trivy/trivy';
      console.log('🔄 Installing Trivy on macOS...');
    } else {
      reject(new Error('❌ Unsupported OS for automatic Trivy installation.'));
      return;
    }

    exec(installCommand, (error, stdout, stderr) => {
      if (error || stderr) {
        reject(new Error(`❌ Failed to install Trivy: ${stderr || error.message}`));
      } else {
        console.log(`✅ Trivy installed successfully. Output: ${stdout}`);
        resolve();
      }
    });
  });
}

async function runTrivyScan(scanDir, reportPath) {
  return new Promise((resolve, reject) => {
    const args = [
      'config',
      '--severity', 'LOW,MEDIUM,HIGH,CRITICAL',
      '--skip-dirs', 'neotrak-jenkins,node_modules,.git,build',
      '--format', 'json',
      '--output', reportPath,
      scanDir
    ];

    console.log(`🔍 Running Trivy scan on directory: ${scanDir}`);
    console.log(`Executing command: trivy ${args.join(' ')}`);

    const trivyProcess = spawn('trivy', args);

    trivyProcess.stdout.on('data', (data) => {
      process.stdout.write(`STDOUT: ${data}`);
    });

    trivyProcess.stderr.on('data', (data) => {
      process.stderr.write(`STDERR: ${data}`);
    });

    trivyProcess.on('close', (code) => {
      if (code === 0) {
        console.log('✅ Trivy scan completed successfully.');
        resolve();
      } else {
        reject(new Error(`❌ Trivy scan failed with exit code ${code}`));
      }
    });

    trivyProcess.on('error', (err) => {
      reject(err);
    });
  });
}

runTrivyScan(scanDir, reportPath)
  .then(() => {
    console.log('Scan finished!');
    // Continue with your report processing here...
  })
  .catch(err => {
    console.error('Error during Trivy scan:', err);
  });

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
    // Step 1: Check if Trivy is installed
    try {
      await checkTrivyInstalled();
      console.log('✅ Trivy is already installed.');
    } catch (e) {
      console.log('❌ Trivy not found.');
      await installTrivy();  // Install Trivy if not found
    }

    // Step 2: Run the Trivy scan
    await runTrivyScan();
    console.log(`✅ Trivy scan completed. Report saved to: ${reportPath}`);

    // Step 3: Parse the Trivy JSON report
    const report = await parseReport(reportPath);
    console.log("📦 Trivy Scan Result:");
    console.log(JSON.stringify(report, null, 2));

    // Step 4: Send the parsed report to the API
    await sendToAPI(report);

    // Step 5: Check if any critical issues were found
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
