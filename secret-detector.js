const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const axios = require('axios');

const debugMode = process.env.DEBUG_MODE === 'true';

function log(...args) {
  if (debugMode) console.log(...args);
}
function warn(...args) {
  if (debugMode) console.warn(...args);
}
function error(...args) {
  console.error(...args);
}

// Function to create temporary rule file for Gitleaks
function createTempRulesFile() {
  const customRules = `[[rules]]
id = "strict-secret-detection"
description = "Detect likely passwords or secrets with high entropy"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_$%!]{10,})["']'''
tags = ["key", "secret", "generic", "password"]`;

  const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
  fs.writeFileSync(rulesPath, customRules);
  return rulesPath;
}

// Function to run Gitleaks with specific directories/files skipped
function runGitleaks(scanDir, reportPath, rulesPath) {
  return new Promise((resolve, reject) => {
    // Check if the directory is 'neotrak-jenkins' and skip it
    if (scanDir.includes('neotrak-jenkins')) {
      console.log("❌ Skipping 'neotrak-jenkins' directory...");
      resolve();  // Skip the scan for this directory
      return;
    }

    const command = `gitleaks detect --source=${scanDir} --report-path=${reportPath} --config=${rulesPath} --no-banner`;
    log(`🔍 Running Gitleaks:\n${command}`);

    exec(command, { shell: '/bin/bash' }, (error, stdout, stderr) => {
      log('📤 Gitleaks STDOUT:\n', stdout);
      if (stderr && stderr.trim()) {
        warn('⚠️ Gitleaks STDERR:\n', stderr);
      }

      resolve();
    });
  });
}

// Function to check the generated report for secrets
function checkReport(reportPath) {
  return new Promise((resolve, reject) => {
    fs.readFile(reportPath, 'utf8', (err, data) => {
      if (err) return reject(err);

      try {
        const report = JSON.parse(data);
        resolve(report.length ? report : "No secrets detected.");
      } catch (e) {
        reject(new Error("Invalid JSON in gitleaks report."));
      }
    });
  });
}

// Function to send secrets to external API
async function sendSecretsToApi(projectId, secretItems) {
  const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-secrets/${projectId}`;
  const secretsData = secretItems.map(mapToSBOMSecret);

  const headers = {
    'Content-Type': 'application/json',
  };

  const apiKey = process.env.X_API_KEY;
  const secretKey = process.env.X_SECRET_KEY;
  const tenantKey = process.env.X_TENANT_KEY;

  if (apiKey) headers['x-api-key'] = apiKey;
  if (secretKey) headers['x-secret-key'] = secretKey;
  if (tenantKey) headers['x-tenant-key'] = tenantKey;

  try {
    log('Sending secrets:', JSON.stringify(secretsData, null, 2));

    const response = await axios.post(apiUrl, secretsData, {
      headers,
      timeout: 60000,
    });

    if (response.status >= 200 && response.status < 300) {
      log('✅ Secrets updated successfully in SBOM API.');
    } else {
      error(`❌ Failed to update secrets. Status: ${response.status}`);
      error('Response body:', response.data);
    }
  } catch (err) {
    error('❌ Error sending secrets to SBOM API:', err.message || err);
  }
}

// Main function to initiate the scan
async function main() {
  try {
    const scanDir = process.env.SCAN_DIR || process.cwd();; 
    const repoName = (process.env.JOB_NAME || process.env.BUILD_TAG || 'repo/unknown').split('/')[1];
    const reportPath = path.join(scanDir, `${repoName}_${Date.now()}_report.json`);
    const rulesPath = createTempRulesFile();

    console.log(`📂 Scanning directory: ${scanDir}`);
    log(`📝 Using custom inline rules from: ${rulesPath}`);

    // Set Git safe directory for Docker/Jenkins context
    try {
      execSync(`git config --global --add safe.directory "${scanDir}"`);
    } catch (e) {
      warn("⚠️ Could not configure Git safe directory (not a git repo?)");
    }

    // Run the scan, skipping 'neotrak-jenkins' directory
    await runGitleaks(scanDir, reportPath, rulesPath);
    const result = await checkReport(reportPath);

    // Filter out files from the report (e.g., node_modules, files you want to ignore)
    const filtered = Array.isArray(result)
      ? result.filter(item =>
        !skipFiles.includes(path.basename(item.File)) &&
        !item.File.includes('node_modules') &&
        !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
      )
      : result;

    if (filtered === "No secrets detected." || (Array.isArray(filtered) && filtered.length === 0)) {
      console.log("✅ No secrets detected.");
    } else {
      console.log("🔐 Detected secrets:");
      console.dir(filtered, { depth: null, colors: true });

      const projectId = process.env.PROJECT_ID;
      if (!projectId) {
        console.error("❌ PROJECT_ID environment variable not set.");
        process.exit(1);
      }

      await sendSecretsToApi(projectId, filtered);
      process.exitCode = 1; // Fail the Jenkins build
    }

    fs.unlinkSync(rulesPath);
  } catch (err) {
    console.error("❌ Error during secret scan:", err.message || err);
    process.exit(1);
  }
}

main();
