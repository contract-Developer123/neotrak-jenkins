const { exec, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axios = require('axios');

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

const skipFiles = [
  'package.json',
  'package-lock.json',
  'pom.xml',
  'build.gradle',
  'requirements.txt',
  'README.md',
  '.gitignore',
  'Jenkinsfile' // Added to skip secrets in Jenkinsfile (remove if not desired)
];

const customRules = `
[[rules]]
id = "password"
description = "Detect likely passwords"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9!@#$%^&*()_+=]{8,})["']'''
tags = ["password", "key", "secret", "token"]

[[rules]]
id = "api-and-general-secrets"
description = "Detect likely API keys and general secrets"
regex = '''(?i)(X_API_KEY|X_SECRET_KEY|PROJECT_ID|WORKSPACE_ID|X_TENANT_KEY|access_token|secret_key|api_key|client_secret|aws_secret_access_key|GITHUB_TOKEN|JWT|Bearer)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_+/=]{20,})["']'''
tags = ["api_key", "secret", "env_var", "token", "jwt"]

[[rules]]
id = "jwt-token"
description = "Detect JWT and OAuth tokens in the code"
regex = '''(?i)(Bearer|JWT|access_token|id_token|oauth_token|oauth_access_token)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_\\.]{64,})["']'''
tags = ["jwt", "token", "bearer", "oauth"]

[[rules]]
id = "private-key"
description = "Detect private keys (RSA, DSA, etc.) in the code"
regex = '''(?i)(private_key|api_private_key|client_private_key|rsa_private_key)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9+/=]{500,})["']'''
tags = ["private_key", "secret"]

[[rules]]
id = "client-secret"
description = "Detect client secrets in the code"
regex = '''(?i)(client_secret|consumer_secret)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_+/=]{32,})["']'''
tags = ["client_secret", "secret"]

[[rules]]
id = "access-token"
description = "Detect access tokens in the code"
regex = '''(?i)(access_token|auth_token)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_+/=]{32,})["']'''
tags = ["access_token", "token", "secret"]

[[rules]]
id = "jwt"
description = "JSON Web Token"
regex = '''eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+'''
tags = ["token", "jwt"]
`;

function checkGitleaksInstalled() {
  return new Promise((resolve, reject) => {
    const system32Path = 'C:\\Windows\\System32\\gitleaks.exe';
    if (fs.existsSync(system32Path)) {
      try {
        fs.unlinkSync(system32Path);
        console.log(`🗑️ Removed stale gitleaks.exe from ${system32Path}`);
      } catch (err) {
        console.log(`⚠️ Could not remove ${system32Path}: ${err.message}`);
      }
    }

    const command = 'where gitleaks';
    exec(command, { shell: true }, (error, stdout, stderr) => {
      if (!error && stdout) {
        const gitleaksPath = stdout.trim().split('\n')[0];
        if (gitleaksPath.toLowerCase().includes('system32')) {
          reject(new Error(`❌ Found incompatible gitleaks.exe in ${gitleaksPath}. Please remove it.`));
          return;
        }
        try {
          const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
          console.log(`✅ Gitleaks found in PATH: ${gitleaksPath}. Version: ${version}`);
          resolve(gitleaksPath);
        } catch (err) {
          reject(new Error(`❌ Gitleaks found in PATH but not executable: ${err.message}`));
        }
      } else {
        const gitleaksPath = path.join(os.homedir(), 'gitleaks', 'gitleaks.exe');
        if (fs.existsSync(gitleaksPath)) {
          try {
            const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
            console.log(`✅ Gitleaks found at ${gitleaksPath}. Version: ${version}`);
            resolve(gitleaksPath);
          } catch (err) {
            reject(new Error(`❌ Gitleaks found at ${gitleaksPath} but not executable: ${err.message}`));
          }
        } else {
          reject(new Error('❌ Gitleaks is not installed or not found in PATH.'));
        }
      }
    });
  });
}

function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
  return new Promise((resolve, reject) => {
    const command = `"${gitleaksPath}" detect --source="${scanDir}" --report-path="${reportPath}" --config="${rulesPath}" --no-banner --verbose --report-format=json`;
    console.log(`🔍 Running Gitleaks:\n${command}`);

    exec(command, { shell: true }, (error, stdout, stderr) => {
      console.log('📤 Gitleaks STDOUT:\n', stdout);

      if (stdout) {
        const fileScanningRegex = /Scanning file: (.+)/g;
        let match;
        const scannedFiles = [];

        while ((match = fileScanningRegex.exec(stdout)) !== null) {
          scannedFiles.push(match[1]);
        }

        if (scannedFiles.length > 0) {
          console.log("🔍 Files being scanned for secrets:");
          scannedFiles.forEach(file => {
            console.log(`- ${file}`);
          });
        }
      }

      if (stderr && stderr.trim()) {
        console.warn('⚠️ Gitleaks STDERR:\n', stderr);
      }

      // Handle Gitleaks exit codes (0: no leaks, 1: leaks found, others: errors)
      if (error && error.code !== 1) {
        reject(`❌ Error executing Gitleaks: ${stderr || error.message}`);
        return;
      }

      resolve();
    });
  });
}

function checkReport(reportPath) {
  return new Promise((resolve, reject) => {
    fs.readFile(reportPath, 'utf8', (err, data) => {
      if (err) return reject(err);

      try {
        const report = JSON.parse(data);
        resolve(report.length ? report : "No credentials detected.");
      } catch (e) {
        reject(new Error("Invalid JSON in Gitleaks report."));
      }
    });
  });
}

function fixFilePath(filePath) {
  return path.normalize(filePath);
}

function mapToSecretFormat(item) {
  const fixedFile = fixFilePath(item.File);
  return {
    RuleID: item.RuleID,
    Description: item.Description,
    File: fixedFile,
    Match: item.Match,
    Secret: item.Secret,
    StartLine: String(item.StartLine ?? ''),
    EndLine: String(item.EndLine ?? ''),
    StartColumn: String(item.StartColumn ?? ''),
    EndColumn: String(item.EndColumn ?? ''),
  };
}

async function sendSecretsToApi(secretItems) {
  const projectId = process.env.PROJECT_ID;
  if (!projectId) {
    console.error("❌ PROJECT_ID is not set in the environment variables.");
    return;
  }
  const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-secrets/${projectId}`;
  const secretsData = secretItems.map(mapToSecretFormat);

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
    console.log('Sending secrets:', JSON.stringify(secretsData, null, 2));

    const response = await axios.post(apiUrl, secretsData, {
      headers,
      timeout: 60000,
    });

    if (response.status >= 200 && response.status < 300) {
      console.log('✅ Secrets updated successfully in API.');
    } else {
      console.error(`❌ Failed to update secrets. Status: ${response.status}`);
      console.error('Response body:', response.data);
    }
  } catch (err) {
    console.error('❌ Error sending secrets to API:', err.message || err);
  }
}

async function main() {
  console.log('🧾 Detecting credentials in folder...');
  try {
    const scanDir = path.join(process.env.SCAN_DIR || process.cwd());
    const reportPath = path.join(scanDir, `credentials_report_${Date.now()}.json`);
    const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');

    fs.writeFileSync(rulesPath, customRules);

    console.log(`📂 Scanning directory: ${scanDir}`);
    console.log(`📝 Using custom rules from: ${rulesPath}`);

    const gitleaksPath = await checkGitleaksInstalled();
    await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);

    const result = await checkReport(reportPath);

    if (result === "No credentials detected.") {
      console.log("✅ No credentials detected.");
      return;
    }

    const secretsDetected = Array.isArray(result) ? result.length : 0;
    console.log(`🔐 Total secrets detected: ${secretsDetected}`);

    if (secretsDetected > 0) {
      console.log("🔐 Detected secrets details:");
      result.forEach(item => {
        const formattedSecret = mapToSecretFormat(item);
        console.log(formattedSecret);
      });
    }

    const filteredSecrets = Array.isArray(result)
      ? result.filter(item =>
          !skipFiles.includes(path.basename(item.File)) &&
          !item.File.includes('node_modules') &&
          !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
        )
      : [];

    if (filteredSecrets.length > 0) {
      console.log("🔐 Filtered credentials detected:");
      filteredSecrets.forEach(item => {
        const formattedFilteredSecret = mapToSecretFormat(item);
        console.log(formattedFilteredSecret);
      });

      await sendSecretsToApi(filteredSecrets);
    } else {
      console.log("✅ No credentials after filtering.");
    }

  } catch (err) {
    console.error("❌ Error during credential scan:", err.message || err);
    process.exit(1);
  }
}

main();