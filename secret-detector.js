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
  /^credentials_report_.*\.json$/i,
  /^trivy_report_.*\.json$/i,
];

// const customRules = `
// [[rules]]
// id = "password"
// description = "Detect likely passwords"
// regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[ \t]*[=:][ \t]*([A-Za-z0-9!@#$%^&*()_+=]+)'''
// tags = ["password", "key", "secret", "token"]

// [[rules]]
// id = "api-and-general-secrets"
// description = "Detect likely API keys and general secrets"
// regex = '''(?i)(X_API_KEY|X_SECRET_KEY|PROJECT_ID|WORKSPACE_ID|X_TENANT_KEY|access_token|secret_key|api_key|client_secret|aws_secret_access_key|GITHUB_TOKEN|JWT|Bearer)[ \t]*[=:][ \t]*([A-Za-z0-9-_+/=]+)'''
// tags = ["api_key", "secret", "env_var", "token", "jwt"]

// [[rules]]
// id = "jwt-token"
// description = "Detect JWT and OAuth tokens in the code"
// regex = '''(?i)(Bearer|JWT|access_token|id_token|oauth_token|oauth_access_token)[ \t]*[=:][ \t]*([A-Za-z0-9-_\\.]+)'''
// tags = ["jwt", "token", "bearer", "oauth"]

// [[rules]]
// id = "private-key"
// description = "Detect private keys (RSA, DSA, etc.) in the code"
// regex = '''(?i)(private_key|api_private_key|client_private_key|rsa_private_key)[ \t]*[=:][ \t]*([A-Za-z0-9+/=]+)'''
// tags = ["private_key", "secret"]

// [[rules]]
// id = "client-secret"
// description = "Detect client secrets in the code"
// regex = '''(?i)(client_secret|consumer_secret)[ \t]*[=:][ \t]*([A-Za-z0-9-_+/=]+)'''
// tags = ["client_secret", "secret"]

// [[rules]]
// id = "access-token"
// description = "Detect access tokens in the code"
// regex = '''(?i)(access_token|auth_token)[ \t]*[=:][ \t]*([A-Za-z0-9-_+/=]+)'''
// tags = ["access_token", "token", "secret"]

// [[rules]]
// id = "jwt"
// description = "JSON Web Token"
// regex = '''eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+'''
// tags = ["token", "jwt"]
// `;

// ✅ Stronger regex: avoids matching dummy values like "hello", "test123"
const customRules = `
[[rules]]
id = "strict-secret-detection"
description = "Detect likely passwords or secrets with high entropy"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_$%!]{10,})["']'''
tags = ["key", "secret", "generic", "password"]

[[rules]]
id = "aws-secret"
description = "AWS Secret Access Key"
regex = '''(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]'''
tags = ["aws", "key", "secret"]

[[rules]]
id = "aws-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "key"]

[[rules]]
id = "github-token"
description = "GitHub Personal Access Token"
regex = '''ghp_[A-Za-z0-9_]{36}'''
tags = ["github", "token"]

[[rules]]
id = "jwt"
description = "JSON Web Token"
regex = '''eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+'''
tags = ["token", "jwt"]

[[rules]]
id = "firebase-api-key"
description = "Firebase API Key"
regex = '''AIza[0-9A-Za-z\\-_]{35}'''
tags = ["firebase", "apikey"]
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

function getReportPathFor(filePath) {
  const fileName = path.basename(filePath, path.extname(filePath));
  const timestamp = Date.now();
  const safeName = fileName.replace(/[^a-zA-Z0-9-_]/g, '_');
  return path.join(os.tmpdir(), `gitleaks_report_${safeName}_${timestamp}.json`);
}

function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
  return new Promise((resolve, reject) => {
    const files = getAllFiles(scanDir);

    if (files.length === 0) {
      console.log("⚠️ No files found to scan in the current directory.");
      resolve();
      return;
    }

    console.log("🔍 Scanning the following files:");
    files.forEach(file => {
      console.log(`- ${file}`);
      // Log file content for debugging
      try {
        const content = fs.readFileSync(file, 'utf8');
        console.log(`📄 Content of ${file}:\n${content}\n`);
      } catch (err) {
        console.error(`❌ Failed to read ${file}: ${err.message}`);
      }
    });

    console.log(`📂 Total files to scan: ${scanDir}`);
    // const filesToScan = files.map(file => `"${file}"`).join(' ');
    // console.log(`📂   : ${filesToScan}`);
    // const command = `"${gitleaksPath}" protect --report-path="${reportPath}" --config="${rulesPath}" --no-banner --verbose --report-format=json ${filesToScan}`;

    const command = `"${gitleaksPath}" detect --no-git --source="${scanDir}" --report-path="${reportPath}" --config="${rulesPath}" --report-format=json --verbose`;

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

      if (error && error.code !== 1) {
        reject(new Error(`❌ Error executing Gitleaks: ${stderr || error.message}\nStack: ${error.stack}`));
        return;
      }

      resolve();
    });
  });
}

function getAllFiles(dirPath, arrayOfFiles = []) {
  console.log(`🔍 Checking directory: ${dirPath}`);
  const files = fs.readdirSync(dirPath);

  files.forEach(function (file) {
    const filePath = path.join(dirPath, file);
    const fileName = path.basename(filePath);

    console.log(`🔍 Evaluating file or directory: ${filePath}`);
    if (
      skipFiles.some(skip => {
        const isSkipped = typeof skip === 'string' ? skip === fileName : skip.test(fileName);
        if (isSkipped) console.log(`⏭️ Skipping file: ${filePath}`);
        return isSkipped;
      }) ||
      (fs.statSync(filePath).isDirectory() && (
        file === 'node_modules' ||
        file === '.git' ||
        file === 'neotrak-jenkins' ||
        file.startsWith('credentials_report') ||
        file.startsWith('trivy_report')
      ))
    ) {
      console.log(`⏭️ Skipping directory: ${filePath}`);
      return;
    }

    if (fs.statSync(filePath).isDirectory()) {
      arrayOfFiles = getAllFiles(filePath, arrayOfFiles);
    } else {
      console.log(`✅ Adding to scan: ${filePath}`);
      arrayOfFiles.push(filePath);
    }
  });

  return arrayOfFiles;
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

// function fixFilePath(filePath) {
//   return path.normalize(filePath);
// }

function fixFilePath(filePath) {
    if (!filePath) return '///////'; // 7 slashes = 8 empty segments

    let segments = filePath.split('/');
    const requiredSegments = 8;

    // Count only actual segments; empty strings from leading/trailing slashes are valid
    const nonEmptyCount = segments.filter(Boolean).length;

    while (nonEmptyCount + segments.length - nonEmptyCount < requiredSegments) {
        segments.unshift('');
    }

    return segments.join('/');
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
      console.log('Response body:', response.status);
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
    const reportPath = path.join(os.tmpdir(), `credentials_report_${Date.now()}.json`);
    const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');

    fs.writeFileSync(rulesPath, customRules);

    console.log(`📂 Scanning directory: ${scanDir}`);
    console.log(`📝 Using custom rules from: ${rulesPath}`);
    console.log(`📄 Report will be saved to: ${reportPath}`);

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
        !skipFiles.some(skip => typeof skip === 'string' ? skip === path.basename(item.File) : skip.test(path.basename(item.File))) &&
        !item.File.includes('node_modules') &&
        !item.File.includes('neotrak-jenkins') &&
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
    console.error("❌ Error during credential scan:", err.message || err, `\nStack: ${err.stack}`);
    process.exit(1);
  }
}

main();