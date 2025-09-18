const { exec, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axios = require('axios'); // Add axios for making API calls

const skipFiles = [
  'package.json',
  'package-lock.json',
  'pom.xml',
  'build.gradle',
  'requirements.txt',
  'README.md',
  '.gitignore'
  // Do not include Jenkinsfile in this list unless explicitly needed
];

// Custom rules for password detection and other secrets
const customRules = `
[[rules]]
id = "password-detection"
description = "Detect likely passwords"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_$%!]{8,})["']'''
tags = ["password", "key", "secret", "token"]

[[rules]]
id = "api-keys-and-secrets"
description = "Detect likely API keys and secret keys in environment variables"
regex = '''(?i)(X_API_KEY|X_SECRET_KEY|PROJECT_ID|WORKSPACE_ID|X_TENANT_KEY|access_token|secret_key)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_+/=]{20,})["']'''
tags = ["api_key", "secret", "env_var", "token"]

[[rules]]
id = "general-secrets"
description = "Detect general secrets in the code"
regex = '''(?i)(api_key|secret_key|password|private_key|token|access_token|client_secret|aws_secret_access_key|GITHUB_TOKEN|JWT|Bearer)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_+/=]{20,})["']'''
tags = ["api_key", "secret", "env_var", "token", "jwt", "password"]

[[rules]]
id = "password"
description = "Detect passwords in the code"
regex = '''(?i)(password|pass|pwd|user_password|db_password|admin_password|private_password|client_password)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9!@#$%^&*()_+=]{8,})["']'''
tags = ["password", "secret"]

[[rules]]
id = "jwt-token"
description = "Detect JWT (JSON Web Tokens) in the code"
regex = '''(?i)(Bearer|JWT|access_token|id_token)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_\\.]{64,})["']'''
tags = ["jwt", "token", "bearer"]

[[rules]]
id = "oauth-token"
description = "Detect OAuth tokens in the code"
regex = '''(?i)(oauth_token|oauth_access_token|oauth)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9-_+/=]{20,})["']'''
tags = ["oauth", "token", "access_token"]

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

// Function to check if Gitleaks is installed
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

// Function to run Gitleaks to detect credentials and print the files it's scanning
function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
  return new Promise((resolve, reject) => {
    const command = `"${gitleaksPath}" detect --source="${scanDir}" --report-path="${reportPath}" --config="${rulesPath}" --no-banner --verbose --report-format=json`;
    console.log(`🔍 Running Gitleaks:\n${command}`);

    exec(command, { shell: true }, (error, stdout, stderr) => {
      console.log('📤 Gitleaks STDOUT:\n', stdout); // This will print detailed output, including which files are being scanned.
      
      // Capture file names from the output and log them
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

      if (error) {
        reject(`❌ Error executing Gitleaks: ${stderr}`);
        return;
      }

      resolve();
    });
  });
}

// Function to check the Gitleaks report for credentials
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

// Function to fix file paths (if necessary, depending on your system)
function fixFilePath(filePath) {
  return path.normalize(filePath);
}

// Function to map secret information to the desired structure
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

// API call function to send secrets to an API endpoint
async function sendSecretsToApi(secretsData) {
  const apiUrl = 'https://your-api-endpoint.com/endpoint'; // Replace with your actual API endpoint
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer your-api-token', // Optional: Add if your API requires an authorization token
  };

  try {
    const response = await axios.post(apiUrl, secretsData, { headers });
    if (response.status === 200) {
      console.log('✅ Successfully sent secrets to the API.');
    } else {
      console.error(`❌ Failed to send secrets. Status: ${response.status}`);
    }
  } catch (error) {
    console.error('❌ Error sending secrets to API:', error.message);
  }
}

async function main() {
  console.log('🧾 Detecting credentials in folder...');
  try {
    const scanDir = path.join(process.SCAN_DIR || process.cwd());
    const reportPath = path.join(scanDir, `credentials_report_${Date.now()}.json`);
    const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');

    // Save custom rules to a temporary file
    fs.writeFileSync(rulesPath, customRules);

    console.log(`📂 Scanning directory: ${scanDir}`);
    console.log(`📝 Using custom rules from: ${rulesPath}`);

    const gitleaksPath = await checkGitleaksInstalled();
    await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);

    const result = await checkReport(reportPath);

    // If no credentials were found, print a success message
    if (result === "No credentials detected.") {
      console.log("✅ No credentials detected.");
      return;
    }

    // Count the secrets found and print the number of secrets detected
    const secretsDetected = Array.isArray(result) ? result.length : 0;
    console.log(`🔐 Total secrets detected: ${secretsDetected}`);

    if (secretsDetected > 0) {
      console.log("🔐 Detected secrets details:");
      result.forEach(item => {
        const formattedSecret = mapToSecretFormat(item);
        console.log(formattedSecret);
      });
    }

    // Optionally, process the secrets to exclude certain files
    const filteredSecrets = Array.isArray(result)
      ? result.filter(item =>
          !skipFiles.includes(path.basename(item.File)) &&
          !item.File.includes('node_modules') &&
          !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
        )
      : result;

    if (filteredSecrets.length > 0) {
      console.log("🔐 Filtered credentials detected:");
      filteredSecrets.forEach(item => {
        const formattedFilteredSecret = mapToSecretFormat(item);
        console.log(formattedFilteredSecret);
      });

      // Send secrets to the API
      await sendSecretsToApi(filteredSecrets);
    } else {
      console.log("✅ No credentials after filtering.");
    }

  } catch (err) {
    console.error("❌ Error during credential scan:", err.message || err);
    process.exit(1);
  }
}

// Start the scanning process
main();





// const { exec, execSync } = require('child_process');
// const fs = require('fs');
// const os = require('os');
// const path = require('path');

// const skipFiles = [
//   'package.json',
//   'package-lock.json',
//   'pom.xml',
//   'build.gradle',
//   'requirements.txt',
//   'README.md',
//   '.gitignore'
// ];

// // Function to check if Gitleaks is installed
// function checkGitleaksInstalled() {
//   return new Promise((resolve, reject) => {
//     const system32Path = 'C:\\Windows\\System32\\gitleaks.exe';
//     if (fs.existsSync(system32Path)) {
//       try {
//         fs.unlinkSync(system32Path);
//         console.log(`🗑️ Removed stale gitleaks.exe from ${system32Path}`);
//       } catch (err) {
//         console.log(`⚠️ Could not remove ${system32Path}: ${err.message}`);
//       }
//     }

//     const command = 'where gitleaks';
//     exec(command, { shell: true }, (error, stdout, stderr) => {
//       if (!error && stdout) {
//         const gitleaksPath = stdout.trim().split('\n')[0];
//         if (gitleaksPath.toLowerCase().includes('system32')) {
//           reject(new Error(`❌ Found incompatible gitleaks.exe in ${gitleaksPath}. Please remove it.`));
//           return;
//         }
//         try {
//           const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
//           console.log(`✅ Gitleaks found in PATH: ${gitleaksPath}. Version: ${version}`);
//           resolve(gitleaksPath);
//         } catch (err) {
//           reject(new Error(`❌ Gitleaks found in PATH but not executable: ${err.message}`));
//         }
//       } else {
//         const gitleaksPath = path.join(os.homedir(), 'gitleaks', 'gitleaks.exe');
//         if (fs.existsSync(gitleaksPath)) {
//           try {
//             const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
//             console.log(`✅ Gitleaks found at ${gitleaksPath}. Version: ${version}`);
//             resolve(gitleaksPath);
//           } catch (err) {
//             reject(new Error(`❌ Gitleaks found at ${gitleaksPath} but not executable: ${err.message}`));
//           }
//         } else {
//           reject(new Error('❌ Gitleaks is not installed or not found in PATH.'));
//         }
//       }
//     });
//   });
// }

// // Function to run Gitleaks to detect credentials and print the files it's scanning
// function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
//   return new Promise((resolve, reject) => {
//     const command = `"${gitleaksPath}" detect --source="${scanDir}" --report-path="${reportPath}" --config="${rulesPath}" --no-banner --verbose --report-format=json`;
//     console.log(`🔍 Running Gitleaks:\n${command}`);

//     exec(command, { shell: true }, (error, stdout, stderr) => {
//       console.log('📤 Gitleaks STDOUT:\n', stdout); // This will print detailed output, including which files are being scanned.
      
//       // Capture file names from the output and log them
//       if (stdout) {
//         const fileScanningRegex = /Scanning file: (.+)/g;
//         let match;
//         const scannedFiles = [];
        
//         while ((match = fileScanningRegex.exec(stdout)) !== null) {
//           scannedFiles.push(match[1]);
//         }
        
//         if (scannedFiles.length > 0) {
//           console.log("🔍 Files being scanned for secrets:");
//           scannedFiles.forEach(file => {
//             console.log(`- ${file}`);
//           });
//         }
//       }

//       if (stderr && stderr.trim()) {
//         console.warn('⚠️ Gitleaks STDERR:\n', stderr);
//       }

//       if (error) {
//         reject(`❌ Error executing Gitleaks: ${stderr}`);
//         return;
//       }

//       resolve();
//     });
//   });
// }

// // Function to check the Gitleaks report for credentials
// function checkReport(reportPath) {
//   return new Promise((resolve, reject) => {
//     fs.readFile(reportPath, 'utf8', (err, data) => {
//       if (err) return reject(err);

//       try {
//         const report = JSON.parse(data);
//         resolve(report.length ? report : "No credentials detected.");
//       } catch (e) {
//         reject(new Error("Invalid JSON in Gitleaks report."));
//       }
//     });
//   });
// }

// // Function to fix file paths (if necessary, depending on your system)
// function fixFilePath(filePath) {
//   return path.normalize(filePath);
// }

// // Function to map secret information to the desired structure
// function mapToSecretFormat(item) {
//   const fixedFile = fixFilePath(item.File);
//   return {
//     RuleID: item.RuleID,
//     Description: item.Description,
//     File: fixedFile,
//     Match: item.Match,
//     Secret: item.Secret,
//     StartLine: String(item.StartLine ?? ''),
//     EndLine: String(item.EndLine ?? ''),
//     StartColumn: String(item.StartColumn ?? ''),
//     EndColumn: String(item.EndColumn ?? ''),
//   };
// }

// // Main function to detect credentials
// async function main() {
//   console.log('🧾 Detecting credentials in folder...');
//   try {
//     const scanDir = path.join(process.SCAN_DIR || process.cwd());
//     const reportPath = path.join(scanDir, `credentials_report_${Date.now()}.json`);
//     const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');

//     console.log(`📂 Scanning directory: ${scanDir}`);
//     console.log(`📝 Using custom rules from: ${rulesPath}`);

//     const gitleaksPath = await checkGitleaksInstalled();
//     await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);

//     const result = await checkReport(reportPath);

//     // If no credentials were found, print a success message
//     if (result === "No credentials detected.") {
//       console.log("✅ No credentials detected.");
//       return;
//     }

//     // Count the secrets found and print the number of secrets detected
//     const secretsDetected = Array.isArray(result) ? result.length : 0;
//     console.log(`🔐 Total secrets detected: ${secretsDetected}`);

//     if (secretsDetected > 0) {
//       console.log("🔐 Detected secrets details:");
//       result.forEach(item => {
//         const formattedSecret = mapToSecretFormat(item);
//         console.log(formattedSecret);
//       });
//     }

//     // Optionally, process the secrets to exclude certain files
//     const filteredSecrets = Array.isArray(result)
//       ? result.filter(item =>
//           !skipFiles.includes(path.basename(item.File)) &&
//           !item.File.includes('node_modules') &&
//           !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
//         )
//       : result;

//     if (filteredSecrets.length > 0) {
//       console.log("🔐 Filtered credentials detected:");
//       filteredSecrets.forEach(item => {
//         const formattedFilteredSecret = mapToSecretFormat(item);
//         console.log(formattedFilteredSecret);
//       });
//     } else {
//       console.log("✅ No credentials after filtering.");
//     }

//   } catch (err) {
//     console.error("❌ Error during credential scan:", err.message || err);
//     process.exit(1);
//   }
// }

// // Start the scanning process
// main();






//////////////////////////////////////////////////////////////////////////////
     // working with Gitleaks in Jenkins on Windows

// const { exec, execSync } = require('child_process');
// const fs = require('fs');
// const os = require('os');
// const path = require('path');

// const debugMode = process.env.DEBUG_MODE === 'true';
// function log(...args) {
//   if (debugMode) console.log(...args);
// }
// function warn(...args) {
//   if (debugMode) console.warn(...args);
// }
// function error(...args) {
//   console.error(...args);
// }

// const skipFiles = [
//   'package.json',
//   'package-lock.json',
//   'pom.xml',
//   'build.gradle',
//   'requirements.txt',
//   'README.md',
//   '.gitignore'
// ];

// // Function to check if Gitleaks is installed
// function checkGitleaksInstalled() {
//   return new Promise((resolve, reject) => {
//     const system32Path = 'C:\\Windows\\System32\\gitleaks.exe';
//     if (fs.existsSync(system32Path)) {
//       try {
//         fs.unlinkSync(system32Path);
//         log(`🗑️ Removed stale gitleaks.exe from ${system32Path}`);
//       } catch (err) {
//         log(`⚠️ Could not remove ${system32Path}: ${err.message}`);
//       }
//     }

//     const command = 'where gitleaks';
//     exec(command, { shell: true }, (error, stdout, stderr) => {
//       if (!error && stdout) {
//         const gitleaksPath = stdout.trim().split('\n')[0];
//         if (gitleaksPath.toLowerCase().includes('system32')) {
//           reject(new Error(`❌ Found incompatible gitleaks.exe in ${gitleaksPath}. Please remove it.`));
//           return;
//         }
//         try {
//           const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
//           console.log(`✅ Gitleaks found in PATH: ${gitleaksPath}. Version: ${version}`);
//           resolve(gitleaksPath);
//         } catch (err) {
//           reject(new Error(`❌ Gitleaks found in PATH but not executable: ${err.message}`));
//         }
//       } else {
//         const gitleaksPath = path.join(os.homedir(), 'gitleaks', 'gitleaks.exe');
//         if (fs.existsSync(gitleaksPath)) {
//           try {
//             const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
//             console.log(`✅ Gitleaks found at ${gitleaksPath}. Version: ${version}`);
//             resolve(gitleaksPath);
//           } catch (err) {
//             reject(new Error(`❌ Gitleaks found at ${gitleaksPath} but not executable: ${err.message}`));
//           }
//         } else {
//           reject(new Error('❌ Gitleaks is not installed or not found in PATH.'));
//         }
//       }
//     });
//   });
// }

// // Function to run Gitleaks to detect credentials
// function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
//   return new Promise((resolve, reject) => {
//     const command = `"${gitleaksPath}" detect --source="${scanDir}" --report-path="${reportPath}" --config="${rulesPath}" --no-banner --verbose`;
//     log(`🔍 Running Gitleaks:\n${command}`);

//     exec(command, { shell: true }, (error, stdout, stderr) => {
//       log('📤 Gitleaks STDOUT:\n', stdout);
//       if (stderr && stderr.trim()) {
//         warn('⚠️ Gitleaks STDERR:\n', stderr);
//       }

//       if (error) {
//         reject(`❌ Error executing Gitleaks: ${stderr}`);
//         return;
//       }

//       resolve();
//     });
//   });
// }

// // Function to check the Gitleaks report for credentials
// function checkReport(reportPath) {
//   return new Promise((resolve, reject) => {
//     fs.readFile(reportPath, 'utf8', (err, data) => {
//       if (err) return reject(err);

//       try {
//         const report = JSON.parse(data);
//         resolve(report.length ? report : "No credentials detected.");
//       } catch (e) {
//         reject(new Error("Invalid JSON in Gitleaks report."));
//       }
//     });
//   });
// }

// // Main function to detect credentials
// async function main() {
//   console.log('🧾 Detecting credentials in folder...');
//   try {
//     const scanDir = path.join(process.SCAN_DIR || process.cwd());
//     const reportPath = path.join(scanDir, `credentials_report_${Date.now()}.json`);
//     const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');

//     console.log(`📂 Scanning directory: ${scanDir}`);
//     log(`📝 Using custom rules from: ${rulesPath}`);

//     const gitleaksPath = await checkGitleaksInstalled();
//     await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);

//     const result = await checkReport(reportPath);
    
//     // If no credentials were found, print a success message
//     if (result === "No credentials detected.") {
//       console.log("✅ No credentials detected.");
//       return;
//     }

//     // Count the secrets found and print the number of secrets detected
//     const secretsDetected = Array.isArray(result) ? result.length : 0;
//     console.log(`🔐 Total secrets detected: ${secretsDetected}`);
//     if (secretsDetected > 0) {
//       console.log("🔐 Detected secrets details:");
//       console.dir(result, { depth: null, colors: true });
//     }

//     // Optionally, process the secrets to exclude certain files
//     const filteredSecrets = Array.isArray(result)
//       ? result.filter(item =>
//           !skipFiles.includes(path.basename(item.File)) &&
//           !item.File.includes('node_modules') &&
//           !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
//         )
//       : result;

//     if (filteredSecrets.length > 0) {
//       console.log("🔐 Filtered credentials detected:");
//       console.dir(filteredSecrets, { depth: null, colors: true });
//     } else {
//       console.log("✅ No credentials after filtering.");
//     }

//   } catch (err) {
//     console.error("❌ Error during credential scan:", err.message || err);
//     process.exit(1);
//   }
// }

// // Start the scanning process
// main();

//////////////////////////////////////////////////////////////////////////////////////////////











// const { exec, execSync } = require('child_process');
// const fs = require('fs');
// const os = require('os');
// const path = require('path');

// const debugMode = process.env.DEBUG_MODE === 'true';
// function log(...args) {
//   if (debugMode) console.log(...args);
// }
// function error(...args) {
//   console.error(...args);
// }

// // Function to check if Gitleaks is installed and get its version
// function checkGitleaksInstalled() {
//   return new Promise((resolve, reject) => {
//     // Remove any stale gitleaks.exe from C:\Windows\System32 to avoid PATH conflicts
//     const system32Path = 'C:\\Windows\\System32\\gitleaks.exe';
//     if (fs.existsSync(system32Path)) {
//       try {
//         fs.unlinkSync(system32Path);
//         log(`🗑️ Removed stale gitleaks.exe from ${system32Path}`);
//       } catch (err) {
//         log(`⚠️ Could not remove ${system32Path}: ${err.message}`);
//       }
//     }

//     const command = 'where gitleaks';
//     exec(command, { shell: true }, (error, stdout, stderr) => {
//       if (!error && stdout) {
//         const gitleaksPath = stdout.trim().split('\n')[0];
//         // Ensure we don't pick up C:\Windows\System32\gitleaks.exe
//         if (gitleaksPath.toLowerCase().includes('system32')) {
//           reject(new Error(`❌ Found incompatible gitleaks.exe in ${gitleaksPath}. Please remove it.`));
//           return;
//         }
//         try {
//           const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
//           console.log(`✅ Gitleaks found in PATH: ${gitleaksPath}. Version: ${version}`);
//           resolve(gitleaksPath);
//         } catch (err) {
//           reject(new Error(`❌ Gitleaks found in PATH but not executable: ${err.message}`));
//         }
//       } else {
//         const gitleaksPath = path.join(os.homedir(), 'gitleaks', 'gitleaks.exe');
//         if (fs.existsSync(gitleaksPath)) {
//           try {
//             const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
//             console.log(`✅ Gitleaks found at ${gitleaksPath}. Version: ${version}`);
//             resolve(gitleaksPath);
//           } catch (err) {
//             reject(new Error(`❌ Gitleaks found at ${gitleaksPath} but not executable: ${err.message}`));
//           }
//         } else {
//           reject(new Error('❌ Gitleaks is not installed or not found in PATH.'));
//         }
//       }
//     });
//   });
// }

// // Function to install Gitleaks
// function installGitleaks() {
//   return new Promise((resolve, reject) => {
//     console.log('🔄 Installing Gitleaks for Jenkins...');
//     exec('choco --version', { shell: true }, (error, stdout, stderr) => {
//       let installCommand;
//       let expectedPath;
//       if (!error && stdout) {
//         console.log('🔄 Installing Gitleaks using Chocolatey...');
//         installCommand = 'choco install gitleaks -y --force';
//         expectedPath = 'C:\\ProgramData\\chocolatey\\bin\\gitleaks.exe';
//       } else {
//         console.log('🔄 Chocolatey not found. Installing Gitleaks manually...');
//         const installDir = path.join(os.homedir(), 'gitleaks');
//         expectedPath = path.join(installDir, 'gitleaks.exe');
//         installCommand = `mkdir "${installDir}" & curl -L -o "${expectedPath}" https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks-windows-amd64.exe`;
//       }

//       exec(installCommand, { shell: true }, (error, stdout, stderr) => {
//         if (error || stderr) {
//           reject(new Error(`❌ Failed to install Gitleaks: ${stderr || error.message}`));
//           return;
//         }
//         console.log(`✅ Gitleaks installed successfully. Output: ${stdout}`);
//         try {
//           const version = execSync(`"${expectedPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
//           console.log(`Gitleaks version: ${version}`);
//           resolve(expectedPath);
//         } catch (err) {
//           reject(new Error(`❌ Gitleaks installed but not executable: ${err.message}`));
//         }
//       });
//     });
//   });
// }

// // Main function to check or install Gitleaks
// async function main() {
//   try {
//     await checkGitleaksInstalled();
//   } catch (err) {
//     console.log('Gitleaks not found. Attempting to install...');
//     try {
//       await installGitleaks();
//     } catch (installErr) {
//       error(`❌ Failed to install Gitleaks: ${installErr.message}`);
//       process.exit(1);
//     }
//   }
// }

// // Start the process
// main();


// const { exec, execSync } = require('child_process');
// const fs = require('fs');
// const os = require('os');
// const path = require('path');
// const axios = require('axios');

// const debugMode = process.env.DEBUG_MODE === 'true';
// function log(...args) {
//   if (debugMode) console.log(...args);
// }
// function warn(...args) {
//   if (debugMode) console.warn(...args);
// }
// function error(...args) {
//   console.error(...args);
// }

// const skipFiles = [
//   'package.json',
//   'package-lock.json',
//   'pom.xml',
//   'build.gradle',
//   'requirements.txt',
//   'README.md',
//   '.gitignore'
// ];

// // Function to check if Gitleaks is installed
// function isGitleaksInstalled() {
//   try {
//     execSync('gitleaks --version', { stdio: 'ignore' });
//     return true;
//   } catch (error) {
//     return false;
//   }
// }

// // Function to install Gitleaks if not installed
// function installGitleaks() {
//   return new Promise((resolve, reject) => {
//     console.log('Gitleaks is not installed. Installing...');

//     const platform = os.platform();
//     let installCommand;

//     if (platform === 'win32') {
//       installCommand = 'curl -L -o gitleaks.exe https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks-windows-amd64.exe && move /Y gitleaks.exe C:\\Windows\\System32\\gitleaks.exe';
//     } else if (platform === 'darwin') {
//       installCommand = 'brew install gitleaks';
//     } else if (platform === 'linux') {
//       installCommand = 'curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-linux-amd64.tar.gz | tar xz -C /tmp && sudo mv /tmp/gitleaks /usr/local/bin';
//     } else {
//       return reject(new Error(`Unsupported platform: ${platform}`));
//     }

//     exec(installCommand, (error, stdout, stderr) => {
//       if (error) {
//         return reject(new Error(`❌ Error installing Gitleaks: ${stderr}`));
//       }
//       resolve(stdout || stderr);
//     });
//   });
// }

// // Function to install Gitleaks if necessary
// async function ensureGitleaksInstalled() {
//   if (!isGitleaksInstalled()) {
//     try {
//       await installGitleaks();
//       console.log('✅ Gitleaks installed successfully.');
//     } catch (err) {
//       console.error(`❌ Failed to install Gitleaks: ${err.message}`);
//       process.exit(1);
//     }
//   } else {
//     console.log('✅ Gitleaks is already installed.');
//   }
// }

// // Custom Rules for Gitleaks
// const customRules = `
// // Add your custom Gitleaks rules here
// [[rules]]
// id = "strict-secret-detection"
// description = "Detect likely passwords or secrets with high entropy"
// regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_!$%]{10,})["']'''
// tags = ["key", "secret", "generic", "password"]

// [[rules]]
// id = "aws-secret"
// description = "AWS Secret Access Key"
// regex = '''(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]'''
// tags = ["aws", "key", "secret"]

// [[rules]]
// id = "aws-key"
// description = "AWS Access Key ID"
// regex = '''AKIA[0-9A-Z]{16}'''
// tags = ["aws", "key"]

// [[rules]]
// id = "github-token"
// description = "GitHub Personal Access Token"
// regex = '''ghp_[A-Za-z0-9_]{36}'''
// tags = ["github", "token"]

// [[rules]]
// id = "jwt"
// description = "JSON Web Token"
// regex = '''eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+'''
// tags = ["token", "jwt"]

// [[rules]]
// id = "firebase-api-key"
// description = "Firebase API Key"
// regex = '''AIza[0-9A-Za-z\\-_]{35}'''
// tags = ["firebase", "apikey"]
// `;

// // Create a temporary file for the Gitleaks rules
// function createTempRulesFile() {
//   const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
//   fs.writeFileSync(rulesPath, customRules);
//   return rulesPath;
// }

// // Run the Gitleaks command for secret scanning
// function runGitleaks(scanDir, reportPath, rulesPath) {
//   return new Promise((resolve, reject) => {
//     const command = `gitleaks detect --source=${scanDir} --report-path=${reportPath} --config=${rulesPath} --no-banner --verbose`;
//     log(`🔍 Running Gitleaks:\n${command}`);

//     exec(command, { shell: true }, (error, stdout, stderr) => {
//       log('📤 Gitleaks STDOUT:\n', stdout);
//       if (stderr && stderr.trim()) {
//         warn('⚠️ Gitleaks STDERR:\n', stderr);
//       }

//       if (error) {
//         reject(`❌ Error executing Gitleaks: ${stderr}`);
//         return;
//       }

//       resolve();
//     });
//   });
// }

// // Check the report for secrets
// function checkReport(reportPath) {
//   return new Promise((resolve, reject) => {
//     fs.readFile(reportPath, 'utf8', (err, data) => {
//       if (err) return reject(err);

//       try {
//         const report = JSON.parse(data);
//         resolve(report.length ? report : "No secrets detected.");
//       } catch (e) {
//         reject(new Error("Invalid JSON in Gitleaks report."));
//       }
//     });
//   });
// }

// // List files in the directory being scanned
// function listFilesInDir(scanDir) {
//   try {
//     const files = fs.readdirSync(scanDir);
//     console.log(`📂 Files in directory "${scanDir}":`);
//     files.forEach(file => {
//       console.log(file);
//     });
//     return files;
//   } catch (err) {
//     console.error(`❌ Error reading directory "${scanDir}":`, err.message || err);
//     return [];
//   }
// }

// // Main function to initiate the scan
// async function main() {
//   try {
//     // Use Jenkins workspace as the scan directory
//     const scanDir = process.env.WORKSPACE || process.cwd();  // WORKSPACE is set in Jenkins
//     const reportPath = path.join(scanDir, `secrets_report_${Date.now()}_report.json`);
//     const rulesPath = createTempRulesFile();

//     console.log(`📂 Scanning directory: ${scanDir}`);
//     log(`📝 Using custom inline rules from: ${rulesPath}`);

//     // List files in the directory (for debugging purposes)
//     const files = listFilesInDir(scanDir);
//     log('Files to scan:', files);

//     // Set Git safe directory for Jenkins context
//     try {
//       execSync(`git config --global --add safe.directory "${scanDir}"`);
//     } catch (e) {
//       warn("⚠️ Could not configure Git safe directory (not a git repo?)");
//     }

//     // Ensure Gitleaks is installed
//     await ensureGitleaksInstalled();

//     // Run the Gitleaks scan
//     await runGitleaks(scanDir, reportPath, rulesPath);
//     const result = await checkReport(reportPath);

//     // Filter out files from the report (e.g., node_modules, files to ignore)
//     const filtered = Array.isArray(result)
//       ? result.filter(item =>
//         !skipFiles.includes(path.basename(item.File)) &&
//         !item.File.includes('node_modules') &&
//         !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
//       )
//       : result;

//     if (filtered === "No secrets detected." || (Array.isArray(filtered) && filtered.length === 0)) {
//       console.log("✅ No secrets detected.");
//     } else {
//       console.log("🔐 Detected secrets:");
//       console.dir(filtered, { depth: null, colors: true });

//       const projectId = process.env.PROJECT_ID;
//       if (!projectId) {
//         console.error("❌ PROJECT_ID environment variable not set.");
//         process.exit(1);
//       }

//       await sendSecretsToApi(projectId, filtered);
//       process.exitCode = 1; // Fail the Jenkins build
//     }

//     fs.unlinkSync(rulesPath);  // Clean up the rules file
//   } catch (err) {
//     console.error("❌ Error during secret scan:", err.message || err);
//     process.exit(1);
//   }
// }

// // Start the scanning process
// main();
