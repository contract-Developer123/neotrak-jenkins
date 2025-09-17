const { exec, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

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

const skipFiles = [
  'package.json',
  'package-lock.json',
  'pom.xml',
  'build.gradle',
  'requirements.txt',
  'README.md',
  '.gitignore'
];

// Function to check if Gitleaks is installed
function checkGitleaksInstalled() {
  return new Promise((resolve, reject) => {
    const system32Path = 'C:\\Windows\\System32\\gitleaks.exe';
    if (fs.existsSync(system32Path)) {
      try {
        fs.unlinkSync(system32Path);
        log(`🗑️ Removed stale gitleaks.exe from ${system32Path}`);
      } catch (err) {
        log(`⚠️ Could not remove ${system32Path}: ${err.message}`);
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

// Function to install Gitleaks
function installGitleaks() {
  return new Promise((resolve, reject) => {
    console.log('🔄 Installing Gitleaks for Jenkins...');
    exec('choco --version', { shell: true }, (error, stdout, stderr) => {
      let installCommand;
      let expectedPath;
      if (!error && stdout) {
        console.log('🔄 Installing Gitleaks using Chocolatey...');
        installCommand = 'choco install gitleaks -y --force';
        expectedPath = 'C:\\ProgramData\\chocolatey\\bin\\gitleaks.exe';
      } else {
        console.log('🔄 Chocolatey not found. Installing Gitleaks manually...');
        const installDir = path.join(os.homedir(), 'gitleaks');
        expectedPath = path.join(installDir, 'gitleaks.exe');
        installCommand = `mkdir "${installDir}" & curl -L -o "${expectedPath}" https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks-windows-amd64.exe`;
      }

      exec(installCommand, { shell: true }, (error, stdout, stderr) => {
        if (error || stderr) {
          reject(new Error(`❌ Failed to install Gitleaks: ${stderr || error.message}`));
          return;
        }
        console.log(`✅ Gitleaks installed successfully. Output: ${stdout}`);
        try {
          const version = execSync(`"${expectedPath}" --version`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
          console.log(`Gitleaks version: ${version}`);
          resolve(expectedPath);
        } catch (err) {
          reject(new Error(`❌ Gitleaks installed but not executable: ${err.message}`));
        }
      });
    });
  });
}

// Function to ensure Gitleaks is installed
async function ensureGitleaksInstalled() {
  try {
    const gitleaksPath = await checkGitleaksInstalled();
    return gitleaksPath;
  } catch (err) {
    console.log('Gitleaks not found. Attempting to install...');
    try {
      const gitleaksPath = await installGitleaks();
      return gitleaksPath;
    } catch (installErr) {
      error(`❌ Failed to install Gitleaks: ${installErr.message}`);
      process.exit(1);
    }
  }
}

// Custom Gitleaks rules for credential detection
const customRules = `
[[rules]]
id = "strict-secret-detection"
description = "Detect likely passwords or secrets with high entropy"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_!$%]{10,})["']'''
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

// Create a temporary file for Gitleaks rules
function createTempRulesFile() {
  const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
  fs.writeFileSync(rulesPath, customRules);
  return rulesPath;
}

// Run Gitleaks to detect credentials
function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
  return new Promise((resolve, reject) => {
    const command = `"${gitleaksPath}" detect --source="${scanDir}" --report-path="${reportPath}" --config="${rulesPath}" --no-banner --verbose`;
    log(`🔍 Running Gitleaks:\n${command}`);

    exec(command, { shell: true }, (error, stdout, stderr) => {
      log('📤 Gitleaks STDOUT:\n', stdout);
      if (stderr && stderr.trim()) {
        warn('⚠️ Gitleaks STDERR:\n', stderr);
      }

      if (error) {
        reject(`❌ Error executing Gitleaks: ${stderr}`);
        return;
      }

      resolve();
    });
  });
}

// Check the Gitleaks report for credentials
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

// List files in the directory being scanned
function listFilesInDir(scanDir) {
  try {
    const files = fs.readdirSync(scanDir);
    console.log(`📂 Files in directory "${scanDir}":`);
    files.forEach(file => {
      console.log(file);
    });
    return files;
  } catch (err) {
    console.error(`❌ Error reading directory "${scanDir}":`, err.message || err);
    return [];
  }
}

// Main function to detect credentials
async function main() {
  console.log('🧾 Detecting credentials in folder...');
  try {
    const scanDir = path.join(process.env.WORKSPACE || process.cwd(), 'neotrak-jenkins');
    const reportPath = path.join(scanDir, `credentials_report_${Date.now()}.json`);
    const rulesPath = createTempRulesFile();

    console.log(`📂 Scanning directory: ${scanDir}`);
    log(`📝 Using custom rules from: ${rulesPath}`);

    const files = listFilesInDir(scanDir);
    log('Files to scan:', files);

    try {
      execSync(`git config --global --add safe.directory "${scanDir}"`, { shell: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      warn("⚠️ Could not configure Git safe directory (not a git repo?)");
    }

    const gitleaksPath = await ensureGitleaksInstalled();
    await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);
    const result = await checkReport(reportPath);

    const filtered = Array.isArray(result)
      ? result.filter(item =>
          !skipFiles.includes(path.basename(item.File)) &&
          !item.File.includes('node_modules') &&
          !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
        )
      : result;

    if (filtered === "No credentials detected." || (Array.isArray(filtered) && filtered.length === 0)) {
      console.log("✅ No credentials detected.");
    } else {
      console.log("🔐 Credentials detected:");
      console.dir(filtered, { depth: null, colors: true });
      process.exitCode = 1;
    }

    fs.unlinkSync(rulesPath);
    console.log('✅ Credential scan completed.');
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
