const { exec, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

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
      console.log('📤 Gitleaks STDOUT:\n', stdout);

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

// Main function to detect credentials
async function main() {
  console.log('🧾 Detecting credentials in folder...');
  try {
    const scanDir = path.join(process.SCAN_DIR || process.cwd());
    const reportPath = path.join(scanDir, `credentials_report_${Date.now()}.json`);
    const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');

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
      : result;

    if (filteredSecrets.length > 0) {
      console.log("🔐 Filtered credentials detected:");
      filteredSecrets.forEach(item => {
        const formattedFilteredSecret = mapToSecretFormat(item);
        console.log(formattedFilteredSecret);
      });
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