const { exec, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axios = require('axios');

function ensureDependencyInstalled(pkg) {
  try {
    require.resolve(pkg);
  } catch {
    console.log(`Installing missing dependency: ${pkg}`);
    execSync(`npm install ${pkg}`, { stdio: 'inherit' });
  }
}
ensureDependencyInstalled('axios');

const skipPatterns = [
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

// Checks if a filename or full path should be skipped based on skipPatterns
function shouldSkip(filePathOrName) {
  const baseName = path.basename(filePathOrName);
  return skipPatterns.some(pattern =>
    typeof pattern === 'string' ? pattern === baseName : pattern.test(baseName)
  );
}

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
id = "uuid"
description = "Generic UUIDs"
regex = '''[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'''
tags = ["uuid", "id", "generic"]

[[rules]]
id = "base64-secret"
description = "Generic Base64 Encoded Secret"
regex = '''(?i)(secret|key|token|auth)[\\s"']*[=:][\\s"']*['"]([A-Za-z0-9+/]{32,}={0,2})['"]'''
tags = ["base64", "secret", "key"]

[[rules]]
id = "firebase-api-key"
description = "Firebase API Key"
regex = '''AIza[0-9A-Za-z\\-_]{35}'''
tags = ["firebase", "apikey"]
`;

// Checks if Gitleaks is installed and usable
// function checkGitleaksInstalled() {
//   return new Promise((resolve, reject) => {
//     const command = 'where gitleaks';
//     exec(command, { shell: true }, (err, stdout) => {
//       if (!err && stdout) {
//         const gitleaksPath = stdout.trim().split('\n')[0];
//         try {
//           const version = execSync(`"${gitleaksPath}" --version`, { encoding: 'utf8' });
//           console.log(`✅ Gitleaks found: ${gitleaksPath} (version: ${version.trim()})`);
//           resolve(gitleaksPath);
//         } catch (execErr) {
//           reject(new Error(`Gitleaks found but not executable: ${execErr.message}`));
//         }
//       } else {
//         reject(new Error('Gitleaks not found in PATH.'));
//       }
//     });
//   });
// }

// Ensure Gitleaks is installed and available
function checkGitleaksInstalled() {
  return new Promise((resolve, reject) => {
    const command = os.platform() === 'win32' ? 'where gitleaks' : 'which gitleaks'; // Use `which` or `where` depending on platform
    try {
      execSync(command, { stdio: 'ignore' }); // Execute silently to check if gitleaks is available in PATH
      const version = execSync('gitleaks --version', { encoding: 'utf8' });
      console.log(`✅ Gitleaks found: ${version.trim()}`);
      resolve('gitleaks'); // Return gitleaks path or identifier
    } catch (err) {
      console.log('❌ Gitleaks not found. Attempting to install...');
      installGitleaks().then(resolve).catch(reject);
    }
  });
}

// Install Gitleaks based on the OS
function installGitleaks() {
  return new Promise((resolve, reject) => {
    const platform = os.platform();
    
    if (platform === 'linux' || platform === 'darwin') {
      console.log(`⚙️ Installing Gitleaks on ${platform}...`);
      const downloadUrl = 'https://github.com/zricethezav/gitleaks/releases/latest/download/gitleaks-linux-amd64.tar.gz';
      const tmpFilePath = path.join(os.tmpdir(), 'gitleaks-linux-amd64.tar.gz'); // Temporary path to save the downloaded file
      
      try {
        // Step 1: Download the file
        console.log('⬇️ Downloading Gitleaks binary...');
        execSync(`curl -L ${downloadUrl} -o ${tmpFilePath}`, { stdio: 'inherit' });
        
        // Step 2: Verify if the file is a valid .tar.gz
        console.log('📦 Extracting Gitleaks binary...');
        execSync(`tar -xzvf ${tmpFilePath} -C /usr/local/bin`, { stdio: 'inherit' });
        
        console.log('✅ Gitleaks installed successfully');
        resolve('gitleaks');
      } catch (err) {
        reject(new Error(`❌ Failed to install Gitleaks: ${err.message}`));
      } finally {
        // Clean up the downloaded file (if the download was successful)
        if (fs.existsSync(tmpFilePath)) {
          fs.unlinkSync(tmpFilePath);
        }
      }
    } else {
      reject(new Error(`❌ Unsupported platform: ${platform}`));
    }
  });
}

// Download Gitleaks for Windows if Chocolatey is not available
function downloadGitleaksWindows() {
  return new Promise((resolve, reject) => {
    const downloadUrl = 'https://github.com/zricethezav/gitleaks/releases/latest/download/gitleaks-windows-amd64.exe';
    const filePath = path.join('C:', 'gitleaks.exe');
    try {
      execSync(`curl -L ${downloadUrl} -o ${filePath}`, { stdio: 'inherit' });
      execSync(`move ${filePath} C:\\Windows\\System32\\gitleaks.exe`, { stdio: 'inherit' });
      resolve('gitleaks');
    } catch (err) {
      reject(new Error(`❌ Failed to download or install Gitleaks on Windows: ${err.message}`));
    }
  });
}



// Recursively get files to scan, skipping those matching skipPatterns or certain directories
function getAllFiles(dir, array = []) {
  if (!fs.existsSync(dir)) {
    console.warn(`⚠️ Directory does not exist: ${dir}`);
    return array;
  }

  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);

    // Skip unwanted files/folders
    if (shouldSkip(fullPath) || ['node_modules', '.git', 'neotrak-jenkins'].includes(file)) {
      // For debugging
      continue;
    }

    if (stat.isDirectory()) {
      getAllFiles(fullPath, array);
    } else {
      array.push(fullPath);
    }
  }
  return array;
}

function writeCustomRules(rules) {
  const filePath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
  fs.writeFileSync(filePath, rules, 'utf8');
  return filePath;
}

function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
  return new Promise((resolve, reject) => {
    // Use --source=scanDir for whole directory scan to avoid huge file lists and maxBuffer issues
    const cmd = `"${gitleaksPath}" detect --no-git --source="${scanDir}" --config="${rulesPath}" --report-path="${reportPath}" --report-format=json --verbose`;

    exec(cmd, { shell: true, maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
      // if (stdout) console.log(`Gitleaks output:\n${stdout}`);
      if (stderr) console.warn(`Gitleaks stderr:\n${stderr}`);

      if (error && error.code !== 1) { // gitleaks returns exit code 1 on leaks found - not an error for us
        reject(new Error(`Gitleaks execution failed: ${error.message}`));
        return;
      }
      resolve();
    });
  });
}

async function readReport(reportPath) {
  try {
    const data = fs.readFileSync(reportPath, 'utf8');
    const json = JSON.parse(data);
    return json.length > 0 ? json : [];
  } catch (err) {
    console.error('Failed to read or parse Gitleaks report:', err.message);
    return [];
  }
}

function filterSecrets(results) {
  return results.filter(item => {
    if (!item.File) return false;
    if (shouldSkip(item.File)) {
      // console.log(`⏭️ Filtered out secret from skipped file: ${item.File}`);
      return false;
    }
    // Exclude secrets in node_modules or neotrak-jenkins directories
    if (item.File.includes('node_modules') || item.File.includes('neotrak-jenkins')) {
      return false;
    }
    // Exclude environment variable placeholders like "${VAR_NAME}"
    if (/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)) {
      return false;
    }
    return true;
  });
}

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

function mapToApiFormat(item) {
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

async function sendSecretsToApi(secrets) {
  if (!secrets.length) {
    console.log('✅ No secrets to send to API.');
    return;
  }

  const projectId = process.env.PROJECT_ID;
  if (!projectId) {
    console.error('❌ PROJECT_ID environment variable is missing.');
    return;
  }

  const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-secrets/${projectId}`;

  const headers = {
    'Content-Type': 'application/json',
  };

  if (process.env.X_API_KEY) headers['x-api-key'] = process.env.X_API_KEY;
  if (process.env.X_SECRET_KEY) headers['x-secret-key'] = process.env.X_SECRET_KEY;
  if (process.env.X_TENANT_KEY) headers['x-tenant-key'] = process.env.X_TENANT_KEY;

  const payload = secrets.map(mapToApiFormat);

  try {
    const response = await axios.post(apiUrl, payload, { headers, timeout: 60000 });
    if (response.status >= 200 && response.status < 300) {
      console.log('✅ Secrets sent successfully to API.');
    } else {
      console.error(`❌ API responded with status ${response.status}:`, response.data);
    }
  } catch (err) {
    console.error('❌ Error sending secrets to API:', err.message);
  }
}

async function main() {
  try {
    console.log('🧾 Starting secret detection...');

    const scanDir = process.env.SCAN_DIR || process.cwd();
    const reportPath = path.join(os.tmpdir(), `credentials_report_${Date.now()}.json`);
    const rulesPath = writeCustomRules(customRules);

    console.log(`📂 Scan directory: ${scanDir}`);
    console.log(`📄 Report path: ${reportPath}`);
    console.log(`📝 Rules file: ${rulesPath}`);

    // const gitleaksPath = await checkGitleaksInstalled();
    // await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);
     await checkGitleaksInstalled(); 
     await runGitleaks(scanDir, reportPath, rulesPath, 'gitleaks');

    const results = await readReport(reportPath);

    if (!results.length) {
      console.log('✅ No secrets detected.');
      return;
    }

    console.log(`🔐 Total secrets detected: ${results.length}`);

    const filteredSecrets = filterSecrets(results);

    if (filteredSecrets.length > 0) {
      await sendSecretsToApi(filteredSecrets);
    } else {
      console.log('✅ No secrets found after filtering.');
    }

  } catch (err) {
    console.error('❌ Fatal error:', err.message);
    process.exit(1);
  }
}

main();
