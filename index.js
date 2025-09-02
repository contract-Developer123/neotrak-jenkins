const { exec } = require('child_process');
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const axios = require('axios');
const FormData = require('form-data');

// Environment variables
const workspaceId = process.env.WORKSPACE_ID;
const projectId = process.env.PROJECT_ID;
const apiKey = process.env.X_API_KEY;
const secretKey = process.env.X_SECRET_KEY;
const tenantKey = process.env.X_TENANT_KEY;
const apiUrlBase = 'https://dev.neotrak.io/open-pulse/project';
const sbomPath = path.resolve('./sbom.json');

function runCommand(cmd, callback) {
  exec(cmd, (error, stdout, stderr) => {
    callback(error, stdout.trim(), stderr.trim());
  });
}

function installCdxgen(callback) {
  console.log('📦 Installing CDxGen...');
  runCommand('npm install @cyclonedx/cdxgen --save-dev', (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ Failed to install CDxGen: ${err.message}`);
      return;
    }
    console.log(stdout);
    if (stderr) console.error(stderr);
    callback();
  });
}

async function uploadSBOM() {
  try {
    await fsPromises.access(sbomPath);
    const stats = fs.statSync(sbomPath);
    const sbomSizeInMB = stats.size / (1024 * 1024);
    console.log(`📄 SBOM file size: ${sbomSizeInMB.toFixed(2)} MB`);

    const form = new FormData({ maxDataSize: 10 * 1024 * 1024 });
    form.append('sbomFile', fs.createReadStream(sbomPath));
    form.append('displayName', process.env.DISPLAY_NAME || 'sbom');

    // Support branch name from GitHub Actions, GitLab CI, Jenkins, or fallback to 'main'
    let branchName =
      process.env.GITHUB_REF_NAME ||      // GitHub Actions
      process.env.CI_COMMIT_REF_NAME ||   // GitLab CI
      process.env.BRANCH_NAME ||          // Jenkins (if set)
      'main';                            // Fallback
    form.append('branchName', branchName);

    if (!workspaceId || !projectId) {
      console.error('❌ WORKSPACE_ID or PROJECT_ID environment variables are missing.');
      process.exit(1);
    }

    const apiUrl = `${apiUrlBase}/${workspaceId}/${projectId}/update-sbom`;
    const headers = { ...form.getHeaders() };
    if (apiKey) headers['x-api-key'] = apiKey;
    if (secretKey) headers['x-secret-key'] = secretKey;
    if (tenantKey) headers['x-tenant-key'] = tenantKey;

    console.log('📤 Uploading SBOM to API:', apiUrl);

    const response = await axios.post(apiUrl, form, {
      headers,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 120000
    });

    if (response.status >= 200 && response.status < 300) {
      console.log('✅ SBOM uploaded successfully:', response.data);
    } else {
      console.error('❌ Failed to upload SBOM. Status:', response.status);
      console.error('Response body:', response.data);
      process.exit(1);
    }
  } catch (err) {
    console.error('❌ Failed to process or upload SBOM', err);
    process.exit(1);
  }
}

function generateSBOM() {
  console.log('🛠️ Generating SBOM...');
  runCommand('npx cdxgen --type nodejs . -o sbom.json', async (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ Failed to generate SBOM: ${err.message}`);
      return;
    }
    console.log(stdout);
    if (stderr) console.error(stderr);
    console.log('✅ SBOM generated as sbom.json');
    await uploadSBOM();
  });
}

function checkAndGenerateSBOM() {
  console.log('🔍 Checking if CDxGen is already installed...');
  runCommand('npx cdxgen --version', (err, stdout, stderr) => {
    if (!err) {
      console.log(`✅ CDxGen is already installed: ${stdout}`);
      generateSBOM();
    } else {
      console.warn('⚠️ CDxGen not found. Installing...');
      installCdxgen(() => {
        generateSBOM();
      });
    }
  });
}

checkAndGenerateSBOM();




// const { exec } = require('child_process');

// function runCommand(cmd, callback) {
//   exec(cmd, (error, stdout, stderr) => {
//     callback(error, stdout.trim(), stderr.trim());
//   });
// }

// function installCdxgen(callback) {
//   console.log('📦 Installing CDxGen...');
//   runCommand('npm install @cyclonedx/cdxgen --save-dev', (err, stdout, stderr) => {
//     if (err) {
//       console.error(`❌ Failed to install CDxGen: ${err.message}`);
//       return;
//     }
//     console.log(stdout);
//     if (stderr) console.error(stderr);
//     callback();
//   });
// }

// function generateSBOM() {
//   console.log('🛠️ Generating SBOM...');
//   // Limiting scan to Node.js to avoid Composer/PHP issues
//   runCommand('npx cdxgen --type nodejs . -o sbom.json', (err, stdout, stderr) => {
//     if (err) {
//       console.error(`❌ Failed to generate SBOM: ${err.message}`);
//       return;
//     }
//     console.log(stdout);
//     if (stderr) console.error(stderr);
//     console.log('✅ SBOM generated as sbom.json');
//   });
// }

// function checkAndGenerateSBOM() {
//   console.log('🔍 Checking if CDxGen is already installed...');

//   runCommand('npx cdxgen --version', (err, stdout, stderr) => {
//     if (!err) {
//       console.log(`✅ CDxGen is already installed: ${stdout}`);
//       generateSBOM();
//     } else {
//       console.warn('⚠️ CDxGen not found. Installing...');
//       installCdxgen(() => {
//         generateSBOM();
//       });
//     }
//   });
// }

// checkAndGenerateSBOM();



