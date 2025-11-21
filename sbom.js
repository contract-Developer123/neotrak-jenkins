const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const fsPromises = require('fs').promises;

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

// Check and install required packages
ensureDependencyInstalled('axios');
ensureDependencyInstalled('form-data');

const axios = require('axios');
const FormData = require('form-data');

// Environment variables
const workspaceId = process.env.WORKSPACE_ID;
const projectId = process.env.PROJECT_ID;
const apiKey = process.env.X_API_KEY;
const secretKey = process.env.X_SECRET_KEY;
const tenantKey = process.env.X_TENANT_KEY;
const apiUrlBase = 'https://dev.neotrak.io/open-pulse/project';

const projectRoot = process.cwd();
const sbomPath = path.resolve(projectRoot, 'sbom.json');

console.log(`📂 Listing files in directory: ${projectRoot}`);
fs.readdirSync(projectRoot).forEach(file => {
  console.log(`- ${file}`);
});

// Detect manifest files in the user's project root
function getManifestFiles(projectPath) {
  const manifests = [
    'package.json',
    'pom.xml',
    'build.gradle',
    'requirements.txt',
    '.csproj'
  ];
  return manifests.filter(file => fs.existsSync(path.join(projectPath, file)));
}

function runCommand(cmd, callback) {
  exec(cmd, (error, stdout, stderr) => {
    callback(error, stdout.trim(), stderr.trim());
  });
}

// function installCdxgen(callback) {
//   console.log('📦 Installing CDxGen...');
//   runCommand('npm install --no-save @cyclonedx/cdxgen@latest', (err, stdout, stderr) => {
//     if (err) {
//       console.error(`❌ Failed to install CDxGen: ${err.message}`);
//       return;
//     }
//     console.log(stdout);
//     if (stderr) console.error(stderr);
//     callback();
//   });
// }

function installCdxgen(callback) {
  console.log('📦 Installing CDxGen...');

  // Ensure using the public npm registry (if needed)
  const installCmd = 'npm install --no-save @cyclonedx/cdxgen@latest --registry=https://registry.npmjs.org/';

  runCommand(installCmd, (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ Failed to install CDxGen: ${err.message}`);
      console.error('Possible causes: incorrect registry, no internet access, or issues with NPM cache.');
      return;
    }
    console.log(stdout);
    if (stderr) {
      console.error('⚠️ stderr output:', stderr);
    }
    callback();
  });
}

async function uploadSBOM() {
  try {
    await fsPromises.access(sbomPath);
    const stats = fs.statSync(sbomPath);
    const sbomSizeInMB = stats.size / (1024 * 1024);
    console.log(`📄 SBOM file size: ${sbomSizeInMB.toFixed(2)} MB`);

    // Read and filter SBOM
    let sbomContent = JSON.parse(await fsPromises.readFile(sbomPath, 'utf8'));
    let originalComponentCount = sbomContent.components ? sbomContent.components.length : 0;
    console.log(`📋 Original SBOM Components Count: ${originalComponentCount}`);

    // Exclude unwanted components (case-insensitive, partial match)
    const excludeComponents = Array.from(new Set([
      'axios',
      'form-data',
      'asynckit',
      'call-bind-apply-helpers',
      'combined-stream',
      'delayed-stream',
      'dunder-proto',
      'es-define-property',
      'es-errors',
      'es-object-atoms',
      'es-set-tostringtag',
      'follow-redirects',
      'function-bind',
      'get-intrinsic',
      'get-proto',
      'gopd',
      'hasown',
      'has-symbols',
      'has-tostringtag',
      'math-intrinsics',
      'mime-types',
      'mime-db',
      'neotrack',
      'proxy-from-env'
    ]));

    const excludedPatterns = excludeComponents.map(e => e.toLowerCase().trim());

    if (sbomContent.components) {
      sbomContent.components = sbomContent.components.filter(component => {
        const name = (component.name || '').toLowerCase().trim();
        return !excludedPatterns.some(pattern => name.includes(pattern));
      });
      console.log('✅ Filtered unwanted components from SBOM');
      console.log(`📋 Filtered SBOM Components Count: ${sbomContent.components.length}`);

      await fsPromises.writeFile(sbomPath, JSON.stringify(sbomContent, null, 2));
    }

    if (!sbomContent.components || sbomContent.components.length === 0) {
      console.warn('⚠️ Warning: SBOM contains 0 components after filtering. Skipping upload.');
      process.exit(0);
    } else {
      console.log(`📦 Final SBOM component count to upload: ${sbomContent.components.length}`);
    }

    const form = new FormData();
    form.append('sbomFile', fs.createReadStream(sbomPath));
    form.append('displayName', process.env.DISPLAY_NAME || 'sbom');

    let branchName =
      process.env.GITHUB_REF_NAME ||
      process.env.CI_COMMIT_REF_NAME ||
      process.env.BRANCH_NAME ||
      'main';
    form.append('branchName', branchName);

    if (!workspaceId || !projectId) {
      console.error('❌ WORKSPACE_ID or PROJECT_ID environment variables are missing.');
      process.exit(1);
    }

    const apiUrl = `${apiUrlBase}/${projectId}/update-sbom`;
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
      if (response.data && response.data.componentCount) {
        console.log(`📋 API Reported Component Count: ${response.data.componentCount}`);
      } else {
        console.log('📋 No component count provided in API response');
      }
    } else {
      console.error('❌ Failed to upload SBOM. Status:', response.status);
      console.error('Response body:', response.data);
      process.exit(1);
    }
  } catch (err) {
    console.error('❌ Failed to process or upload SBOM', err);
    if (err.response) {
      // Server responded with a status code
      console.error(`🚨 HTTP ${err.response.status}: ${err.response.statusText}`);
      console.error('🔍 Response data:', JSON.stringify(err.response.data, null, 2));
    } else if (err.request) {
      // No response received
      console.error('📡 No response received from the server.');
      console.error(err.request);
    } else {
      // Something else caused the error
      console.error('💥 Unexpected Error:', err.message);
    }

    console.error('🧵 Stack trace:\n', err.stack);
    process.exit(1);
  }
}

function generateSBOM() {
  const foundManifests = getManifestFiles(projectRoot);
  if (foundManifests.length === 0) {
    console.error('❌ No supported manifest file found in the project root.');
    process.exit(1);
  }
  console.log(`🔍 Found manifest file(s): ${foundManifests.join(', ')}`);

  console.log(`🛠️ Preparing environment for SBOM generation...`);

  // If package.json is found, run npm install
  if (foundManifests.includes('package.json')) {
    console.log('📦 package.json detected. Running npm install...');
    try {
      execSync('npm install', { cwd: projectRoot, stdio: 'inherit' });
      console.log('✅ npm install completed.');
    } catch (installErr) {
      console.error('❌ npm install failed:', installErr);
      process.exit(1);
    }
  }
  console.log(`🛠️ Generating SBOM for: ${projectRoot}`);

  const excludeFlags = [
    '--exclude "neotrak-jenkins/**"',
    '--exclude "node_modules/**"'
  ].join(' ');

  runCommand(`npx @cyclonedx/cdxgen "${projectRoot}" -o "${sbomPath}" ${excludeFlags} --spec-version 1.4 --no-dev-dependencies`, async (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ Failed to generate SBOM: ${err.message}`);
      return;
    }
    console.log(stdout);
    if (stderr) console.error(stderr);
    console.log(`✅ SBOM generated as ${sbomPath}`);
    await uploadSBOM();
  });
}

function checkAndGenerateSBOM() {
  console.log('🔍 Checking if CDxGen is already installed...');
  runCommand('npx @cyclonedx/cdxgen --version', (err, stdout, stderr) => {
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
