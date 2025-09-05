const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const fsPromises = require('fs').promises;
const axios = require('axios');
const FormData = require('form-data');

// Ensure dependencies are installed in a temporary directory
// function ensureDependencies() {
//   const tempDir = path.join(__dirname, 'temp_node_modules');
//   const nodeModulesPath = path.join(tempDir, 'node_modules');
//   const axiosPath = path.join(nodeModulesPath, 'axios');
//   const formDataPath = path.join(nodeModulesPath, 'form-data');
//   if (!fs.existsSync(axiosPath) || !fs.existsSync(formDataPath)) {
//     console.log('📦 Installing dependencies: axios, form-data in temp directory...');
//     if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);
//     execSync(`npm install axios form-data --prefix ${tempDir}`, { stdio: 'inherit' });
//   }
//   // Update require paths to use temp directory
//   require('module').Module._initPaths();
//   process.env.NODE_PATH = `${process.env.NODE_PATH || ''}:${nodeModulesPath}`;
// }

// ensureDependencies();

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

function installCdxgen(callback) {
  console.log('📦 Installing CDxGen...');
  runCommand('npm install @cyclonedx/cdxgen@latest --save-dev', (err, stdout, stderr) => {
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

    // Read and filter SBOM
    let sbomContent = JSON.parse(await fsPromises.readFile(sbomPath, 'utf8'));
    let originalComponentCount = sbomContent.components ? sbomContent.components.length : 0;
    console.log(`📋 Original SBOM Components Count: ${originalComponentCount}`);

    // Filter out axios, form-data, and their transitive dependencies
    const excludeComponents = [
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
      'neotrack',
      'proxy-from-env',
      'mime-types',
      'mime-db',
      'math-intrinsics',
      '	has-tostringtag',
      'has-symbols',
    ];
    if (sbomContent.components) {
      sbomContent.components = sbomContent.components.filter(component => {
        const componentName = component.name || '';
        return !excludeComponents.includes(componentName);
      });
      console.log('✅ Filtered unwanted components from SBOM');
      console.log(`📋 Filtered SBOM Components Count: ${sbomContent.components.length}`);
      await fsPromises.writeFile(sbomPath, JSON.stringify(sbomContent, null, 2));
    }

    const form = new FormData({ maxDataSize: 10 * 1024 * 1024 });
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
  console.log(`🛠️ Generating SBOM for: ${projectRoot}`);

  const excludeFlags = [
    '--exclude "neotrak-jenkins/**"',
    '--exclude "node_modules/**"'
  ].join(' ');

  runCommand(`npx cdxgen "${projectRoot}" -o "${sbomPath}" ${excludeFlags} --spec-version 1.4 --no-dev-dependencies`, async (err, stdout, stderr) => {
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


// const { exec, execSync } = require('child_process');
// const fs = require('fs');
// const path = require('path');

// // Ensure dependencies are installed
// function ensureDependencies() {
//   const nodeModulesPath = path.join(__dirname, 'node_modules');
//   const axiosPath = path.join(nodeModulesPath, 'axios');
//   const formDataPath = path.join(nodeModulesPath, 'form-data');
//   if (!fs.existsSync(axiosPath) || !fs.existsSync(formDataPath)) {
//     console.log('📦 Installing dependencies: axios, form-data...');
//     execSync('npm install axios form-data', { stdio: 'inherit' });
//   }
// }

// ensureDependencies();

// const fsPromises = require('fs').promises;
// const axios = require('axios');
// const FormData = require('form-data');

// // Environment variables
// const workspaceId = process.env.WORKSPACE_ID;
// const projectId = process.env.PROJECT_ID;
// const apiKey = process.env.X_API_KEY;
// const secretKey = process.env.X_SECRET_KEY;
// const tenantKey = process.env.X_TENANT_KEY;
// const apiUrlBase = 'https://dev.neotrak.io/open-pulse/project';

// const projectRoot = process.cwd();
// const sbomPath = path.resolve(projectRoot, 'sbom.json');


// console.log(`📂 Listing files in directory: ${projectRoot}`);
// fs.readdirSync(projectRoot).forEach(file => {
//   console.log(`- ${file}`);
// });

// // Detect manifest files in the user's project roo
// function getManifestFiles(projectPath) {
//   const manifests = [
//     'package.json',
//     'pom.xml',
//     'build.gradle',
//     'requirements.txt',
//     '.csproj'
//   ];
//   return manifests.filter(file => fs.existsSync(path.join(projectPath, file)));
// }

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

// async function uploadSBOM() {
//   try {
//     await fsPromises.access(sbomPath);
//     const stats = fs.statSync(sbomPath);
//     const sbomSizeInMB = stats.size / (1024 * 1024);
//     console.log(`📄 SBOM file size: ${sbomSizeInMB.toFixed(2)} MB`);

//     const form = new FormData({ maxDataSize: 10 * 1024 * 1024 });
//     form.append('sbomFile', fs.createReadStream(sbomPath));
//     form.append('displayName', process.env.DISPLAY_NAME || 'sbom');

//     // Support branch name from GitHub Actions, GitLab CI, Jenkins, or fallback to 'main'
//     let branchName =
//       process.env.GITHUB_REF_NAME ||      // GitHub Actions
//       process.env.CI_COMMIT_REF_NAME ||   // GitLab CI
//       process.env.BRANCH_NAME ||          // Jenkins (if set)
//       'main';                            // Fallback
//     form.append('branchName', branchName);

//     if (!workspaceId || !projectId) {
//       console.error('❌ WORKSPACE_ID or PROJECT_ID environment variables are missing.');
//       process.exit(1);
//     }

//     const apiUrl = `${apiUrlBase}/${workspaceId}/${projectId}/update-sbom`;
//     const headers = { ...form.getHeaders() };
//     if (apiKey) headers['x-api-key'] = apiKey;
//     if (secretKey) headers['x-secret-key'] = secretKey;
//     if (tenantKey) headers['x-tenant-key'] = tenantKey;

//     console.log('📤 Uploading SBOM to API:', apiUrl);

//     const response = await axios.post(apiUrl, form, {
//       headers,
//       maxContentLength: Infinity,
//       maxBodyLength: Infinity,
//       timeout: 120000
//     });

//     if (response.status >= 200 && response.status < 300) {
//       console.log('✅ SBOM uploaded successfully:', response.data);
//     } else {
//       console.error('❌ Failed to upload SBOM. Status:', response.status);
//       console.error('Response body:', response.data);
//       process.exit(1);
//     }
//   } catch (err) {
//     console.error('❌ Failed to process or upload SBOM', err);
//     process.exit(1);
//   }
// }

// function generateSBOM() {
//   const foundManifests = getManifestFiles(projectRoot);
//   if (foundManifests.length === 0) {
//     console.error('❌ No supported manifest file found in the project root.');
//     process.exit(1);
//   }
//   console.log(`🔍 Found manifest file(s): ${foundManifests.join(', ')}`);
//   console.log(`🛠️ Generating SBOM for: ${projectRoot}`);

//   const excludeFlags = [
//     '--exclude "neotrak-jenkins/**"',
//     '--exclude "node_modules/**"',
//     '--exclude "**/axios/**"',
//     '--exclude "**/form-data/**"'
//   ].join(' ');

//   runCommand(`npx cdxgen "${projectRoot}" -o "${sbomPath}" ${excludeFlags}`, async (err, stdout, stderr) => {
//     if (err) {
//       console.error(`❌ Failed to generate SBOM: ${err.message}`);
//       return;
//     }
//     console.log(stdout);
//     if (stderr) console.error(stderr);
//     console.log(`✅ SBOM generated as ${sbomPath}`);
//     await uploadSBOM();
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


//////////////////////////////////////////////////////////////////////////////////////////////////

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



