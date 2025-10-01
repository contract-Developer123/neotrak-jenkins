
// const { spawn, execSync } = require('child_process');
// const fs = require('fs');
// const path = require('path');
// const fsPromises = require('fs').promises;

// function ensureDependencyInstalled(packageName) {
//   try {
//     require.resolve(packageName);
//   } catch (e) {
//     console.warn(`📦 '${packageName}' not found. Installing...`);
//     try {
//       execSync(`npm install ${packageName}`, { stdio: 'inherit' });
//       console.log(`✅ '${packageName}' installed successfully.`);
//     } catch (installErr) {
//       console.error(`❌ Failed to install '${packageName}':`, installErr);
//       process.exit(1);
//     }
//   }
// }

// // Check and install required packages
// ensureDependencyInstalled('axios');
// ensureDependencyInstalled('form-data');

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

// // Detect manifest files in the user's project root
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

// async function uploadSBOM() {
//   try {
//     await fsPromises.access(sbomPath);
//     const stats = fs.statSync(sbomPath);
//     const sbomSizeInMB = stats.size / (1024 * 1024);
//     console.log(`📄 SBOM file size: ${sbomSizeInMB.toFixed(2)} MB`);

//     // Read SBOM content
//     let sbomContent = JSON.parse(await fsPromises.readFile(sbomPath, 'utf8'));
//     let originalComponentCount = sbomContent.components ? sbomContent.components.length : 0;
//     console.log(`📋 Original SBOM Components Count: ${originalComponentCount}`);

//     if (!sbomContent.components || sbomContent.components.length === 0) {
//       console.warn('⚠️ Warning: SBOM contains 0 components. Skipping upload.');
//       process.exit(0);
//     } else {
//       console.log(`📦 Final SBOM component count to upload: ${sbomContent.components.length}`);
//     }

//     const form = new FormData();
//     form.append('sbomFile', fs.createReadStream(sbomPath));
//     form.append('displayName', process.env.DISPLAY_NAME || 'sbom');

//     let branchName =
//       process.env.GITHUB_REF_NAME ||
//       process.env.CI_COMMIT_REF_NAME ||
//       process.env.BRANCH_NAME ||
//       'main';
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
//       if (response.data && response.data.componentCount) {
//         console.log(`📋 API Reported Component Count: ${response.data.componentCount}`);
//       } else {
//         console.log('📋 No component count provided in API response');
//       }
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

// // Helper for spawning commands on Windows (cmd /c) and other platforms
// const isWindows = process.platform === 'win32';

// function spawnCommand(command, args, options = {}) {
//   if (isWindows) {
//     args = ['/c', command, ...args];
//     command = 'cmd';
//   }
//   return spawn(command, args, options);
// }

// function installCdxgen(callback) {
//   console.log('📦 Installing CDxGen...');
//   const install = spawnCommand('npm', ['install', '--no-save', '@cyclonedx/cdxgen@latest'], { stdio: 'inherit' });

//   install.on('close', (code) => {
//     if (code === 0) {
//       callback();
//     } else {
//       console.error(`❌ Failed to install CDxGen, exit code ${code}`);
//       process.exit(1);
//     }
//   });

//   install.on('error', (err) => {
//     console.error('❌ Error installing CDxGen:', err);
//     process.exit(1);
//   });
// }

// function generateSBOM() {
//   const foundManifests = getManifestFiles(projectRoot);
//   if (foundManifests.length === 0) {
//     console.error('❌ No supported manifest file found in the project root.');
//     process.exit(1);
//   }
//   console.log(`🔍 Found manifest file(s): ${foundManifests.join(', ')}`);
//   console.log(`🛠️ Generating SBOM for: ${projectRoot}`);

//   // Arguments for cdxgen
//   const cdxgenArgs = [
//     projectRoot,
//     '-o', sbomPath,
//     '--exclude', 'neotrak-jenkins/**',
//     '--exclude', 'node_modules/**',
//     '--spec-version', '1.4',
//     '--no-dev-dependencies'
//   ];

//   const cdxgen = spawnCommand('npx', ['cdxgen', ...cdxgenArgs], { stdio: 'inherit' });

//   cdxgen.on('error', (err) => {
//     console.error('❌ Failed to start cdxgen:', err);
//     process.exit(1);
//   });

//   cdxgen.on('close', async (code) => {
//     if (code === 0) {
//       console.log(`✅ SBOM generated at ${sbomPath}`);
//       try {
//         await uploadSBOM();
//       } catch (err) {
//         console.error('❌ Error uploading SBOM:', err);
//         process.exit(1);
//       }
//     } else {
//       console.error(`❌ cdxgen exited with code ${code}`);
//       process.exit(1);
//     }
//   });
// }

// function checkAndGenerateSBOM() {
//   console.log('🔍 Checking if CDxGen is already installed...');
//   const check = spawnCommand('npx', ['cdxgen', '--version']);

//   let output = '';
//   let errorOutput = '';

//   check.stdout.on('data', (data) => {
//     output += data.toString();
//   });

//   check.stderr.on('data', (data) => {
//     errorOutput += data.toString();
//   });

//   check.on('close', (code) => {
//     if (code === 0) {
//       console.log(`✅ CDxGen is already installed: ${output.trim()}`);
//       generateSBOM();
//     } else {
//       console.warn('⚠️ CDxGen not found. Installing...');
//       installCdxgen(() => {
//         generateSBOM();
//       });
//     }
//   });

//   check.on('error', (err) => {
//     console.warn('⚠️ Error checking cdxgen:', err);
//     console.warn('⚠️ Attempting to install CDxGen...');
//     installCdxgen(() => {
//       generateSBOM();
//     });
//   });
// }

// checkAndGenerateSBOM();




/////////////////////////////////////////////////////////////////////////


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

function installCdxgen(callback) {
  console.log('📦 Installing CDxGen...');
  runCommand('npm install --no-save @cyclonedx/cdxgen@latest', (err, stdout, stderr) => {
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

      // console.log('🧹 Filtered component names:');
      // sbomContent.components.forEach(c => console.log(`- ${c.name}`));

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
