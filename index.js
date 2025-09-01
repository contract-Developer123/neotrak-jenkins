// const { exec } = require('child_process');

// function generateSBOM() {
//   console.log('Installing CDxGen...');

//   // Install CDxGen locally (not globally)
//   exec('npm install @cyclonedx/cdxgen --save-dev', (installError, installStdout, installStderr) => {
//     if (installError) {
//       console.error(`❌ Error installing CDxGen: ${installError.message}`);
//       return;
//     }
//     console.log(installStdout);
//     console.error(installStderr);

//     console.log('Checking CDxGen version...');

//     // Use npx to run the local binary
//     exec('npx cdxgen . -o sbom.json', (error, stdout, stderr) => {
//       if (error) {
//         console.error(`Error running CDxGen: ${error.message}`);
//         return;
//       }
//       console.log(`CDxGen version: ${stdout.trim()}`);
//       if (stderr) console.error(stderr);
//       console.log('CDxGen is working.');
//     });
//   });
// }

// generateSBOM();


const { exec } = require('child_process');

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

function generateSBOM() {
  console.log('🛠️ Generating SBOM...');
  // Limiting scan to Node.js to avoid Composer/PHP issues
  runCommand('npx cdxgen --type nodejs . -o sbom.json', (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ Failed to generate SBOM: ${err.message}`);
      return;
    }
    console.log(stdout);
    if (stderr) console.error(stderr);
    console.log('✅ SBOM generated as sbom.json');
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



