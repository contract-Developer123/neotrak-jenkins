// // index.js
// const { execSync } = require('child_process');

// function generateSBOM() {
//   try {
//     console.log('📦 Installing CDxGen...');
//     execSync('npm install -g @cyclonedx/cdxgen', { stdio: 'inherit' });

//     console.log('🛠 Generating SBOM...');
//     execSync('cdxgen . -o sbom.json', { stdio: 'inherit' });

//     console.log('✅ SBOM generated in sbom.json');
//   } catch (error) {
//     console.error('❌ Failed to generate SBOM:', error.message);
//     process.exit(1);
//   }
// }

// generateSBOM();


//////////////////////////


const { exec } = require('child_process');

function generateSBOM() {
  console.log('Installing CDxGen...');

  // Install CDxGen locally (not globally)
  exec('npm install @cyclonedx/cdxgen --save-dev', (installError, installStdout, installStderr) => {
    if (installError) {
      console.error(`❌ Error installing CDxGen: ${installError.message}`);
      return;
    }
    console.log(installStdout);
    console.error(installStderr);

    console.log('Checking CDxGen version...');

    // Use npx to run the local binary
    exec('npx cdxgen . -o sbom.json', (error, stdout, stderr) => {
      if (error) {
        console.error(`Error running CDxGen: ${error.message}`);
        return;
      }
      console.log(`CDxGen version: ${stdout.trim()}`);
      if (stderr) console.error(stderr);
      console.log('CDxGen is working.');
    });
  });
}

generateSBOM();


