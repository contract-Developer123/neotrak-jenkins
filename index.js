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

const { exec } = require('child_process');

function generateSBOM() {
  console.log('📦 Installing CDxGen...');
  
  exec('npm install -g @cyclonedx/cdxgen', (error, stdout, stderr) => {
    if (error) {
      console.error(`❌ Error installing CDxGen: ${error.message}`);
      return;
    }
    console.log(stdout);
    console.error(stderr);

    console.log('🛠 Generating SBOM...');
    
    exec('cdxgen . -o sbom.json', (error, stdout, stderr) => {
      if (error) {
        console.error(`❌ Error generating SBOM: ${error.message}`);
        return;
      }
      console.log(stdout);
      console.error(stderr);
      console.log('✅ SBOM generated in sbom.json');
    });
  });
}

generateSBOM();
