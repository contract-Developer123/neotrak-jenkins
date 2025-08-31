// index.js
const { execSync } = require('child_process');

function generateSBOM() {
  try {
    console.log('📦 Installing CDxGen...');
    execSync('npm install -g @cyclonedx/cdxgen', { stdio: 'inherit' });

    console.log('🛠 Generating SBOM...');
    execSync('cdxgen . -o sbom.json', { stdio: 'inherit' });

    console.log('✅ SBOM generated in sbom.json');
  } catch (error) {
    console.error('❌ Failed to generate SBOM:', error.message);
    process.exit(1);
  }
}

generateSBOM();
