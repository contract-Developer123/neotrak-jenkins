const { spawn } = require('child_process');

const scanTypeRaw = process.env.SCAN_TYPE || '';
const scanTypes = scanTypeRaw
  .split(',')
  .map(type => type.trim().toLowerCase());

function runScript(scriptPath) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [scriptPath], { stdio: 'inherit' });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`❌ ${scriptPath} exited with code ${code}`));
      }
    });

    proc.on('error', (err) => {
      reject(new Error(`❌ Failed to start ${scriptPath}: ${err.message}`));
    });
  });
}

async function runScans() {
  try {
    const tasks = [];

    if (scanTypes.includes('sca')) {
      console.log('🧪 Running SCA scan...');
      tasks.push(runScript('sbom.js'));
    }

    if (scanTypes.includes('configs') || scanTypes.includes('config')) {
      console.log('🧾 Running Config scan...');
      tasks.push(runScript('config-scanner.js'));
    }

    if (tasks.length === 0) {
      console.log(`⚠️ No valid SCAN_TYPE found in "${scanTypeRaw}". Skipping scans.`);
      process.exit(0);
    }

    // Run scans in sequence (await one after another)
    for (const task of tasks) {
      await task;
    }

    console.log('✅ All scans completed successfully.');
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

runScans();
