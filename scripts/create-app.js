const fs = require('fs');
const path = require('path');

const appName = process.argv[2];

if (!appName) {
  console.error('Please provide an app name');
  process.exit(1);
}

const appDir = path.join(__dirname, '..', 'apps', appName);

if (fs.existsSync(appDir)) {
  console.error(`App "${appName}" already exists`);
  process.exit(1);
}

fs.mkdirSync(appDir, { recursive: true });

const packageJson = {
  name: appName,
  version: '0.1.0',
  private: true,
  scripts: {
    start: 'echo "Start script not set" && exit 1',
    build: 'echo "Build script not set" && exit 1',
    test: 'echo "Test script not set" && exit 1'
  }
};

fs.writeFileSync(
  path.join(appDir, 'package.json'),
  JSON.stringify(packageJson, null, 2)
);

fs.writeFileSync(
  path.join(appDir, 'README.md'),
  `# ${appName}\n\nThis is a new app created with the create:app script.`
);

console.log(`App "${appName}" created successfully in apps/${appName}`);
