const fs = require('fs');
const path = require('path');

const packageName = process.argv[2];

if (!packageName) {
  console.error('Please provide a package name');
  process.exit(1);
}

const packageDir = path.join(__dirname, '..', 'packages', packageName);

if (fs.existsSync(packageDir)) {
  console.error(`Package "${packageName}" already exists`);
  process.exit(1);
}

fs.mkdirSync(packageDir, { recursive: true });

const packageJson = {
  name: packageName,
  version: '0.1.0',
  main: 'index.js',
  scripts: {
    test: 'echo "Error: no test specified" && exit 1'
  }
};

fs.writeFileSync(
  path.join(packageDir, 'package.json'),
  JSON.stringify(packageJson, null, 2)
);

fs.writeFileSync(
  path.join(packageDir, 'README.md'),
  `# ${packageName}\n\nThis is a new package created with the create:package script.`
);

fs.writeFileSync(
  path.join(packageDir, 'index.js'),
  `console.log('Hello from ${packageName}');`
);

console.log(`Package "${packageName}" created successfully in packages/${packageName}`);
