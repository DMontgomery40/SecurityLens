import { execSync } from 'child_process';

function runCommand(command) {
    try {
        execSync(command, { stdio: 'inherit' });
    } catch (error) {
        console.error(`Failed to execute command: ${command}`);
        process.exit(1);
    }
}

// First, commit any pending changes
runCommand('git add .');
runCommand('git commit -m "Auto-commit before sync"');

// Configure git pull strategy
runCommand('git config pull.rebase false');

// Ensure we're on main branch and it's up to date
runCommand('git checkout main');
runCommand('git pull origin main');

// Sync development branch
runCommand('git fetch origin development');
runCommand('git checkout development');
runCommand('git pull origin development');
runCommand('git merge main --no-ff -m "Sync development with main"');
runCommand('git push origin development');

// Install dependencies if needed
runCommand('npm install');

// Build and sync gh-pages
runCommand('git checkout development');
runCommand('npm run build');
runCommand('git add dist -f');
runCommand('git commit -m "Build for gh-pages"');
runCommand('npm run deploy');

// Return to main branch
runCommand('git checkout main');

console.log('Successfully synced all branches!'); 