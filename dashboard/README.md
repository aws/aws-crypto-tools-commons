# AWS Crypto Tools Dashboard

A static page that shows pull requests, issues, and daily CI across the Crypto Tools repos, plus a Test Server Results tab.

The page calls the GitHub API from your browser. Paste a classic GitHub token (`repo` scope, SSO-authorized for the `aws` org) on the Settings page. The token stays in your browser's localStorage, and every tab uses it.

`.github/workflows/dashboard-pages.yml` publishes this folder to GitHub Pages on every push to `main` that changes it.

## Files

```
├── index.html        # Main dashboard page
├── config.js         # Repository list and token storage
├── dashboard.js      # Dashboard functionality
├── styles.css        # Styling
└── test-servers/     # Test Server Results tab
```

To add a repository, add an entry to `REPOSITORIES` in `config.js`.
