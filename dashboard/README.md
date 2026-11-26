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
├── api-examples/     # API Examples tab
├── pr-review/        # PR Review tab
└── test-servers/     # Test Server Results tab
```

To add a repository, add an entry to `REPOSITORIES` in `config.js`.

## PR Review

`pr-review/index.html?pr=owner/repo#N` shows one pull request's diff with what CI found on each changed line: whether a test runs it, branches no test takes, mutants no test catches, the tests that run it, its duvet annotation, and the API option it belongs to. Above the diff it lists only what needs a look. With nothing to look at, it says so in one line.

It reads the artifacts that the PR's CI runs upload: `mutation-results-*`, `local-coverage-*`, `per-test-coverage-*`, `*-test-server-reports`, `duvet-test-reach-*` and `smithy-conformance-*`. For an aws-crypto-tools-rust PR, it also compares the API at the PR's head commit with main's. That comes from an `api-examples-types.yml` run with `rust-ref` set to the head commit, which the page can start. `?ref=<commons branch>` picks the branch whose types runs it reads and starts.

A click on a line opens its side pane, where a review comment posts to GitHub as you. That needs a token that can write pull requests. No AI runs on the page. "Ask an AI" gives a prompt for the library-pr-review skill, which reads the same artifacts.

`node --test dashboard/pr-review/review.test.js` runs its tests.
