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
├── pr-review/        # PR Review tab
└── test-servers/     # Test Server Results tab
```

To add a repository, add an entry to `REPOSITORIES` in `config.js`.

## PR Review

`?pr=owner/repo#N#pr-review` on the dashboard opens one pull request on the PR Review tab. The PR goes into the box that the PR Review, Duvet and Test Servers tabs share, so each of them shows it. Pasting another PR into any of them changes it for all of them.

The tab lists only what needs a look: failed checks, changed lines no test runs, branches no test takes, mutants no test catches, duvet tests that miss their code, failed test server cases, open Smithy conformance findings, and API changes. Below that it shows those lines, with two lines around each; GitHub shows the whole diff. With nothing to look at, it says so in one line. The line box, or `&line=<file>:<line>` in the link, opens any other line of the head commit.

It reads the artifacts that the PR's CI runs upload: `mutation-results-*`, `local-coverage-*`, `per-test-coverage-*`, `*-test-server-reports`, `duvet-test-reach-*` and `smithy-conformance-*`. For an aws-crypto-tools-rust PR, its CI also uploads `api-types-rust` and `api-types-rust-base`, the API at the head commit and at the merge base, which the tab compares. `?ref=<commons branch>` goes on to the API Examples page in its links.

A click on a line opens its side pane, where a review comment posts to GitHub as you. That needs a token that can write pull requests. No AI runs on the page. "Ask an AI" gives a prompt for the library-pr-review skill, which reads the same artifacts.

`node --test dashboard/pr-review/review.test.js` runs its tests.
