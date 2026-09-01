# Enhanced Code Coverage Report Template for cloudhealthoffice

## Overview

This document provides a workflow template to enhance the code coverage reporting in the **cloudhealthoffice** repository, modeled after the comprehensive coverage implementation in the **privaseeai.net** build (PrivaseeAI.Security repository).

## What's Different?

### Current CloudHealthOffice Coverage (codecov.yml)
✅ Basic codecov upload  
✅ Terminal coverage summary  
❌ No HTML coverage artifacts  
❌ No test result publishing  
❌ No PR coverage comments  
❌ No test artifacts  

### Enhanced Coverage (This Template)
✅ Codecov upload (retained)  
✅ Terminal coverage summary (retained)  
✅ **HTML coverage reports as downloadable artifacts** (30-day retention)  
✅ **Test results published as PR status checks**  
✅ **Automated coverage comments on PRs**  
✅ **Test result artifacts for debugging**  

## Implementation Guide

### Step 1: Install Required Dependencies

Add the `jest-junit` package to your `devDependencies` in `package.json`:

```bash
npm install --save-dev jest-junit
```

### Step 2: Configure Jest for JUnit Output

Update your `jest.config.js` or `package.json` jest configuration to support junit reporting:

```javascript
// jest.config.js
module.exports = {
  // ... existing config ...
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: './test-results',
      outputName: 'junit.xml',
    }]
  ],
};
```

Or in `package.json`:

```json
{
  "jest": {
    "reporters": [
      "default",
      ["jest-junit", {
        "outputDirectory": "./test-results",
        "outputName": "junit.xml"
      }]
    ]
  }
}
```

### Step 3: Update `.gitignore`

Add these lines to `.gitignore` if not already present:

```
# Test results and coverage
coverage/
test-results/
*.lcov
```

### Step 4: Replace the Workflow File

Replace the current `.github/workflows/codecov.yml` with the enhanced version:

1. **Option A: Direct replacement**
   - Copy the content from `.github/workflow-templates/nodejs-coverage-enhanced.yml` in this repository
   - Replace `.github/workflows/codecov.yml` in cloudhealthoffice repository

2. **Option B: Create new workflow**
   - Keep the existing `codecov.yml` as backup
   - Create a new file `.github/workflows/test.yml` with the enhanced template
   - Disable the old workflow once the new one is verified

### Step 5: Verify Permissions

Ensure your GitHub Actions workflow has the necessary permissions. The enhanced workflow requires:

```yaml
permissions:
  contents: read
  checks: write
  pull-requests: write
```

These are already included in the template.

### Step 6: Test the Workflow

1. Create a pull request with the new workflow
2. Verify that the workflow runs successfully
3. Check for the following:
   - ✅ Tests execute with coverage
   - ✅ Codecov upload succeeds
   - ✅ Test results appear as PR checks
   - ✅ Coverage comment appears on PR
   - ✅ Artifacts are available for download

## What You'll Get

### 1. HTML Coverage Reports

After each workflow run, you can download a complete HTML coverage report:

- Navigate to the workflow run in the **Actions** tab
- Scroll to the **Artifacts** section
- Download `coverage-report-html`
- Open `index.html` in your browser for interactive coverage exploration

### 2. Test Results as PR Checks

Test results will appear as status checks on pull requests:
- ✅ Total tests passed/failed/skipped
- ✅ Test execution time
- ✅ Detailed breakdown by test suite

### 3. PR Coverage Comments

Each PR will get an automated comment showing:
- Overall coverage percentage
- Coverage changes (increase/decrease)
- File-by-file coverage breakdown
- Uncovered lines highlighted

### 4. Test Result Artifacts

JUnit XML test results are uploaded as artifacts for:
- Integration with external tools
- Historical test result tracking
- Debugging test failures

## Enhanced Features Explained

### Feature 1: Multiple Coverage Report Formats

```yaml
npm test -- --coverage \
  --coverageReporters=lcov \        # For Codecov
  --coverageReporters=json-summary \ # For summary display
  --coverageReporters=text \         # For terminal output
  --coverageReporters=html           # For browsable report
```

### Feature 2: Test Results Publishing

```yaml
- name: Publish Test Results
  uses: EnricoMi/publish-unit-test-result-action@v2
  if: always()
  with:
    files: test-results/junit.xml
    check_name: Test Results
```

This creates a status check on PRs with test statistics.

### Feature 3: Coverage Comments on PRs

```yaml
- name: Comment coverage on PR
  uses: romeovs/lcov-reporter-action@v0.3.1
  if: github.event_name == 'pull_request'
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    lcov-file: ./coverage/lcov.info
    delete-old-comments: true
```

Automatically posts coverage information to PRs.

**Security Note:** This example uses a mutable tag (`@v0.3.1`). For enhanced security in production environments, consider pinning this action to a specific commit SHA to prevent potential supply chain attacks. For example: `uses: romeovs/lcov-reporter-action@<commit-sha>`. You can find the commit SHA for a specific release on the action's GitHub repository.

### Feature 4: Artifact Upload

```yaml
- name: Upload coverage HTML report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: coverage-report-html
    path: coverage/
    retention-days: 30
```

Stores coverage and test results for 30 days.

## Comparison with PrivaseeAI.Security

| Feature | PrivaseeAI.Security (Python) | Enhanced CloudHealthOffice (TypeScript) |
|---------|----------------------------|----------------------------------------|
| Code Coverage Tool | pytest-cov | Jest |
| Coverage Upload | Codecov | Codecov |
| HTML Reports | ✅ htmlcov/ | ✅ coverage/ |
| Test Result Publishing | ✅ EnricoMi action | ✅ EnricoMi action |
| PR Coverage Comments | ✅ py-cov-action/python-coverage-comment-action | ✅ lcov-reporter-action |
| Test Artifacts | ✅ JUnit XML | ✅ JUnit XML |
| Artifact Retention | 30 days | 30 days |
| Multi-version Matrix | Python 3.11, 3.12 | Node.js 20 (single) |

## Troubleshooting

### Issue: jest-junit not generating output

**Solution:** Ensure jest-junit is properly configured in jest.config.js and the outputDirectory exists or can be created.

### Issue: Coverage comment not appearing on PR

**Solution:** 
1. Verify the workflow has `pull-requests: write` permission
2. Check that the workflow is running on `pull_request` events
3. Ensure the lcov.info file exists in ./coverage/

### Issue: Test Results check not showing up

**Solution:**
1. Verify the workflow has `checks: write` permission
2. Ensure JUnit XML file is generated in the correct location
3. Check workflow logs for any errors from the publish-unit-test-result-action

### Issue: Artifacts not uploading

**Solution:**
1. Verify paths are correct (coverage/ and test-results/)
2. Ensure tests are running and generating output
3. Check that `if: always()` is present to upload even on failure

## Additional Customization

### Adjust Coverage Thresholds

You can add coverage thresholds in your `jest.config.js`:

```javascript
module.exports = {
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};
```

### Change Artifact Retention

Modify the `retention-days` value (default is 30, max is 90):

```yaml
retention-days: 90  # Keep artifacts for 90 days
```

### Add Coverage Badges

After implementing this workflow, add a coverage badge to your README:

```markdown
[![Code Coverage](https://codecov.io/gh/aurelianware/cloudhealthoffice/branch/main/graph/badge.svg)](https://codecov.io/gh/aurelianware/cloudhealthoffice)
```

## Benefits

1. **Better PR Reviews**: Reviewers can see coverage impact immediately
2. **Interactive Exploration**: HTML reports let you explore uncovered code paths
3. **Historical Tracking**: 30-day artifact retention for trend analysis
4. **Automated Feedback**: PR comments reduce manual coverage checks
5. **Debugging Support**: JUnit XML for integration with test reporting tools

## Support

For issues or questions:
1. Check the workflow logs in GitHub Actions
2. Review the troubleshooting section above
3. Compare with the working PrivaseeAI.Security implementation
4. Consult the documentation for the GitHub Actions used:
   - [codecov-action](https://github.com/codecov/codecov-action)
   - [publish-unit-test-result-action](https://github.com/EnricoMi/publish-unit-test-result-action)
   - [lcov-reporter-action](https://github.com/romeovs/lcov-reporter-action)

---

**Template Version:** 1.0  
**Last Updated:** 2026-02-04  
**Tested With:** Node.js 20, Jest 29, TypeScript 5
