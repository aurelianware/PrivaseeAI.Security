# Quick Start: Apply Enhanced Coverage to cloudhealthoffice

This guide provides step-by-step instructions to apply the enhanced code coverage workflow to the cloudhealthoffice repository.

## Prerequisites

- Access to the cloudhealthoffice repository
- Basic knowledge of GitHub Actions
- Node.js and npm installed locally (for testing)

## Quick Implementation (5 minutes)

### Step 1: Install jest-junit

In your local clone of the cloudhealthoffice repository:

```bash
cd path/to/cloudhealthoffice
npm install --save-dev jest-junit
```

### Step 2: Add Jest Configuration

Add to your `jest.config.js` (or create if it doesn't exist):

```javascript
module.exports = {
  // ... existing configuration ...
  
  // Add JUnit reporter
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: './test-results',
      outputName: 'junit.xml',
    }]
  ],
};
```

If you're using `package.json` for Jest config instead:

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

### Step 3: Update .gitignore

Add to `.gitignore`:

```
# Test results and coverage
coverage/
test-results/
```

### Step 4: Copy the Workflow File

**Option A: Replace existing codecov.yml**

```bash
# From the PrivaseeAI.Security repository
cp .github/workflow-templates/nodejs-coverage-enhanced.yml \
   /path/to/cloudhealthoffice/.github/workflows/codecov.yml
```

**Option B: Create new workflow (safer)**

```bash
# From the PrivaseeAI.Security repository
cp .github/workflow-templates/nodejs-coverage-enhanced.yml \
   /path/to/cloudhealthoffice/.github/workflows/test-coverage.yml
```

Then optionally rename or disable the old `codecov.yml`.

### Step 5: Commit and Push

```bash
cd /path/to/cloudhealthoffice
git checkout -b feature/enhanced-coverage-reporting
git add package.json jest.config.js .gitignore .github/workflows/
git commit -m "Add enhanced code coverage reporting

- Install jest-junit for JUnit XML test results
- Configure Jest for multiple coverage report formats
- Add workflow for HTML coverage artifacts
- Enable PR coverage comments and test result publishing
- Based on PrivaseeAI.Security coverage implementation"

git push origin feature/enhanced-coverage-reporting
```

### Step 6: Create Pull Request

1. Go to the cloudhealthoffice repository on GitHub
2. Create a pull request from `feature/enhanced-coverage-reporting` to `main`
3. Wait for the workflow to run
4. Verify the enhancements:
   - ✅ Test Results check appears
   - ✅ Coverage comment is posted
   - ✅ Artifacts are available for download

## What to Expect

### During the PR

You should see:

1. **Status Check: "Test Results"**
   - Shows: X passed, Y failed, Z skipped
   - Click for detailed breakdown

2. **Comment: Coverage Report**
   - Overall coverage percentage
   - File-by-file changes
   - Links to Codecov

3. **Artifacts Section** (after workflow completes)
   - `coverage-report-html` - Interactive HTML coverage
   - `test-results` - JUnit XML files

### After Merge

The workflow will run on every:
- Push to `main`, `develop`, or `release/*` branches
- Pull request to `main`, `develop`, or `release/*` branches
- Manual trigger (workflow_dispatch)

## Verification Checklist

After the PR workflow runs, verify:

- [ ] Workflow completes successfully
- [ ] Test Results check appears on PR
- [ ] Coverage comment is posted to PR
- [ ] Codecov upload succeeds
- [ ] Coverage HTML artifact is available
- [ ] Test results artifact is available
- [ ] Terminal shows coverage summary
- [ ] No errors in workflow logs

## Rollback (If Needed)

If something goes wrong:

```bash
# Revert the changes
git revert HEAD
git push origin feature/enhanced-coverage-reporting

# Or restore the old workflow
git checkout main -- .github/workflows/codecov.yml
git add .github/workflows/codecov.yml
git commit -m "Restore original codecov workflow"
git push origin feature/enhanced-coverage-reporting
```

## Customization

### Change Node.js Version

Edit the workflow file:

```yaml
- name: Setup Node.js
  uses: actions/setup-node@v4
  with:
    node-version: '22'  # Change from 20 to 22
```

### Adjust Artifact Retention

Edit the workflow file:

```yaml
- name: Upload coverage HTML report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: coverage-report-html
    path: coverage/
    retention-days: 90  # Change from 30 to 90 days
```

### Add Coverage Thresholds

In `jest.config.js`:

```javascript
module.exports = {
  // ... other config ...
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

This will fail the build if coverage drops below 80%.

## Troubleshooting

### Tests fail with "jest-junit not found"

**Solution:**
```bash
npm install --save-dev jest-junit
npm install  # Ensure dependencies are installed
```

### Coverage report not generated

**Solution:**
Ensure your test script includes `--coverage`:
```json
{
  "scripts": {
    "test": "jest --coverage"
  }
}
```

### PR comment not appearing

**Solution:**
- Ensure workflow runs on `pull_request` event
- Check that `pull-requests: write` permission is granted
- Verify lcov.info exists in coverage directory

### Workflow fails on "Publish Test Results"

**Solution:**
- Ensure junit.xml exists in test-results/
- Check jest-junit configuration
- Verify paths in workflow match jest output

## Next Steps

After successfully implementing:

1. **Add Coverage Badge** to README.md:
   ```markdown
   [![Coverage](https://codecov.io/gh/aurelianware/cloudhealthoffice/branch/main/graph/badge.svg)](https://codecov.io/gh/aurelianware/cloudhealthoffice)
   ```

2. **Set Branch Protection Rules**:
   - Require "Test Results" check to pass
   - Require minimum coverage threshold

3. **Educate Team**:
   - Share the coverage reports location
   - Explain how to download HTML artifacts
   - Show how coverage comments work

## Support

For detailed information, see:
- [CLOUDHEALTHOFFICE_COVERAGE_GUIDE.md](./CLOUDHEALTHOFFICE_COVERAGE_GUIDE.md) - Comprehensive guide
- [nodejs-coverage-enhanced.yml](./nodejs-coverage-enhanced.yml) - Workflow template
- [PrivaseeAI.Security test.yml](../workflows/test.yml) - Reference Python implementation

---

**Estimated Time:** 5-10 minutes  
**Difficulty:** Easy  
**Impact:** High - Better visibility into test coverage and quality
