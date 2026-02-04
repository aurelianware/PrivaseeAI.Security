# Workflow Templates

This directory contains reusable GitHub Actions workflow templates that can be applied to other repositories.

## Available Templates

### 1. Node.js/TypeScript Enhanced Coverage Template

**File:** `nodejs-coverage-enhanced.yml`  
**Purpose:** Comprehensive code coverage and test reporting for Node.js/TypeScript projects  
**Guide:** [`CLOUDHEALTHOFFICE_COVERAGE_GUIDE.md`](./CLOUDHEALTHOFFICE_COVERAGE_GUIDE.md)

#### Features:
- ✅ Multiple coverage report formats (lcov, HTML, JSON, text)
- ✅ HTML coverage reports as downloadable artifacts (30-day retention)
- ✅ Test results published as PR status checks
- ✅ Automated coverage comments on pull requests
- ✅ JUnit XML test results for external tool integration
- ✅ Codecov integration for historical tracking
- ✅ Terminal coverage summary in workflow logs

#### Intended For:
- TypeScript/JavaScript projects using Jest
- Node.js applications requiring comprehensive test coverage
- Teams wanting detailed coverage feedback on PRs
- Projects already using Codecov

#### Example Use Case:
This template was created to enhance the code coverage reporting in the [cloudhealthoffice](https://github.com/aurelianware/cloudhealthoffice) repository, based on the comprehensive coverage implementation in this repository (PrivaseeAI.Security).

## How to Use These Templates

### Step 1: Review the Guide
Each template has an associated guide (e.g., `CLOUDHEALTHOFFICE_COVERAGE_GUIDE.md`) that explains:
- What the template does
- How to implement it
- Required dependencies
- Configuration steps
- Troubleshooting

### Step 2: Adapt to Your Project
1. Copy the template workflow file
2. Modify paths, branch names, and settings for your project
3. Install any required dependencies
4. Configure your project's test framework as needed

### Step 3: Test Before Deploying
1. Create a test branch in your repository
2. Add the workflow file
3. Open a pull request to verify everything works
4. Check for:
   - Successful workflow execution
   - Proper artifact upload
   - PR comments (if applicable)
   - Status checks appearing correctly

## Template Comparison

| Template | Language | Test Framework | Coverage Tool | PR Comments | Artifacts |
|----------|----------|----------------|---------------|-------------|-----------|
| nodejs-coverage-enhanced.yml | TypeScript/JavaScript | Jest | Jest + Codecov | ✅ | ✅ |

## Contributing Templates

If you create a useful workflow template for other projects, consider adding it here:

1. Add the `.yml` workflow file
2. Create a comprehensive guide (`.md` file)
3. Update this README with template details
4. Test the template in at least one repository

## Related Workflows

For reference implementations, see the workflows in use in this repository:

- **`.github/workflows/test.yml`** - Python testing with pytest and comprehensive coverage
- **`.github/workflows/code-quality.yml`** - Python code quality checks
- **`.github/workflows/pages.yml`** - GitHub Pages deployment

---

**Maintained by:** PrivaseeAI.Security team  
**Last Updated:** 2026-02-04
