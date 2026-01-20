# CLI Examples - Enhanced Command-Line Interface

This document shows practical examples of the new command-line interface features added to the billing report generator.

## Basic Usage

### Default: Last 30 Days
```bash
python main.py
```
- Generates billing reports for the last 30 days
- Outputs both CSV and JSON files with metadata headers
- Logs at INFO level

## Date Range Options

### Specific Date Range (Start and End)
```bash
python main.py --start 2025-11-01 --end 2025-11-30
```
- Generates report for November 1-30, 2025
- Both start and end dates are converted to UTC midnight

### Start Date Only
```bash
python main.py --start 2025-11-01
```
- Generates report from Nov 1 to today (UTC midnight)

### End Date Only
```bash
python main.py --end 2025-11-30
```
- Generates report from 30 days before Nov 30 to Nov 30

## Filtering Options

### Filter by Single Namespace
```bash
python main.py --namespace prod-acme
```
- Only includes the `prod-acme` namespace in the output
- Cost center totals will only reflect this namespace

### Filter by Multiple Namespaces
```bash
python main.py --namespace "prod-acme, staging-acme, dev-acme"
```
- Includes all three namespaces (whitespace-trimmed automatically)
- Useful for reporting on a team or business unit

### Filter by Single Cost Center
```bash
python main.py --cost-center "Team A"
```
- Only outputs the "Team A" cost center row
- Useful for chargeback reports to specific departments

### Filter by Multiple Cost Centers
```bash
python main.py --cost-center "Team A, Team B, Finance"
```
- Shows totals for all three cost centers

### Combined Filtering
```bash
python main.py --start 2025-11-01 --end 2025-11-30 --namespace "prod-acme" --cost-center "Engineering"
```
- Filters both namespace and cost center for targeted reporting

## Output Format Options

### CSV Only (No JSON)
```bash
python main.py --format csv
```
- Writes `billing_namespace_combined_*.csv` and `billing_cost_centers_*.csv`
- Skips JSON files
- Useful for Excel/Sheets analysis

### JSON Only (No CSV)
```bash
python main.py --format json
```
- Writes `billing_namespace_combined_*.json` and `billing_cost_centers_*.json`
- Skips CSV files
- Useful for programmatic parsing

### Both Formats (Default)
```bash
python main.py --format both
```
- Generates both CSV and JSON files (default behavior)

### Omit Metadata Headers
```bash
python main.py --no-metadata
```
- Writes CSV files without comment lines at the top
- Metadata would normally look like:
  ```
  # Generated: 2025-12-10T15:30:45.123456+00:00
  # Period Start: 2025-11-10T00:00:00+00:00
  # Period End: 2025-12-10T00:00:00+00:00
  ```

## Validation & Testing Modes

### Validate Configuration Only
```bash
python main.py --validate
```
- Checks:
  - API base URL is configured and reachable
  - API authentication is valid
  - Output folder exists and is writable
  - Does NOT run any billing calculations
- Returns exit code 0 if all checks pass
- Useful for:
  - Pre-deployment verification
  - Troubleshooting configuration issues
  - Automated health checks (cron jobs, monitoring)

### Dry Run (Calculate but Don't Write Files)
```bash
python main.py --dry-run
```
- Calculates all billing metrics
- Displays summary: namespaces, total cost
- Does NOT write CSV/JSON files
- Useful for:
  - Testing different date ranges before committing
  - Verifying calculations without creating files
  - Preview mode for manual review

## Logging Options

### Debug Mode (Detailed Diagnostics)
```bash
python main.py --log DEBUG
```
- Shows:
  - Cache hits/misses for API calls
  - Sample API responses
  - Namespace mappings
  - Filtered record counts
  - Individual billable source outputs
- Useful for:
  - Troubleshooting missing data
  - Understanding calculation logic
  - Verifying filters are working

### Warning Level (Minimal Logging)
```bash
python main.py --log WARNING
```
- Only shows warnings and errors
- Useful for:
  - Quiet production runs
  - Log file analysis (less noise)

### Silent with Errors
```bash
python main.py --log ERROR
```
- Only shows errors (nothing on success)
- Useful for:
  - Automated jobs where silence = success

## Complex Examples

### Monthly Finance Report
```bash
python main.py \
  --start 2025-11-01 \
  --end 2025-11-30 \
  --cost-center "Finance, HR, Engineering" \
  --format csv \
  --no-metadata
```
- Report for November across three departments
- CSV only for Excel import
- No metadata for clean data import

### Real-Time Validation Before Production Run
```bash
python main.py --validate && \
python main.py --start 2025-11-01 --end 2025-11-30 --dry-run && \
python main.py --start 2025-11-01 --end 2025-11-30
```
1. Validates configuration
2. Dry-runs the billing (checks math)
3. Runs actual billing and writes files

### Troubleshoot Missing Namespace Data
```bash
python main.py \
  --namespace prod-acme \
  --log DEBUG \
  --dry-run
```
- Focuses on one namespace
- Shows detailed debug output
- Doesn't write files
- Helps identify why data is missing

### Team-Based Chargeback Report
```bash
# For each team, generate their cost center report
for team in "Engineering" "Operations" "Finance"; do
  python main.py \
    --start 2025-11-01 \
    --end 2025-11-30 \
    --cost-center "$team" \
    --format csv \
    --log WARNING
done
```
- Creates individual CSVs for each team
- Minimal logging
- Suitable for batch processing

## Exit Codes

- `0`: Success (or validation passed)
- `1`: Configuration error (missing API credentials, etc.)
- `1`: Validation failed
- `2`: Date parsing error
- `1`: File I/O error

## Integration Examples

### GitHub Actions CI/CD
```yaml
- name: Validate Billing Config
  run: python main.py --validate

- name: Generate Monthly Report
  run: python main.py --start 2025-11-01 --end 2025-11-30 --format csv
```

### Cron Job (Daily Billing)
```bash
# In crontab: Run every day at midnight UTC
0 0 * * * cd /path/to/billing && python main.py --log ERROR >> billing.log 2>&1
```

### Monitor Health with Cron
```bash
# Weekly validation check
0 0 * * 0 cd /path/to/billing && python main.py --validate --log ERROR
```

## Notes

- All dates are interpreted in UTC
- Filtering is applied **after** calculation (calculations still run for all namespaces)
- Multiple filters are AND'd together (namespace=X AND cost_center=Y)
- Metadata headers in CSV are comments (prefixed with `#`) and won't interfere with parsing
- Use `--dry-run` liberally for testing without creating artifacts
