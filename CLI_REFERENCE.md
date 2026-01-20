# CLI Help Reference

## Full Help Output
```
usage: main.py [-h] [--start YYYY-MM-DD] [--end YYYY-MM-DD]
               [--namespace NAME] [--cost-center NAME]
               [--format {csv,json,both}] [--no-metadata] [--validate]
               [--dry-run] [--log {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

F5 XC Billing Report Generator

options:
  -h, --help            show this help message and exit

time window:
  --start YYYY-MM-DD, --start-date YYYY-MM-DD
                        Start date (YYYY-MM-DD). Default: 30 days ago
  --end YYYY-MM-DD, --end-date YYYY-MM-DD
                        End date (YYYY-MM-DD). Default: today

filtering:
  --namespace NAME      Filter to specific namespace (comma-separated
                        for multiple)
  --cost-center NAME    Filter to specific cost center (comma-separated
                        for multiple)

output:
  --format {csv,json,both}
                        Output format (default: both)
  --no-metadata         Omit metadata headers in CSV files

mode:
  --validate            Run pre-flight validation checks only (no
                        billing calculation)
  --dry-run             Calculate billing but do not write output files
  --log {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level (default: INFO)

Examples:
  python main.py                           # Last 30 days (default)
  python main.py --start 2025-11-01 --end 2025-11-30  # Specific date range
  python main.py --namespace prod-acme    # Only prod-acme namespace
  python main.py --cost-center "Team A"   # Only Team A cost center
  python main.py --format csv              # CSV only (no JSON)
  python main.py --validate                # Pre-flight checks only
  python main.py --dry-run                 # Show what would be calculated (no files)
  python main.py --log DEBUG               # Detailed diagnostics
```

## Argument Groups

### Time Window Arguments
Specify the billing period. If neither is provided, defaults to the last 30 days.

| Argument | Format | Default | Example |
|----------|--------|---------|---------|
| `--start` / `--start-date` | YYYY-MM-DD | 30 days ago | `--start 2025-11-01` |
| `--end` / `--end-date` | YYYY-MM-DD | today (UTC midnight) | `--end 2025-11-30` |

**Date Handling:**
- All dates are interpreted at UTC midnight
- Both start and end dates are inclusive
- If you provide only `--start`, the end date is today
- If you provide only `--end`, the start date is 30 days before
- If you provide both, those exact dates are used

### Filtering Arguments
Restrict the output to specific namespaces or cost centers.

| Argument | Format | Effect |
|----------|--------|--------|
| `--namespace` | Comma-separated string | Filter rows to matching namespaces |
| `--cost-center` | Comma-separated string | Filter rows to matching cost centers |

**Filtering Notes:**
- All calculations still run (filtering happens at the end)
- Multiple values should be comma-separated: `"ns1, ns2, ns3"`
- Whitespace is automatically trimmed
- Multiple filters are AND'd together
- Filtering happens **after** cost center aggregation

### Output Arguments
Control what gets written to disk.

| Argument | Values | Default | Effect |
|----------|--------|---------|--------|
| `--format` | csv, json, both | both | Which file formats to write |
| `--no-metadata` | flag | (not set) | Omit comment headers in CSV |

**Output Notes:**
- With `--format csv`: Only CSV files written (no JSON)
- With `--format json`: Only JSON files written (no CSV)
- With `--format both`: Both CSV and JSON files written
- Metadata headers are comment lines starting with `#`
- Metadata includes generation time, period, and row counts

### Mode Arguments
Control how the tool behaves.

| Argument | Effect |
|----------|--------|
| `--validate` | Run configuration checks, exit without calculating |
| `--dry-run` | Calculate everything but don't write files |
| `--log LEVEL` | Set logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL) |

**Mode Notes:**
- `--validate` exits early with exit code 0 if all checks pass
- `--dry-run` shows summary output (namespaces, total cost) but creates no files
- Logging levels follow Python's standard logging levels
- All three mode arguments can be combined (though `--validate` exits early)

## Common Command Patterns

### One-off Report
```bash
python main.py --start 2025-10-01 --end 2025-10-31
```
Generate a report for October 2025

### Verify Setup Before Running
```bash
python main.py --validate
```
Check API connectivity, auth, and folder permissions before running a full report

### Check Calculations Without Writing Files
```bash
python main.py --start 2025-11-01 --dry-run
```
See what would be calculated without creating files

### Team Chargeback Report
```bash
python main.py --namespace "prod-team-a, staging-team-a, dev-team-a" --format csv
```
Show all namespaces for Team A in CSV format

### Finance Department Report
```bash
python main.py --cost-center "Finance, Accounting" --format csv --no-metadata
```
Show Finance and Accounting costs in clean CSV (no metadata headers)

### Troubleshoot Data Issues
```bash
python main.py --namespace problem-ns --log DEBUG --dry-run
```
Get detailed diagnostics for a specific namespace without writing files

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success or validation passed |
| 1 | Error (missing config, API failure, validation failed, date parse error, file I/O error) |

## Integration Examples

### Shell Script (Monthly Report)
```bash
#!/bin/bash
MONTH=${1:-$(date +%Y-%m)}
START="${MONTH}-01"
END="${MONTH}-31"
python main.py --start "$START" --end "$END" --format csv
```

### Scheduled Job (Daily via Cron)
```bash
0 2 * * * cd /path/to/billing && python main.py --log WARNING >> billing.log 2>&1
```
Run daily at 2 AM UTC, log warnings only

### GitHub Actions
```yaml
- name: Validate Config
  run: python main.py --validate

- name: Generate Report
  run: python main.py --start 2025-11-01 --end 2025-11-30
```

## Tips & Tricks

1. **Test Before Running**: Always use `--dry-run` to preview calculations
2. **Validate Setup**: Use `--validate` before important reports
3. **Debug Issues**: Add `--log DEBUG` to see detailed information
4. **Clean Output**: Use `--format csv --no-metadata` for data imports
5. **Multiple Reports**: Combine with shell loops for batch processing

## See Also

- `CLI_EXAMPLES.md`: Detailed examples with use cases
- `CLI_ENHANCEMENT.md`: Summary of what was added
- `.github/copilot-instructions.md`: Architecture and patterns
