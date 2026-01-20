# F5 XC Billing Report Generator

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Proof of Concept](https://img.shields.io/badge/Type-Proof%20of%20Concept-informational.svg)]()

A sophisticated billing report generator for F5 Distributed Cloud (XC) that demonstrates how to use the XC API to calculate per-namespace and per-cost-center costs based on HTTP requests, WAF metrics, and feature inventory.

## ⚠️ Disclaimer

**This is a proof-of-concept project provided as-is and is NOT officially supported by F5 Networks.** This project demonstrates how the F5 XC APIs can be used for billing and cost allocation use cases. It is not part of the official F5 XC product. For issues with the official F5 XC service, please contact F5 Support.

## Features

- **Dynamic Billing Calculation**
  - HTTP request metrics from Graph Service (per-million chunk billing with ceiling rounding)
  - WAF-restricted request tracking (public LBs with WAF enabled)
  - Inventory-based feature counts (public load balancers, API Discovery, Bot Protection)
  - Flexible per-unit flat fees for features

- **Advanced Reporting**
  - Per-namespace detailed breakdown
  - Per-cost-center aggregated summaries
  - CSV and JSON output formats
  - Automatic metadata headers (timestamp, period, counts)

- **Flexible CLI**
  - Custom date ranges (`--start`, `--end`)
  - Namespace filtering (`--namespace`)
  - Cost center filtering (`--cost-center`)
  - Output format control (`--format`, `--no-metadata`)
  - PDF report generation (`--pdf`)
  - Pre-flight validation (`--validate`)
  - Dry-run mode (`--dry-run`)
  - Debug logging (`--log DEBUG`)

## Prerequisites

- Python 3.11 or higher
- F5 Distributed Cloud tenant with API access
- API credentials (API base URL and token)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/yourusername/xc-ns-billing-py.git
cd xc-ns-billing-py
pip install -r requirements.txt
```

### 2. Configure Credentials

Create a `.env` file with your F5 XC credentials:

```bash
F5XC_API_BASE=https://f5-emea-ent.console.ves.volterra.io/api
F5XC_API_TOKEN=your-api-token-here

# Optional: Pricing configuration (in USD)
WAF_REQUEST_PRICE_PER_MILLION=10.0
PRICE_PER_PUBLIC_LB=100.0
PRICE_PER_API_DISCOVERY_LB=200.0
PRICE_PER_BOT_PROTECTION_LB=150.0

# Optional: Output folder (default: ./billing_reports)
F5XC_OUTPUT_FOLDER=./billing_reports

### 3. Validate Setup

```bash
python main.py --validate
```

### 4. Generate Your First Report

```bash
# Last 30 days (default)
python main.py

# Specific date range
python main.py --start 2025-11-01 --end 2025-11-30

# Filter to specific namespace
python main.py --namespace prod-acme

# Preview before writing files
python main.py --dry-run --log WARNING
```

## Usage Examples

### Generate Monthly Report
```bash
python main.py --start 2025-11-01 --end 2025-11-30 --format csv --log WARNING
```

### Filter by Cost Center
```bash
python main.py --cost-center "Engineering, Finance" --format csv --no-metadata
```

### Troubleshoot Data Issues
```bash
python main.py --namespace problem-ns --log DEBUG --dry-run
```

### Batch Process Multiple Teams
```bash
for team in "Engineering" "Operations" "Finance"; do
  python main.py --cost-center "$team" --format csv
done
```

## Documentation

- **[CLI_EXAMPLES.md](CLI_EXAMPLES.md)** - Practical examples with real-world use cases
- **[CLI_REFERENCE.md](CLI_REFERENCE.md)** - Complete command reference with argument details

## Output Files

Generated to the configured output folder (default: `./billing_reports/`):

```
billing_namespace_combined_2025-11-01_to_2025-11-30.csv
billing_namespace_combined_2025-11-01_to_2025-11-30.json
billing_cost_centers_2025-11-01_to_2025-11-30.csv
billing_cost_centers_2025-11-01_to_2025-11-30.json
billing_cost_centers_2025-11-01_to_2025-11-30.pdf  # (with --pdf flag)
```

### CSV Format with Metadata
```csv
# Generated: 2025-12-10T15:30:45.123456+00:00
# Period Start: 2025-11-10T00:00:00+00:00
# Period End: 2025-12-10T00:00:00+00:00
# Namespace Count: 45
period_start,period_end,namespace,cost_center,http_requests,request_cost,http_waf_requests,...
2025-11-10T00:00:00+00:00,2025-12-10T00:00:00+00:00,prod-acme,Engineering,1500000,15.00,450000,45.00,...
```

### PDF Report Generation

Generate professional PDF reports with embedded cost charts using the `--pdf` flag:

```bash
python main.py --pdf
python main.py --start 2025-11-01 --end 2025-11-30 --pdf
python main.py --cost-center "Engineering" --pdf
```

**PDF Contents:**
- Bar chart: Total cost by cost center
- Pie chart: Cost distribution (percentage share)
- Stacked bar chart: Cost breakdown by type (HTTP, WAF, LB features, etc.)
- Summary table: All cost centers with totals

**Technical Details:**
- Pure Python implementation using matplotlib and ReportLab
- No browser or external dependencies required
- Fully portable (Windows, macOS, Linux)
- Charts generated as high-resolution PNG (150 DPI)
- Professional styling with multi-page layout

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `F5XC_API_BASE` | required | F5 XC API base URL (https://...) |
| `F5XC_API_TOKEN` | required | API authentication token |
| `REQUEST_PRICE_PER_MILLION` | 0.0 | HTTP request pricing (USD) |
| `WAF_REQUEST_PRICE_PER_MILLION` | 10.0 | WAF request pricing (USD) |
| `PRICE_PER_PUBLIC_LB` | 100.0 | Public load balancer pricing (USD) |
| `PRICE_PER_API_DISCOVERY_LB` | 200.0 | API Discovery pricing (USD) |
| `PRICE_PER_BOT_PROTECTION_LB` | 150.0 | Bot Protection pricing (USD) |
| `F5XC_OUTPUT_FOLDER` | ./billing_reports | Output directory |
| `F5XC_VHOST_PREFIX` | ves-io-http-loadbalancer- | Vhost name prefix for WAF matching |
| `F5XC_VHOST_TYPE` | HTTP_LOAD_BALANCER | Graph Service vhost type filter |
| `F5XC_MAX_RETRIES` | 3 | API request retry attempts |
| `F5XC_RETRY_BACKOFF` | 2 | Retry backoff in seconds |

### Cost Center Mapping

Namespaces map to cost centers via tags in the namespace description using a configurable format:

```
"Production namespace for Acme. {{cost_center: Acme Corp}}"
                                      ↓
Namespace: prod-acme  →  Cost Center: Acme Corp
```

**Tag format:** `{{key:value}}` where:
- `key`: Configurable via `F5XC_COST_CENTER_TAG_KEY` env variable (default: `cost_center`)
- `value`: The cost center name
- Container: Double curly braces `{{}}` (required)
- Case-insensitive matching

**Examples:**
```
# Default key "cost_center"
{{cost_center: Acme Corp}}
{{ cost_center : Finance Team }}

# Custom key via environment variable
{{billing_team: Engineering}}
{{department: Operations}}
```

**Configuration:**
```bash
# Use default "cost_center" key
# No configuration needed, or set explicitly:
F5XC_COST_CENTER_TAG_KEY=cost_center

# Use custom key
F5XC_COST_CENTER_TAG_KEY=billing_team
# Then use {{billing_team: Team Name}} in descriptions
```

## CLI Reference

```
usage: main.py [-h] [--start YYYY-MM-DD] [--end YYYY-MM-DD]
               [--namespace NAME] [--cost-center NAME]
               [--format {csv,json,both}] [--no-metadata] 
               [--validate] [--dry-run] 
               [--log {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

options:
  --start YYYY-MM-DD, --start-date
                        Start date (default: 30 days ago)
  --end YYYY-MM-DD, --end-date
                        End date (default: today)
  --namespace NAME      Filter to namespace(s) [comma-separated]
  --cost-center NAME    Filter to cost center(s) [comma-separated]
  --format CHOICE       Output format: csv, json, both [default: both]
  --no-metadata         Omit CSV metadata headers
  --validate            Pre-flight checks only (no billing)
  --dry-run             Calculate but don't write files
  --log LEVEL           Logging level [default: INFO]
```

## Debugging

### Pre-flight Validation
```bash
python main.py --validate
```
Checks:
- API connectivity and authentication
- Namespace accessibility
- Output folder permissions

### Dry Run Mode
```bash
python main.py --dry-run
```
- Calculates everything
- Shows summary (namespace count, total cost)
- Doesn't write files

### Debug Logging
```bash
python main.py --log DEBUG
```
Shows:
- Cache hits/misses
- Sample API responses
- Namespace mappings
- Filtered counts
- Detailed parsing information

## Using as Reference or Fork

This project is intended as a reference implementation and starting point. Feel free to:

- Fork the repository and customize for your needs
- Use individual components as reference code
- Adapt the billing model to your requirements
- Extend with additional billable sources
- Modify for other F5 XC use cases

Since this is not actively maintained, forking is the recommended way to use this code.

## Common Workflows

### GitHub Actions (Monthly Report)
```yaml
name: Generate Monthly Report
on:
  schedule:
    - cron: '0 2 1 * *'  # First day of month at 2 AM UTC

jobs:
  billing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python main.py --validate
      - run: python main.py --start ${{ env.MONTH_START }} --end ${{ env.MONTH_END }}
      - uses: actions/upload-artifact@v3
        with:
          name: billing-reports
          path: billing_reports/
```

### Cron Job (Daily Billing)
```bash
0 2 * * * cd /path/to/billing && python main.py --log WARNING >> billing.log 2>&1
```

### Shell Script (Multi-Team Report)
```bash
#!/bin/bash
for team in "Engineering" "Operations" "Finance"; do
  python main.py \
    --cost-center "$team" \
    --format csv \
    --log WARNING
done
```

## Project Status

Project status: Proof of concept. This repository is community-maintained and provided as-is. If you want additional stability or features, please consider contributing or forking the project.

## Security

- API credentials stored in `.env` (not committed to git)
- `.env` should be in `.gitignore`
- All API calls use HTTPS
- No credentials logged even in DEBUG mode
- Validate configuration before first use

**Example `.gitignore`:**
```
.env
.env.local
billing_reports/
__pycache__/
*.pyc
.DS_Store
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Important: Not Affiliated with F5

This tool is provided by the community and is **NOT** an official F5 Networks product. It is not supported, maintained, or endorsed by F5 Networks, Inc. The author(s) assume no responsibility for any issues, data loss, or damages caused by the use of this tool. Users are responsible for:

- Validating billing calculations independently
- Testing in a non-production environment first
- Maintaining their own backups and records
- Contacting F5 Support for official API issues

Use this tool at your own risk. Always verify billing reports are accurate before taking action on them.


---

**Last Updated:** December 10, 2025  
**Python Version:** 3.11+  
**Status:** ⚡️ Proof-of-concept
