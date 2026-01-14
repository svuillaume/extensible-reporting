#!/bin/bash

set -euo pipefail

# Load configuration
source .env

# Input files
ID_HIGH_PRIV="${OUTPUT_DIR:-.}/Identities_with_excessive_privileges.json"
ID_ROOT="${OUTPUT_DIR:-.}/Root_Identities.json"
ID_ROOT_AND_HIGH="${OUTPUT_DIR:-.}/Root_Identities_with_excessive_privileges.json"

# Output file
OUTPUT_HTML="${OUTPUT_DIR:-.}/forticnapp_identity_entitlement_report.html"

echo "Generating HTML report..."

# Count records
HIGH_PRIV_COUNT=$(jq -s 'length' "$ID_HIGH_PRIV" 2>/dev/null || echo "0")
ROOT_COUNT=$(jq -s 'length' "$ID_ROOT" 2>/dev/null || echo "0")
ROOT_AND_HIGH_COUNT=$(jq -s 'length' "$ID_ROOT_AND_HIGH" 2>/dev/null || echo "0")

# Get current timestamp
REPORT_TIME=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Format dates for display
START_DATE_DISPLAY=$(echo "$START_DATE" | cut -d'T' -f1)
END_DATE_DISPLAY=$(echo "$END_DATE" | cut -d'T' -f1)

# Generate table rows for critical identities
CRITICAL_ROWS=""
if [ "$ROOT_AND_HIGH_COUNT" -gt 0 ]; then
    CRITICAL_ROWS=$(jq -rs '.[] |
        "<tr>" +
        "<td><code style=\"font-size: 0.85em;\">" + .PRINCIPAL_ID + "</code></td>" +
        "<td>" + .NAME + "</td>" +
        "<td data-provider=\"" + .PROVIDER_TYPE + "\"><span class=\"provider-badge " + .PROVIDER_TYPE + "\">" + .PROVIDER_TYPE + "</span></td>" +
        "<td><small>" + .DOMAIN_ID + "</small></td>" +
        "<td><strong>" + (.ENTITLEMENT_COUNTS.entitlements_unused_count | tostring) + "</strong> / " + (.ENTITLEMENT_COUNTS.entitlements_total_count | tostring) + " (" + (.ENTITLEMENT_COUNTS.entitlements_unused_percentage | tostring) + "%)</td>" +
        "<td><span class=\"risk-indicator " + .METRICS.risk_severity + "\">" + .METRICS.risk_severity + "</span></td>" +
        "<td style=\"font-size: 0.75rem; line-height: 1.4;\">" + (.METRICS.risks | map("<span style=\"display: inline-block; margin-right: 4px; white-space: nowrap;\">" + . + "</span>") | join(" ")) + "</td>" +
        "</tr>"
    ' "$ID_ROOT_AND_HIGH")
else
    CRITICAL_ROWS='<tr><td colspan="7" class="empty-state">
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        <div>No critical risk identities found</div>
    </td></tr>'
fi

# Get JSON data for JavaScript (slurp into array)
CRITICAL_JSON=$(jq -cs '.' "$ID_ROOT_AND_HIGH" 2>/dev/null || echo "[]")

# Generate HTML with direct variable substitution
cat > "$OUTPUT_HTML" <<HTML_START
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiCNAPP Cloud Identity Entitlement Management Report</title>
    <link rel="stylesheet" href="https://fonts.xz.style/serve/inter.css">
    <style>
        @media print {
            @page {
                size: A4 landscape;
                margin: 0.8cm;
            }

            body {
                width: 100%;
                max-width: none;
                padding: 0;
                font-size: 11pt;
            }

            .container {
                margin: 0;
            }

            .header {
                padding: 1rem;
                margin-bottom: 1rem;
            }

            .header-logo {
                width: 50px;
                height: 50px;
            }

            .header-text h1 {
                font-size: 1.3rem;
            }

            .report-title {
                padding: 1.5rem;
                margin-bottom: 1rem;
            }

            .report-title .meta {
                font-size: 0.8rem;
            }

            .stats-grid {
                margin: 1rem 0;
            }

            .stat-card {
                padding: 1rem;
            }

            .stat-card .value {
                font-size: 2rem;
            }

            .header, .report-title, .stats-grid, .data-section {
                break-inside: avoid;
                page-break-inside: avoid;
            }

            .data-section {
                padding: 1rem;
                margin-bottom: 1rem;
            }

            .data-section h2 {
                font-size: 1.3rem;
                margin-bottom: 1rem;
            }

            table {
                page-break-inside: auto;
                font-size: 9pt;
            }

            thead th {
                font-size: 8pt;
                padding: 0.5rem 0.5rem;
            }

            tr {
                page-break-inside: avoid;
                page-break-after: auto;
            }

            thead {
                display: table-header-group;
            }

            .filter-bar {
                display: none !important;
            }

            .no-print {
                display: none !important;
            }

            .footer {
                margin-top: 1rem;
                padding: 0.5rem;
                font-size: 8pt;
            }
        }

        :root {
            --color-critical: #DC2626;
            --color-critical-bg: #FEE2E2;
            --color-high: #EA580C;
            --color-high-bg: #FFEDD5;
            --color-medium: #CA8A04;
            --color-medium-bg: #FEF3C7;
            --color-low: #2563EB;
            --color-low-bg: #DBEAFE;
            --color-success: #16A34A;
            --color-success-bg: #DCFCE7;
            --color-primary: #307FE2;
            --color-primary-dark: #1E5BB8;
            --color-text: #1F2937;
            --color-text-light: #6B7280;
            --color-border: #E5E7EB;
            --color-bg-light: #F9FAFB;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            width: 95%;
            max-width: 1400px;
            margin: 0 auto;
            color: var(--color-text);
            background: #FFFFFF;
            line-height: 1.6;
            font-size: 14px;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem 2rem;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            border-bottom: 3px solid var(--color-primary);
            margin-bottom: 2rem;
            border-radius: 8px;
        }

        .header-top {
            display: flex;
            align-items: center;
            gap: 20px;
            flex: 1;
        }

        .header-logo {
            width: 70px;
            height: 70px;
            flex-shrink: 0;
        }

        .header-text h1 {
            font-size: 1.75rem;
            color: var(--color-text);
            margin-bottom: 0.25rem;
            line-height: 1.3;
            font-weight: 700;
        }

        .header-text .subtitle {
            color: var(--color-text-light);
            font-size: 1rem;
        }

        .report-title {
            background: linear-gradient(135deg, var(--color-primary) 0%, var(--color-primary-dark) 100%);
            color: white;
            padding: 2.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }

        .report-title .meta {
            margin-top: 1.5rem;
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .report-title .meta-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .report-title .meta-item strong {
            font-weight: 600;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid var(--color-border);
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .stat-card.critical {
            border-top: 4px solid var(--color-critical);
        }

        .stat-card.high {
            border-top: 4px solid var(--color-high);
        }

        .stat-card.warning {
            border-top: 4px solid var(--color-medium);
        }

        .stat-card.info {
            border-top: 4px solid var(--color-primary);
        }

        .stat-card .label {
            font-size: 0.85rem;
            color: var(--color-text-light);
            line-height: 1.3;
            margin-bottom: 0.5rem;
        }

        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.5rem;
        }

        .stat-card.critical .value { color: var(--color-critical); }
        .stat-card.high .value { color: var(--color-high); }
        .stat-card.warning .value { color: var(--color-medium); }
        .stat-card.info .value { color: var(--color-primary); }

        .stat-card .description {
            font-size: 0.85rem;
            color: var(--color-text-light);
            line-height: 1.3;
        }

        .data-section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--color-border);
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .data-section h2 {
            font-size: 1.75rem;
            color: var(--color-text);
            border-bottom: 2px solid var(--color-primary);
            padding-bottom: 0.75rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 700;
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.critical {
            background: var(--color-critical-bg);
            color: var(--color-critical);
        }

        .badge.high {
            background: var(--color-high-bg);
            color: var(--color-high);
        }

        .badge.medium {
            background: var(--color-medium-bg);
            color: var(--color-medium);
        }

        .badge.low {
            background: var(--color-low-bg);
            color: var(--color-low);
        }

        .table-container {
            overflow-x: auto;
            margin-top: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1.5rem 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            font-size: 0.875rem;
        }

        thead th {
            background: var(--color-primary);
            color: white;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 1rem;
            text-align: left;
        }

        tbody tr {
            border-bottom: 1px solid var(--color-border);
        }

        tbody tr:nth-child(even) {
            background: var(--color-bg-light);
        }

        tbody tr:hover {
            background: #EBF5FF;
        }

        td {
            padding: 0.875rem 1rem;
            color: var(--color-text);
            word-wrap: break-word;
            overflow-wrap: break-word;
        }

        td:nth-child(1) { max-width: 180px; }  /* Principal ID */
        td:nth-child(2) { max-width: 150px; }  /* Name */
        td:nth-child(3) { max-width: 80px; }   /* Provider */
        td:nth-child(4) { max-width: 150px; }  /* Domain ID */
        td:nth-child(5) { max-width: 120px; }  /* Unused Entitlements */
        td:nth-child(6) { max-width: 100px; }  /* Risk Severity */
        td:nth-child(7) { min-width: 200px; }  /* Risk - more space for list */

        @media print {
            td {
                font-size: 0.75rem;
                padding: 0.5rem 0.75rem;
            }

            td:nth-child(7) {
                font-size: 0.7rem;
                line-height: 1.3;
            }
        }

        .risk-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .risk-indicator.CRITICAL {
            background: var(--color-critical-bg);
            color: var(--color-critical);
        }

        .risk-indicator.HIGH {
            background: var(--color-high-bg);
            color: var(--color-high);
        }

        .risk-indicator.MEDIUM {
            background: var(--color-medium-bg);
            color: var(--color-medium);
        }

        .risk-indicator.LOW {
            background: var(--color-low-bg);
            color: var(--color-low);
        }

        .provider-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .provider-badge.AWS {
            background: #fff5e1;
            color: #ff9900;
        }

        .provider-badge.AZURE {
            background: #e1f5ff;
            color: #0078d4;
        }

        .provider-badge.GCP {
            background: #e8f5e9;
            color: #34a853;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #718096;
        }

        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        .filter-bar {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.5rem 1rem;
            border: 2px solid var(--color-border);
            background: white;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--color-text);
            transition: all 0.2s;
        }

        .filter-btn:hover {
            border-color: var(--color-primary);
            color: var(--color-primary);
        }

        .filter-btn.active {
            background: var(--color-primary);
            color: white;
            border-color: var(--color-primary);
        }

        .search-box {
            flex: 1;
            min-width: 250px;
            padding: 0.5rem 1rem;
            border: 2px solid var(--color-border);
            border-radius: 6px;
            font-size: 0.875rem;
            transition: border-color 0.2s;
        }

        .search-box:focus {
            outline: none;
            border-color: var(--color-primary);
        }

        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--color-text-light);
            font-size: 0.875rem;
            border-top: 1px solid var(--color-border);
            margin-top: 2rem;
        }

        .print-button {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--color-primary);
            color: white;
            border: none;
            border-radius: 50px;
            padding: 1rem 2rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(48, 127, 226, 0.3);
            transition: all 0.2s;
            z-index: 1000;
        }

        .print-button:hover {
            background: var(--color-primary-dark);
            box-shadow: 0 6px 20px rgba(48, 127, 226, 0.4);
            transform: translateY(-2px);
        }

        @media print {
            .print-button {
                display: none !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-top">
                <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAMAAAAJbSJIAAAA8FBMVEX///8wf+JGRkZZmegmZrPb5/lEREQVduAvgec8PDwvgukzMzMsfeJJjOVHQjghZLJNk+f0+P1BdLk3NzdHQzw6OjpGRUJHQjZLfL2mxfEvLy/i4uJKgslPT0/t7e1JSUlhYWExfNtxcXGTk5Ph4eEAWa6EhITAwMCurq6bm5szd801c8O6urp9fX2kpKSMjIzR0dFESlTV1dU/WoJmZmZBVHIyedI9X585aaoAV61CUmpAWHw7ZaBYWFi+1fVES1dDT2KRue9+ruzr8vykutttksdeicNnoOnM2euSqtLJ3PeAn83Az+V4quufttnS4vg+Y9XeAAARCUlEQVR4nO1daXvaxhY2MtbVciNsJKRELrvNYrHaBhzAcdKkTW+btv//31zNGbFJM9IMaCHPo/dp034gQi9nnXPOzFxc5MiRI0eOHDly5MiRI0eOHDly5MiRI0eOHDly5ECoTXr94fNrtVoXhXq10RqPBo9Zv1N8uOt1BFuvyCJAENCfslxR7Ua7W8v65U7HZFxXK4gXAaKs66+j26xf8RTctUVV3mNnmqaBYJp7LO3nQdbveSy6jR0909A0YbpcPS0QVss3QdMMj6eoy/2fUVsHVV3csLOE1dqZFxRFcv+RJPSfwtxZr6aWx1JWxz8bx8mGn6mZs5e5S0sq+ICoztdLw8Ac7XbW78yD2rOK+RnW7KWpBMjt0VSa66kFgpTFbtbvzYy+7fETFqH0NiSdGXAU1dbPoaq3rxXMz1wXlCh6HseHFeZY+RnEOMACNI0FIz+A8rAEjuow6/ePREcFAVqzZqR6+jiWTeRz5OqZZwCNCjZAh0N+HqTmygJrnGRNIgS1qowIarMCpwA9Mb5AeLRHWfOgoobzT2vNL0BPjPMp0lR1nDUTCm4hRzPNIzR0S7Gw0txn6Ofpb2qYYH1+lIZuoKyRMeqdrNkQcFMHgm+8PjRAsQwUz1BRG8jJmNPmafwQRUdz/Y16du5mGBdBoIg86pmlNz0VbPBUFcWQgKJ+VqH/0YY4+BALQRQYXVsU61mz2gcEQqscE0GX4sKVonwODvWmBuudDjJCbXF8HAxSnLmhP9P8rdbtt6oVHUF8BoLm5xgJukApqpgVu8GwqurytkSI/8doxkpQclxTlPtZ0Os1bFL903qJzQgxlCdXT+3UF/2ToVo5rH+aUPs0tVm8OuqiiVaLKSeo3Vd1r/5pGdPlbLWaLd9MS1jELEEX0gtyNmkGxcfGhp+hmTNU/4Tqp/tvoXncejACSj3diNHxCmimNV04BSVY/4wdIMTULPFRkLH4jCdHit3kaEBCTCkDH2EBGhZLATQ2SGsjrdxtqGP9XMWTWTOjaaWU2MDSTzCmJ5QnjoMyMwU5+bXwDS6gWYsUnIsP0gtKwBNn+AomqJXTFiBCE4XEpBv+uDphxrX044OyNBP3ph1UxDaF0wpoRwO86XOiBAe4DZERwUIB1TMSXUPdqrFWJ46AlnBuCl7GcrIjKL2Zgp5g1W2EIr0RZ3WCF8rKdTW9xAjWdKhiZydBV4YLI8mYD1VeK0MjxOsLsZUUwTs7ax3FxWGxmhTDIXIzde53OsDJFFG40BMieItEqHEUmNAIUKHpOC/rhYcXx2kWTuM5dxnaMTOrPXZ77WGrAZFiyvh2Lrmms159NixNM3bQNMtcrtZO8+iaQNwMu+2GrOu6LONJUEYRuqJzFp8NbX/mcL8gZ1jG28I5bu08j7OS0W253A4roVaTgV7zZWVuBw0pQLOJEQNgZDRjK7jV+rp+wA7NgkaXeZVCeWlpW3ai7KqAquroD/SfirxXPDY1a+bwjBEBYI6oc3cyv44q735uQ7OQ+awWUuma0lwIG3oimmt+Ho+6k9sa4Pb2sTsYdV5tdacZpoZG3XgIomU+ms4cnqapI9vj59rS28x1gQ8FGAQNJ4im0QyPXsWudgaUH/q2229s9d9VjKcHHo6ofyGcOJ05qVa8H7ju+gNJYXPvygOeKEQzvmprEPUTT/rCZmLYtGYcHCWnjtVElo/NwNubSuHMkZg9gTJfefxku8X4zXf9urrlOGfmKEnlz/i7jpvOrOFZSdN6mrM7Okla4N+Vd0T7cejZu6lxFLYkyfmswa8p8pcWH7HmWEse21AcGM5y+VW5x+xr/YpXPecpTkqKU0dfKdq8K6mujQe1Xjj4SYUny+N3nGGMZMzReuJo6EgFrDYqX6umi0coljyl7I0AZfH4bRLemDRfjVl5eENfrPOspSZA0OJaH0lrLED1pAZ0reUN2vKMMUoSKE+FneIdfIvFp6EzMHm9cWoi1cWqqi05fl1vrK/C2hjGs4Qaj6J485+iGkflBM9LG1OeSiUeCNMZ9Ye/jqY4kF/HNYrdhUTYNLiMEVIclcnF9XVeFVXKeJw+tsJQ7RU6BhZPS0SC4UyW9dQj0hGuIgwMm7kPj7O2hxuTfL8zskWxEf3sqsg5xoQJinq8Dcu+zU9x5foCPbJd04Na75yboBx3hX2AKXL17qYmg57CqB3HL4fVX6zHPxmBsw4ej4cHwiJym77Mp6PwUEGsJjH6MYHhW4Oj8IwHwsK1Ca0nrAd2gnMUJpKQIFBEUjQF5rcpFJpm1EBYz2VorjhUH2m+KCY1vAOKan7mEOIC1afCXgdtHOAQIYyzJtnGG0HoeuL4ySNGM1Es5LBCZY1SpUQHBqCXzjHAiSwxbL52LKPZCtbHSQ+QKCXXxENoiHzR60ELnSVCNUyT+WGFupn8jCAsAzhMUfkcNkuEVk0ms9KDa95rcF3Fi81jIWZozMvF8JG3nszRU8KRcBd8bt79J04427dqI1PUmPV0jkbeaJVw1BdkaEh4mAoHWeDN9SXr32RAsbx7LciUl8yq5b5XhVZHQRkba9dMWSMdfd39ZZdhfBSLpT2GsO+GeVeK8kQ3xJqNwj3jg5qgo3vagBheFv57PKs9FA8YXrShrsFqPSGG+OguK4w124PAzcj7HQNgGA/Foo8hXg4wvhmMLVJap12dPRpCKDwYf8QM46BYDDAcwHQL418HV0NOs1BSqjlMT4HWln4Q6z2Gp9tiMcgQSkes6oWawxRnOnKVwWLzyg/BTXIbhqdSLJIYQlA02B4wpzeHEUO2uINGrgT90CVvGV42T+DXLBIZQvJmsIXqEIZ9Zoaoh+73VzuGJ1DcEAwwBCGyRbIIGTJpKZopEyq+jHuP4dEUtwQDDMES2SoaUQxZFoeKYAbnyPcZXr47kWCQIXKnJtMusRCG2JdG/0yw31j2d88PGF6+OyJo7BEMMoSYyJRShvjSic5mzeBnAs84ZOhS5ERhXgxliBIbpoCB/DylkIEWTwbDbrqmLyMlMrx8x4kDggSGd4z1B7x3j0jw4sJmyuEhLfL7mQDD6w+UL6HhfSmcISwxGBwhKkZRa/vIX2nRj0D5TFANEmc4YlPT0EU+UnUGV2MSGyCJMwQ1ZVgmumZIHXFHqXdk1wl70mD/I3GGoKaRG8Ph9ej1TVQvqEfIEMI9wRsnz3DMomJghvStiaiMEfUMaWkS11/JM8QqFiWAaWj9b8KSOKBYQZh6SJ4h1CCWEb+/E2aGF7hgGpE4PFDq5skzxEv98J8fHH0l5GvQ8iK8TQABlfQjpcBwGN1Vgd8/bByzpkbV0KndnRQYjiKbDjhWh3aKkL8Kba+hgCoIhL+ZAsNIV4ObwOFzQyDEsHUY8lXBpDQdhrdRXQe0oS2qBwx5jRmymEZdVpH0K6XAsIb6t290htDti97uJYeP06BaHXEDbgoMIauZUl8Nd/uidwp1Q/UU52yklmEaDBvh3T/UclcZRj9bIEXK2JxU1igRNQ2GLTGkViYtKblIENCTpBwhh8Mhqa+dBsNOSK0M+gyCzjQ0gYc8yBRR3yM7hm06Q+UJzuNjHD3D5+RNSSPQwJBY50mDIYR8Yt8BE2Q/U7ENnRDSZvtzYEh4KwkmlHWO3TNjoGgEx+bw6pAUU9NgSGnDK3hCme/gzw6e7wzs7jhHht4pw5zbES76KnFbANbSc2KozGcwwMu/RwAfMG5aq4ONSOdmh0phAQIUjznV9A4fsGOiTXPbh2YbD329I0lpLjS8i+XIGfrhZvPa8qXgGSTOaUhRx1/z5mVYPmT4nvSZ8R5DSZKcFb4hQrSPnqGf1MHhCKZmPJWbsLfSIRa8XdwcErz8wvldLAxbUE9Em9+VZvnJ3GyTez1lq2xPrmwu3DDenl6cB0q11IWP4a98X3RTOmT4O+lDsBNk/uCsn94MY7OLUzj1NppefXtpCjoTEUVW4vrw4vshw+98X3NzXzxg+BvpQ3jDoKUZu5to6nGMRnZbB+daUtb4F3/7hHjD9SV/+Bj+j/CZmiocvEZFfY7rhJpa79neP3mVWFP+9ZDg9RXpQ1R8O2R4/43wmYm+JSfKLHuM+fDYG1ZFFUuT2ID84GP4ievxv5UOGf4gfAYFC0Gu6Kpeb40Smkyu3XWrAiVcfPKFCz5Xc+9j+JXwGVQvlUfdyV2ix17C4TvEWfErH8Nrnsf6zLB4T/oQUtLkz0geoP4UscfqD/nXf3I89q9DERLDIWogJnes0BZwRBR59s8XLrjUtORjSHKlKO9O8PCrLeCAIaIh+lzN5TXJlsj45ldSkqNBGU3iZyVeePsTic2PP31qypG4FX24JwRTiIbJn3d5gYuWxDOo/IbILkS/CIlmiAaaUjDDC9wfIS8RfTH/8vJvtif6clJKvEe/LHVEPV4IIiVeBNSUMer7on2x+JGgpLCFPnTTVnwAdSHGJT9DNj394dNR8sICrQ0TPs9zB5nmTb/4GbKsML7e+0V4/0fwUxClUlJS3Asn2rw/rXGFGO1Py36CpSLlO6njarHjBpkEcUdxwNdE12ve+wmS/QwSYYonzaP+ATEkBoUY5W1+DxAs0kWY3l3IEHyJbZ6gEMOl+Lvfy5BFCF9IXngnhDFNiF+DQgyxxZuADVLqiHCdS5JHzgaAxpMo62ASRUoOflUkqOhHgiOFTDHly2VAiETDDxJEIJU0vn0kELz/i/DJKmT76d7wDIZBTN2u3pEYBo3xK8EEKZFiBGvSxI5jpQC5U/KwMUlPXYrfD8X4LRDnsY4ShA06ynj0TJyQqYrjLyturXGXwv0okwTo6ug/hOfB7YKpOlIM2DFXIWbCZIbIqWKOP96TBVi8J9WBoTJE39qbIGCdSFyvkULGRo7/3nwrU/hRloWgo5lctQYHz+vEugkhtdlydGj8yATx5XuCzFdBjwk96lI4jOIvVILEUTZ8uGH6bgYD9JQch+kUaQzJ/TSIhNldB4hmBQWZvCq94mR4TySIL7LJ8EpHOD+mQv6Bv3IxJHrRi2d8UqSdgR/dAEaLaFMQvxI1lcSwRFwS4hlCtnHD5AAvQTvAhZjdEBiWSsROnCdBio6kBnAFtMPorr4HOQYYlsgaevGKCVLsPD3gS8Wpx/AExehnWCqRKvgXNexF00+4Ca+Ce6a0iaSAGA8Zlj6SVktuoPf66smdssWBO5hkoF8J/unymsawdP+e3AsfqGdEcEOxQreXD9fXJIalj2Wigrou2htJEOWzIOhmqGCLskgNWzcfdnLcMHTlR6hXINQalc1ExJkQdN+pjvxe6Am0nzb2CAxL9x9/o81qDDbzO3IiZxUeixa0hkPPRr/6Asr6S6nkiu8bba2wOSo5VO0zQRtWORFH3P/pkvzlY/kfer9mIG+uYojvRNu44Lm/qCPu//0R0o66e94IMJ4zl2PGLZ5HFVkPZA6gNt7eKlyJ6czluDHG86jycQMTfX2joOIpV1Yki0kdv6QucHPsbQ3QFWB6HRh+eHdiiBWR5/KHWl+uCFsBZnFvOgduW54xyfaQcYtOt7W7y0ZUW+dpgfuYbK4hF9V6O1LfHtvC7ioiUa+nccnv6Zg8bzjKujqk3aPjKmd3rKu7i6RElf/ej8zw2LI3by5WVLHRHjwemmXtcdB51bfeE2m1+ppRyfBI3LbF3fuLaOxVrT4PO+N2e9xpveo2utNqR8/97DjDctOx6Hbkg8vMRFGUEcS967owPX34c4lvD5N21a74rmw7IOfqsPzz0sOoDTpVWYVb9w64ya4XkqvD3k+onATc3HVHnWdBtW0VYNtyozPqJjuvnRHw3XKZNJJy5MiRI0eOHDly5MiRI0eOHDnOG/8HuxXQ4oZWuz8AAAAASUVORK5CYII=" alt="FortiCNAPP Logo" class="header-logo">
                <div class="header-text">
                    <h1>FortiCNAPP Cloud Identity Entitlement Management Report</h1>
                    <p class="subtitle">Unused Permissions ≥70%</p>
                </div>
            </div>
        </div>

        <div class="report-title">
            <div class="meta">
                <div class="meta-item"><strong>Report Generated:</strong> $REPORT_TIME</div>
                <div class="meta-item"><strong>Account:</strong> $LW_ACCOUNT</div>
                <div class="meta-item"><strong>Date Range:</strong> $START_DATE_DISPLAY to $END_DATE_DISPLAY</div>
                <div class="meta-item"><strong>Threshold:</strong> ≥ $UNUSED_THRESHOLD unused entitlements</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="label">Critical Risk Identities</div>
                <div class="value">$ROOT_AND_HIGH_COUNT</div>
                <div class="description">High privileges + Full admin access</div>
            </div>
            <div class="stat-card warning">
                <div class="label">Excessive Privileges</div>
                <div class="value">$HIGH_PRIV_COUNT</div>
                <div class="description">Identities with ≥ $UNUSED_THRESHOLD unused entitlements</div>
            </div>
            <div class="stat-card info">
                <div class="label">Full Admin Access</div>
                <div class="value">$ROOT_COUNT</div>
                <div class="description">Identities with ALLOWS_FULL_ADMIN</div>
            </div>
        </div>

        <div class="data-section">
            <h2>
                🚨 Critical Risk Identities
                <span class="badge critical">$ROOT_AND_HIGH_COUNT identities</span>
            </h2>
            <p style="color: #718096; margin-bottom: 20px;">
                These identities have both excessive unused privileges (≥$UNUSED_THRESHOLD) and full administrative access, representing the highest security risk.
            </p>

            <div class="filter-bar">
                <input type="text" class="search-box" id="searchCritical" placeholder="Search by name, ID, or domain...">
                <button class="filter-btn active" onclick="filterTable('critical', 'all')">All</button>
                <button class="filter-btn" onclick="filterTable('critical', 'AZURE')">Azure</button>
                <button class="filter-btn" onclick="filterTable('critical', 'AWS')">AWS</button>
                <button class="filter-btn" onclick="filterTable('critical', 'GCP')">GCP</button>
            </div>

            <div class="table-container">
                <table id="criticalTable">
                    <thead>
                        <tr>
                            <th>Principal ID</th>
                            <th>Name</th>
                            <th>Provider</th>
                            <th>Domain ID</th>
                            <th>Unused Entitlements</th>
                            <th>Risk Severity</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody id="criticalTableBody">
                        $CRITICAL_ROWS
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            Generated by FortiCNAPP Cloud Identity Entitlement Management | Report Time: $REPORT_TIME
        </div>
    </div>

    <!-- Print/PDF Button -->
    <button class="print-button no-print" onclick="window.print()">
        📄 Save as PDF
    </button>

    <script>
        // Load data
        const criticalData = $CRITICAL_JSON;

        // Search functionality
        document.getElementById('searchCritical').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const rows = document.querySelectorAll('#criticalTableBody tr');

            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });

        // Filter functionality
        let currentFilter = 'all';
        function filterTable(table, provider) {
            currentFilter = provider;
            const rows = document.querySelectorAll('#criticalTableBody tr');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            rows.forEach(row => {
                const providerCell = row.querySelector('[data-provider]');
                if (provider === 'all' || providerCell.dataset.provider === provider) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }

        // Initialize tooltips or additional interactions
        console.log(`Report loaded with ${criticalData.length} critical identities`);
    </script>
</body>
</html>
HTML_START

echo "✓ HTML report generated: $OUTPUT_HTML"
echo ""

# Generate PDF version
if [ -f "./generate_pdf.sh" ]; then
    echo "Generating PDF version..."
    ./generate_pdf.sh || echo "⚠ PDF generation failed, but HTML report is available"
fi

echo ""
echo "Open in browser:"
echo "  open $OUTPUT_HTML"
