#!/bin/bash

set -euo pipefail

# Load configuration
source .env

# Files
HTML_REPORT="${OUTPUT_DIR:-.}/forticnapp_identity_entitlement_report.html"
PDF_REPORT="${OUTPUT_DIR:-.}/forticnapp_identity_entitlement_report.pdf"

echo "Generating PDF from HTML report..."

# Check if HTML report exists
if [ ! -f "$HTML_REPORT" ]; then
    echo "Error: HTML report not found at $HTML_REPORT"
    echo "Please run ./generate_report.sh first"
    exit 1
fi

# Method 1: Try Chrome/Chromium headless (most common on macOS)
if command -v /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome &> /dev/null; then
    echo "Using Google Chrome to generate PDF..."
    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
        --headless \
        --disable-gpu \
        --print-to-pdf="$PDF_REPORT" \
        --no-pdf-header-footer \
        --print-to-pdf-no-header \
        "file://$(pwd)/$HTML_REPORT"
    echo "✓ PDF generated successfully: $PDF_REPORT"
    exit 0
fi

# Method 2: Try wkhtmltopdf (if installed via homebrew)
if command -v wkhtmltopdf &> /dev/null; then
    echo "Using wkhtmltopdf to generate PDF..."
    wkhtmltopdf \
        --page-size A4 \
        --orientation Landscape \
        --margin-top 10mm \
        --margin-bottom 10mm \
        --margin-left 10mm \
        --margin-right 10mm \
        --no-stop-slow-scripts \
        --javascript-delay 1000 \
        "$HTML_REPORT" \
        "$PDF_REPORT"
    echo "✓ PDF generated successfully: $PDF_REPORT"
    exit 0
fi

# Method 3: Instructions for manual conversion
echo "⚠ No automatic PDF generator found."
echo ""
echo "To generate PDF, you have these options:"
echo ""
echo "Option 1: Use your web browser"
echo "  1. Open the HTML report: open $HTML_REPORT"
echo "  2. Press Cmd+P (or File > Print)"
echo "  3. Click 'Save as PDF' in the PDF dropdown"
echo "  4. Save to: $PDF_REPORT"
echo ""
echo "Option 2: Install wkhtmltopdf"
echo "  brew install wkhtmltopdf"
echo "  Then run this script again"
echo ""
echo "Option 3: Use Chrome from command line"
echo "  /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \\"
echo "    --headless --print-to-pdf=\"$PDF_REPORT\" \\"
echo "    \"file://$(pwd)/$HTML_REPORT\""
echo ""

exit 1
