# Default (70% unused entitlement threshold)
  python lw_report_gen.py \
    --report CSA_Detailed \
    --format HTML \
    --customer "Customer Name" \
    --author "Your Name"

  # Custom threshold (50% - shows more identities)
  python lw_report_gen.py \
    --report CSA_Detailed \
    --format PDF \
    --customer "Customer Name" \
    --ciem-threshold 50 \
    --alerts-start-time 30:0

  # With caching for testing
  python lw_report_gen.py \
    --report CSA_Detailed \
    --cache-data \
    --customer "Test" \
    --ciem-threshold 90
