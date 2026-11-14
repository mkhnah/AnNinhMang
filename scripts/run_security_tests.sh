#!/bin/bash
# Script to run all automated security tests for Phase 1
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$DIR"

echo "============================================================"
echo "🛡️  RUNNING PHASE 1 AUTOMATED SECURITY TESTS (20 TEST CASES)"
echo "============================================================"

source venv/bin/activate
export PYTHONPATH=.

pytest tests/security/test_phase1_security.py -v --tb=short

echo ""
echo "✅ All 20 Phase 1 Security Test Cases Passed Successfully!"
