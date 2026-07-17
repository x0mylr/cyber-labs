#!/usr/bin/env bash
# Lab 02 Verification Script
# Usage: bash lab-02-verify.sh <check-name>
# Checks: check-install | check-interfaces | check-capture | check-scenario | check-analysis | check-report | all

set -euo pipefail

CAPTURES_DIR="$HOME/cyber-labs/captures"
REPORTS_DIR="$HOME/cyber-labs/reports"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED=1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

FAILED=0

check_install() {
    echo ""
    info "=== Installation Check ==="
    echo ""

    if command -v tshark &>/dev/null; then
        TSHARK_VER=$(tshark --version 2>&1 | head -1 | awk '{print $3}')
        pass "tshark is installed (version $TSHARK_VER)"
    else
        fail "tshark is not installed — run: sudo apt install -y tshark"
    fi

    if command -v wireshark &>/dev/null; then
        WS_VER=$(wireshark --version 2>&1 | head -1 | awk '{print $3}')
        pass "wireshark is installed (version $WS_VER)"
    else
        fail "wireshark is not installed — run: sudo apt install -y wireshark"
    fi

    CURRENT_USER=$(id -un)
    if groups "$CURRENT_USER" | grep -qw wireshark; then
        pass "User '$CURRENT_USER' is in the wireshark group"
    else
        fail "User '$CURRENT_USER' is NOT in the wireshark group"
        echo "       Fix: sudo usermod -aG wireshark \$USER && newgrp wireshark"
    fi

    if [ -d "$CAPTURES_DIR" ]; then
        pass "Captures directory exists ($CAPTURES_DIR)"
    else
        fail "Captures directory missing — run: mkdir -p $CAPTURES_DIR"
    fi

    if [ -d "$REPORTS_DIR" ]; then
        pass "Reports directory exists ($REPORTS_DIR)"
    else
        fail "Reports directory missing — run: mkdir -p $REPORTS_DIR"
    fi

    echo ""
    if [ "$FAILED" -eq 0 ]; then
        info "Installation check complete. Ready to capture packets."
    else
        echo -e "${RED}One or more checks failed. Fix the issues above before continuing.${NC}"
    fi
}

check_interfaces() {
    echo ""
    info "=== Network Interface Check ==="
    echo ""

    if ! command -v tshark &>/dev/null; then
        fail "tshark not installed — run check-install first"
        return
    fi

    info "Available interfaces detected by tshark:"
    if tshark -D 2>/dev/null | head -10; then
        echo ""
    else
        fail "tshark -D failed — you may need sudo or wireshark group membership"
        return
    fi

    # Check for at least one non-loopback interface
    IFACES=$(ip link show 2>/dev/null | grep -E '^[0-9]+: ' | awk -F': ' '{print $2}' | grep -v '^lo$')
    if [ -n "$IFACES" ]; then
        pass "At least one non-loopback interface found"
        for iface in $IFACES; do
            STATE=$(ip link show "$iface" 2>/dev/null | grep -oP 'state \K\S+' || echo "UNKNOWN")
            info "  Interface '$iface' — state: $STATE"
        done
    else
        fail "No non-loopback interfaces found — check your network connection"
    fi

    echo ""
    info "Interface check complete."
}

check_capture() {
    echo ""
    info "=== Baseline Capture Check ==="
    echo ""

    PCAP="$CAPTURES_DIR/baseline.pcap"

    if [ -d "$CAPTURES_DIR" ]; then
        pass "Captures directory exists"
    else
        fail "Captures directory missing — run: mkdir -p $CAPTURES_DIR"
        return
    fi

    if [ -f "$PCAP" ]; then
        pass "baseline.pcap exists"
    else
        fail "baseline.pcap not found at $PCAP"
        echo "       Run the Step 3.2 capture command first."
        return
    fi

    FILE_SIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)
    if [ "$FILE_SIZE" -gt 1024 ]; then
        pass "baseline.pcap is non-empty ($(du -sh "$PCAP" | cut -f1))"
    else
        fail "baseline.pcap is too small (${FILE_SIZE} bytes) — no packets were captured"
        echo "       Make sure you generated network traffic during the capture."
    fi

    if tshark -r "$PCAP" -c 1 &>/dev/null; then
        PACKET_COUNT=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
        pass "baseline.pcap is a valid pcap file ($PACKET_COUNT packets)"
    else
        fail "baseline.pcap is not a valid pcap file — it may be corrupted"
    fi

    echo ""
    info "Capture check complete."
}

check_scenario() {
    echo ""
    info "=== Scenario Capture Check ==="
    echo ""

    PCAP="$CAPTURES_DIR/scenario.pcap"

    if [ -f "$PCAP" ]; then
        pass "scenario.pcap exists"
    else
        fail "scenario.pcap not found — complete Part 4 of the lab first"
        return
    fi

    FILE_SIZE=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)
    if [ "$FILE_SIZE" -gt 2048 ]; then
        pass "scenario.pcap is non-empty ($(du -sh "$PCAP" | cut -f1))"
    else
        fail "scenario.pcap is too small — the capture may not have run long enough"
    fi

    if tshark -r "$PCAP" -c 1 &>/dev/null; then
        PACKET_COUNT=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
        pass "scenario.pcap is a valid pcap file ($PACKET_COUNT packets)"
    else
        fail "scenario.pcap is not a valid pcap file"
        return
    fi

    # Check for TCP traffic (the beacon uses TCP/HTTP)
    TCP_COUNT=$(tshark -r "$PCAP" -Y "tcp" 2>/dev/null | wc -l)
    if [ "$TCP_COUNT" -gt 0 ]; then
        pass "scenario.pcap contains TCP traffic ($TCP_COUNT packets)"
    else
        warn "No TCP traffic found in scenario.pcap — was the simulation running?"
    fi

    # Check for HTTP or HTTPS traffic
    HTTP_COUNT=$(tshark -r "$PCAP" -Y "http or tls" 2>/dev/null | wc -l)
    if [ "$HTTP_COUNT" -gt 0 ]; then
        pass "scenario.pcap contains HTTP/TLS traffic ($HTTP_COUNT packets)"
    else
        warn "No HTTP or TLS traffic found — the beacon simulation may not have run"
    fi

    echo ""
    info "Scenario capture check complete."
}

check_analysis() {
    echo ""
    info "=== Analysis Readiness Check ==="
    echo ""

    PCAP="$CAPTURES_DIR/scenario.pcap"

    if [ ! -f "$PCAP" ]; then
        fail "scenario.pcap not found — complete Part 4 first"
        return
    fi

    if tshark -r "$PCAP" -c 1 &>/dev/null; then
        PACKET_COUNT=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
        pass "scenario.pcap exists and is non-empty ($PACKET_COUNT packets)"
    else
        fail "scenario.pcap is not a valid pcap file"
        return
    fi

    TCP_COUNT=$(tshark -r "$PCAP" -Y "tcp" 2>/dev/null | wc -l)
    if [ "$TCP_COUNT" -gt 0 ]; then
        pass "scenario.pcap contains TCP traffic"
    else
        fail "No TCP traffic in scenario.pcap — re-run the scenario capture"
    fi

    DNS_COUNT=$(tshark -r "$PCAP" -Y "dns" 2>/dev/null | wc -l)
    if [ "$DNS_COUNT" -gt 0 ]; then
        pass "scenario.pcap contains DNS traffic"
    else
        warn "No DNS traffic found — this is unusual but may not be a problem"
    fi

    # Show top destination IPs as a guide
    echo ""
    info "Top destination IPs in your capture (use these for Part 5 analysis):"
    tshark -r "$PCAP" -T fields -e ip.dst 2>/dev/null | sort | uniq -c | sort -rn | head -8 | \
        while read count ip; do
            echo "       $count connections → $ip"
        done

    echo ""
    info "Analysis check complete. Proceed to report writing."
}

check_report() {
    echo ""
    info "=== Incident Report Check ==="
    echo ""

    REPORT="$REPORTS_DIR/lab-02-incident-report.txt"

    if [ -d "$REPORTS_DIR" ]; then
        pass "Reports directory exists"
    else
        fail "Reports directory missing — run: mkdir -p $REPORTS_DIR"
        return
    fi

    if [ -f "$REPORT" ]; then
        pass "lab-02-incident-report.txt exists"
    else
        fail "lab-02-incident-report.txt not found"
        echo "       Complete Part 7 of the lab to create your report."
        return
    fi

    LINE_COUNT=$(wc -l < "$REPORT")
    if [ "$LINE_COUNT" -gt 10 ]; then
        pass "lab-02-incident-report.txt has content ($LINE_COUNT lines)"
    else
        fail "lab-02-incident-report.txt is too short — it may not be filled in yet"
    fi

    echo ""
    info "Report check complete."
}

run_all() {
    echo ""
    echo "================================================"
    echo "  Lab 02 — Full Verification Suite"
    echo "================================================"
    check_install
    check_interfaces
    check_capture
    check_scenario
    check_analysis
    check_report
    echo ""
    echo "================================================"
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}All checks passed. Lab 02 complete!${NC}"
    else
        echo -e "${RED}Some checks failed. Review the output above.${NC}"
    fi
    echo "================================================"
}

# ---- Main ----
COMMAND="${1:-}"

case "$COMMAND" in
    check-install)    check_install    ;;
    check-interfaces) check_interfaces ;;
    check-capture)    check_capture    ;;
    check-scenario)   check_scenario   ;;
    check-analysis)   check_analysis   ;;
    check-report)     check_report     ;;
    all)              run_all          ;;
    *)
        echo ""
        echo "Usage: bash lab-02-verify.sh <command>"
        echo ""
        echo "Commands:"
        echo "  check-install     Verify tshark/wireshark are installed and configured"
        echo "  check-interfaces  Verify network interfaces are available"
        echo "  check-capture     Verify the baseline.pcap capture exists and is valid"
        echo "  check-scenario    Verify the scenario.pcap capture exists and is valid"
        echo "  check-analysis    Verify scenario capture is ready for analysis"
        echo "  check-report      Verify the incident report was created"
        echo "  all               Run every check in sequence"
        echo ""
        ;;
esac

exit $FAILED
