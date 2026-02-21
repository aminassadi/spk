#!/bin/bash
# Script to detach all TC egress programs from lo interface

IFACE="lo"

echo "Checking for TC egress filters on $IFACE..."
sudo tc filter show dev $IFACE egress

echo ""
echo "Detaching all TC egress filters..."

# Get all filter handles and priorities
sudo tc filter show dev $IFACE egress | grep -E "filter protocol|handle|pref" | while read line; do
    if [[ $line =~ handle[[:space:]]+0x([0-9a-f]+) ]]; then
        HANDLE="${BASH_REMATCH[1]}"
        if [[ $line =~ pref[[:space:]]+([0-9]+) ]]; then
            PRIORITY="${BASH_REMATCH[1]}"
            echo "Detaching filter with handle $HANDLE and priority $PRIORITY..."
            sudo tc filter del dev $IFACE egress handle $HANDLE prio $PRIORITY protocol all 2>/dev/null || \
            sudo tc filter del dev $IFACE egress handle 0x$HANDLE prio $PRIORITY protocol all 2>/dev/null || \
            echo "Failed to detach filter $HANDLE"
        fi
    fi
done

# Alternative: Remove all filters more directly
echo ""
echo "Attempting to remove all egress filters..."
sudo tc filter del dev $IFACE egress 2>/dev/null || echo "No filters to remove or already removed"

echo ""
echo "Checking remaining filters..."
sudo tc filter show dev $IFACE egress

echo ""
echo "Done!"

