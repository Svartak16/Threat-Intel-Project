"""
daemon_runner.py - Week 3
Runs the enforcer as a continuous background daemon.
Schedules enforcement cycles every 15 minutes automatically.

Usage:
    sudo python3 daemon_runner.py              # Run forever
    sudo python3 daemon_runner.py --once       # Single cycle then exit
    sudo python3 daemon_runner.py --interval 5 # Run every 5 minutes
"""

import sys
import time
import argparse
import schedule
from datetime import datetime, timezone
from enforcer import run_enforcement

INTERVAL_MINUTES = 15   # default cycle interval

def job():
    print(f"\n{'='*60}")
    print(f"[DAEMON] Enforcement cycle triggered @ {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")
    try:
        run_enforcement()
    except Exception as e:
        print(f"[DAEMON ERROR] Enforcement cycle failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="TIP Enforcement Daemon")
    parser.add_argument("--once",     action="store_true", help="Run one cycle then exit")
    parser.add_argument("--interval", type=int, default=INTERVAL_MINUTES,
                        help=f"Minutes between cycles (default: {INTERVAL_MINUTES})")
    args = parser.parse_args()

    print(r"""
  _____ ___ ____    ____                                
 |_   _|_ _|  _ \  |  _ \  __ _  ___ _ __ ___   ___  _ __  
   | |  | || |_) | | | | |/ _` |/ _ \ '_ ` _ \ / _ \| '_ \ 
   | |  | ||  __/  | |_| | (_| |  __/ | | | | | (_) | | | |
   |_| |___|_|     |____/ \__,_|\___|_| |_| |_|\___/|_| |_|
                                                              
  Dynamic Policy Enforcement Daemon — Week 3
    """)

    if args.once:
        print("[DAEMON] Running single enforcement cycle...")
        job()
        print("[DAEMON] Single cycle complete. Exiting.")
        sys.exit(0)

    print(f"[DAEMON] Starting continuous mode. Interval: every {args.interval} minute(s).")
    print("[DAEMON] Press Ctrl+C to stop.\n")

    # Run immediately on start, then schedule
    job()
    schedule.every(args.interval).minutes.do(job)

    try:
        while True:
            schedule.run_pending()
            time.sleep(30)   # check scheduler every 30 seconds
    except KeyboardInterrupt:
        print("\n[DAEMON] Interrupted by user. Shutting down gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("[!] daemon_runner.py requires sudo for iptables access.")
        print("    Usage: sudo python3 daemon_runner.py")
        sys.exit(1)
    main()
