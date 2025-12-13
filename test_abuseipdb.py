"""
Test AbuseIPDB integration directly
"""
import os
import sys
sys.path.append('src')
from threat_intel import check_ip_abuse

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

if not ABUSEIPDB_API_KEY:
    print("❌ ABUSEIPDB_API_KEY not set!")
    print("Run: $env:ABUSEIPDB_API_KEY=\"your_key_here\"")
else:
    print(f"✓ API Key configured: {ABUSEIPDB_API_KEY[:10]}...")
    
    # Test with a known suspicious IP (use a test IP)
    test_ip = "118.25.6.39"  # Known malicious IP for testing
    print(f"\n Testing AbuseIPDB check for {test_ip}...")
    
    result = check_ip_abuse(test_ip, ABUSEIPDB_API_KEY)
    
    print("\n" + "="*70)
    print("ABUSEIPDB RESULT:")
    print("="*70)
    
    if result:
        print(f"IP Address: {result.get('ipAddress', 'N/A')}")
        print(f"Abuse Score: {result.get('abuseConfidenceScore', 0)}")
        print(f"Country: {result.get('countryCode', 'N/A')}")
        print(f"Usage Type: {result.get('usageType', 'N/A')}")
        print(f"ISP: {result.get('isp', 'N/A')}")
        print(f"Domain: {result.get('domain', 'N/A')}")
        print(f"Total Reports: {result.get('totalReports', 0)}")
        print(f"Last Reported: {result.get('lastReportedAt', 'Never')}")
        
        score = result.get('abuseConfidenceScore', 0)
        if score >= 50:
            print(f"\n⚠️  HIGH RISK! Score {score} >= 50 - Would be auto-blocked!")
        elif score > 0:
            print(f"\n⚠️  Medium risk (score: {score})")
        else:
            print(f"\n✓ Clean IP (score: {score})")
    else:
        print("❌ No data returned from AbuseIPDB")
        
print("\n" + "="*70)
print("Integration test complete!")
