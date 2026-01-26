#!/usr/bin/env python3
"""Test improved threat detection logic with mock profiles."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from privaseeai_security.device_info import ProfileInfo, DeviceInfoExtractor
from privaseeai_security.crypto.cert_validator import ThreatLevel

def test_threat_reduction():
    """Test that new threat detection reduces false positives."""
    
    # Create a mock extractor to access the methods
    extractor = DeviceInfoExtractor("/tmp/dummy")
    
    print("=" * 60)
    print("FALSE POSITIVE REDUCTION TEST")
    print("=" * 60)
    
    # Test Case 1: Apple System MDM Profile (should be NONE - whitelisted)
    print("\n[Test 1] Apple System MDM Profile")
    profile1 = ProfileInfo(
        profile_id="Library/ConfigurationProfiles/com.apple.mdm.profile",
        profile_type="MDM",
        is_signed=False,
        organization=None,
        display_name="System MDM"
    )
    profile1.suspicious_indicators = extractor._detect_suspicious_indicators(profile1)
    profile1.threat_level = extractor._assess_threat_level(profile1)
    
    print(f"   Indicators: {profile1.suspicious_indicators}")
    print(f"   Threat Level: {profile1.threat_level.value}")
    print(f"   ✅ Expected: NONE (whitelisted)" if profile1.threat_level == ThreatLevel.NONE else f"   ❌ Got: {profile1.threat_level.value}")
    
    # Test Case 2: VPN with localhost server (should be CRITICAL)
    print("\n[Test 2] VPN Profile with Localhost Server")
    profile2 = ProfileInfo(
        profile_id="vpn.localhost.profile",
        profile_type="VPN",
        is_signed=False,
        organization=None,
        display_name="Localhost VPN"
    )
    profile2.suspicious_indicators = extractor._detect_suspicious_indicators(profile2)
    profile2.threat_level = extractor._assess_threat_level(profile2)
    
    print(f"   Indicators: {profile2.suspicious_indicators}")
    print(f"   Threat Level: {profile2.threat_level.value}")
    print(f"   ✅ Expected: CRITICAL (localhost VPN)" if profile2.threat_level == ThreatLevel.CRITICAL else f"   ❌ Got: {profile2.threat_level.value}")
    
    # Test Case 3: ProtonVPN (unsigned, no org) - should be CRITICAL
    print("\n[Test 3] ProtonVPN (unsigned, unknown org)")
    profile3 = ProfileInfo(
        profile_id="net.protonmail.vpn.profile",
        profile_type="VPN",
        is_signed=False,
        organization=None,
        display_name="ProtonVPN"
    )
    profile3.suspicious_indicators = extractor._detect_suspicious_indicators(profile3)
    profile3.threat_level = extractor._assess_threat_level(profile3)
    
    print(f"   Indicators: {profile3.suspicious_indicators}")
    print(f"   Threat Level: {profile3.threat_level.value}")
    print(f"   ✅ Expected: CRITICAL (unsigned VPN from unknown org)")
    
    # Test Case 4: Verizon Carrier Profile (known org) - should be LOW/NONE
    print("\n[Test 4] Verizon Carrier Profile (known org)")
    profile4 = ProfileInfo(
        profile_id="carrier.verizon.profile",
        profile_type="MDM",
        is_signed=True,
        organization="Verizon",
        display_name="Verizon Carrier Settings"
    )
    profile4.suspicious_indicators = extractor._detect_suspicious_indicators(profile4)
    profile4.threat_level = extractor._assess_threat_level(profile4)
    
    print(f"   Indicators: {profile4.suspicious_indicators}")
    print(f"   Threat Level: {profile4.threat_level.value}")
    print(f"   ✅ Expected: NONE (known legitimate org)" if profile4.threat_level == ThreatLevel.NONE else f"   ⚠️ Got: {profile4.threat_level.value}")
    
    # Test Case 5: Apple com.apple.* profile - should be NONE
    print("\n[Test 5] Apple Bundle ID Profile")
    profile5 = ProfileInfo(
        profile_id="com.apple.wifi.configuration",
        profile_type="Configuration",
        is_signed=True,
        organization="Apple Inc.",
        display_name="WiFi Configuration"
    )
    profile5.suspicious_indicators = extractor._detect_suspicious_indicators(profile5)
    profile5.threat_level = extractor._assess_threat_level(profile5)
    
    print(f"   Indicators: {profile5.suspicious_indicators}")
    print(f"   Threat Level: {profile5.threat_level.value}")
    print(f"   ✅ Expected: NONE (Apple bundle ID)" if profile5.threat_level == ThreatLevel.NONE else f"   ❌ Got: {profile5.threat_level.value}")
    
    # Test Case 6: Unsigned MDM from unknown org - should be CRITICAL
    print("\n[Test 6] Unsigned MDM from Unknown Org")
    profile6 = ProfileInfo(
        profile_id="unknown.mdm.profile",
        profile_type="MDM",
        is_signed=False,
        organization=None,
        display_name="Custom MDM"
    )
    profile6.suspicious_indicators = extractor._detect_suspicious_indicators(profile6)
    profile6.threat_level = extractor._assess_threat_level(profile6)
    
    print(f"   Indicators: {profile6.suspicious_indicators}")
    print(f"   Threat Level: {profile6.threat_level.value}")
    print(f"   ✅ Expected: CRITICAL (unsigned MDM, no org)")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    test_results = [
        ("Apple System MDM", profile1.threat_level == ThreatLevel.NONE),
        ("Localhost VPN", profile2.threat_level == ThreatLevel.CRITICAL),
        ("ProtonVPN unsigned", profile3.threat_level == ThreatLevel.CRITICAL),
        ("Verizon known org", profile4.threat_level == ThreatLevel.NONE),
        ("Apple bundle ID", profile5.threat_level == ThreatLevel.NONE),
        ("Unknown MDM", profile6.threat_level == ThreatLevel.CRITICAL),
    ]
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    print(f"\nTests Passed: {passed}/{total}")
    
    for test_name, result in test_results:
        status = "✅" if result else "❌"
        print(f"  {status} {test_name}")
    
    print("\n" + "=" * 60)
    print("EXPECTED IMPROVEMENTS")
    print("=" * 60)
    print("✅ Apple system files whitelisted (no false positives)")
    print("✅ Known orgs (Verizon, Apple) not flagged")
    print("✅ Localhost VPN detected as CRITICAL")
    print("✅ Unsigned VPNs from unknown orgs flagged as CRITICAL")
    print("✅ Real threats still detected properly")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(test_threat_reduction())
