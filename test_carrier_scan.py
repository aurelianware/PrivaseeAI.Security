#!/usr/bin/env python3
"""Quick carrier compromise scan script."""

from src.privaseeai_security.monitors.carrier_detection import CarrierCompromiseDetector

print('🔍 PrivaseeAI Carrier Compromise Detector')
print('=' * 60)

detector = CarrierCompromiseDetector()

# 1. Check for localhost-routing VPN profiles (THE attack)
print('\n🚨 CRITICAL: Checking iOS backups for localhost-routing VPN profiles...')
localhost_threats = detector.detect_localhost_routing()
if localhost_threats:
    for threat in localhost_threats:
        print(f'\n{threat.threat_level.value}: {threat.attack_type}')
        print(f'Details: {threat.details}')
        for indicator in threat.indicators:
            print(f'  • {indicator}')
        if threat.profile_info:
            print(f'Profile: {threat.profile_info}')
        print(f'⚠️  ACTION: {threat.recommended_action}')
else:
    print('✅ No localhost-routing VPN profiles found in backups')

# 2. Check for unauthorized eSIM profiles
print('\n\n🔍 Checking for unauthorized eSIM profiles...')
esim_threats = detector.monitor_esim_profiles()
if esim_threats:
    for threat in esim_threats:
        print(f'\n{threat.threat_level.value}: {threat.attack_type}')
        print(f'Details: {threat.details}')
        for indicator in threat.indicators:
            print(f'  • {indicator}')
else:
    print('✅ No suspicious eSIM profiles detected')

# 3. Check DNS configuration
print('\n\n🔍 Checking DNS configuration...')
dns_threats = detector.analyze_dns_resolution()
if dns_threats:
    for threat in dns_threats:
        print(f'\n{threat.threat_level.value}: {threat.attack_type}')
        print(f'Details: {threat.details}')
        for indicator in threat.indicators:
            print(f'  • {indicator}')
        if threat.profile_info:
            print(f'DNS Info: {threat.profile_info}')
else:
    print(f'✅ DNS looks normal (baseline: {detector.dns_baseline})')

# 4. Check network interfaces
print('\n\n🔍 Checking network interfaces...')
iface_threats = detector.track_network_interfaces()
if iface_threats:
    for threat in iface_threats:
        print(f'\n{threat.threat_level.value}: {threat.attack_type}')
        print(f'Details: {threat.details}')
        for indicator in threat.indicators:
            print(f'  • {indicator}')
else:
    print('✅ Network interfaces appear normal')

print('\n' + '=' * 60)
print('Scan complete!')
