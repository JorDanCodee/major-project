import datetime
import json

def anaylze_logs(log_file):
    """Enhanced honeypot log analysis with temporal and behavioral patterns"""
    ip_analysis = {}
    port_analysis = {}
    hourly_attacks = {}
    data_patterns = {}

    #Track session patterns
    ip_sessions = {}
    attack_timeline = []

    with open(log_file, 'r') as f:
        for line in f:
            try:
                activity = json.loads(line)
                timestamp = datetime.datetime.fromisoformat(activity['timestamp'])
                ip = activity['remote_ip']
                port = activity['port']
                data = activity['data']

                #Initalizing IP tracking if new
                if ip not in ip_analysis:
                    ip_analysis[ip] = {
                        'total_attempts' : 0,
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'targeted_ports': set(),
                        'unique_payloads': set(),
                        'session_count': 0
                    }
                
                #Update IP statistics
                ip_analysis[ip]['total_attempts'] += 1
                ip_analysis[ip]['last_seen'] = timestamp
                ip_analysis[ip]['targeted_ports'].add(port)
                ip_analysis[ip]['unique_payloads'].add(data.strip())

                #Track hourly patterns
                hour = timestamp.hour
                hourly_attacks[hour] = hourly_attacks.get(hour, 0) +1

                #Anaylze port targeting patterns
                if port not in port_analysis:
                    port_analysis[port] = {
                        'total_attempts': 0,
                        'unique_ips': set(),
                        'unique_payloads': set()
                    }
                
                port_analysis[port]['total_attempts'] += 1
                port_analysis[port]['unique_ips'].add(ip)
                port_analysis[port]['unique_payloads'].add(data.strip())

                #Track payload patterns
                attack_timeline.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'port':port
                })

            except (json.JSONDecodeError, KeyError) as e:
                continue

    #Anaysis Report Generation
    print("\n=== Honeypot Anaylsis Report ===")

    #1. IP-based Analysis
    print("\nTop 10 Most Active IPs:")
    sorted_ips = sorted(ip_analysis.items(),
                        key= lambda x: x[1]['total_attempts'],
                        reverse=True)[:10]
    for ip, stats in sorted_ips:
        duration = stats['last_seen'] - stats['first_seen']
        print(f"\nIP: {ip}")
        print(f"Total Attempts: {stats['total_attempts']}")
        print(f"Active Duration: {duration}")
        print(f"Unique ports Targeted: {len(stats['targeted_ports'])}")
        print(f"Unique Payloads: {len(stats['unique_payloads'])}")

    #2. Port Analysis
    print("\nPort Targeting Analysis:")
    sorted_ports = sorted(port_analysis.items(),
                          key=lambda x: x[1]['total_attempts'],
                          reverse=True)
    for port, stats in sorted_ports:
        print(f"\nPort {port}:")
        print(f"Total Attempts: {stats['total_attempts']}")
        print(f"Unique Attackers: {len(stats['unique_ips'])}")
        print(f"Unique Payloads: {len(stats['unique_payloads'])}")

    #3. Temporal Analysis
    print("\nHourly Attack Distribution:")
    for hour in sorted(hourly_attacks.keys()):
        print(f"Hour {hour:02d}: {hourly_attacks[hour]} attempts")

    #4. Attack Sophistication Analysis
    print("\nAttacker Sophistication Analysis:")
    for ip, stats in sorted_ips:
        sophistication_score = (
            len(stats['targeted_ports']) * 0.4 + #Port diversity
            len(stats['unique_payloads']) * 0.6 #Payload diversity
        )
    print(f"IP {ip}: Sophistication Score {sophistication_score:.2f}")

    #5. Common Payload Patterns
    print("\nTop 10 Most Common Payloads:")
    sorted_payloads = sorted(data_patterns.items(),
                             key=lambda x: x[1],
                             reverse=True)[:10]
    for payload, count in sorted_payloads:
        if len(payload) > 50: # Truncate long payloads
            payload = payload[:50] + "..."
        print(f"Count {count}: {payload}")

