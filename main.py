import datetime

# Sample log data
logins = [
    {'timestamp': '2025-03-13T10:00:01', 'user': 'user1', 'status': 'failed'},
    {'timestamp': '2025-03-13T10:00:30', 'user': 'user1', 'status': 'failed'},
    {'timestamp': '2025-03-13T10:01:15', 'user': 'user1', 'status': 'failed'},
    {'timestamp': '2025-03-13T10:02:30', 'user': 'user1', 'status': 'failed'},
    {'timestamp': '2025-03-13T10:03:10', 'user': 'user1', 'status': 'failed'},
    {'timestamp': '2025-03-13T10:05:00', 'user': 'user2', 'status': 'failed'},
]

# Time window and threshold
time_window = datetime.timedelta(minutes=5)
threshold = 4

# Convert timestamps to datetime objects
for login in logins:
    login['timestamp'] = datetime.datetime.strptime(login['timestamp'], '%Y-%m-%dT%H:%M:%S')

# Check for failed login attempts within the time window
def detect_brute_force(logins, threshold, time_window):
    alerts = []
    
    for i in range(len(logins)):
        user = logins[i]['user']
        start_time = logins[i]['timestamp']
        failed_attempts = [log for log in logins if log['user'] == user and start_time <= log['timestamp'] <= start_time + time_window and log['status'] == 'failed']
        
        if len(failed_attempts) >= threshold:
            alerts.append({
                'alert': f"Suspicious activity detected for user {user}: {len(failed_attempts)} failed login attempts in {time_window}."
            })
    return alerts

# Run the detection
alerts = detect_brute_force(logins, threshold, time_window)
for alert in alerts:
    print(alert['alert'])
