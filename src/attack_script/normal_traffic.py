
import sys
import subprocess

SERVER = "192.168.100.122"
PORT = 80
URI = "/"


def main():
	if len(sys.argv) < 3 or len(sys.argv) > 4:
		print("Usage: python3 normal_traffic.py <num_conns> <rate> [GET|POST]")
		sys.exit(1)
	try:
		n = int(sys.argv[1])
		r = int(sys.argv[2])
	except ValueError:
		print("Arguments must be integers.")
		sys.exit(1)
	order = sys.argv[3].upper() if len(sys.argv) == 4 else "GET"
	if order not in ("GET", "POST"):
		print("Order must be GET or POST.")
		sys.exit(1)
	n_half = n // 2
	cmds = []
	get_cmd = [
		"httperf",
		"--server", SERVER,
		"--port", str(PORT),
		"--uri", URI,
		"--num-conns", str(n_half),
		"--rate", str(r)
	]
	post_cmd = [
		"httperf",
		f"--server={SERVER}",
		f"--port={PORT}",
		f"--uri={URI}",
		f"--num-conns={n - n_half}",
		f"--rate={r}",
		"--method=POST"
	]
	if order == "GET":
		cmds = [("GET", get_cmd), ("POST", post_cmd)]
	else:
		cmds = [("POST", post_cmd), ("GET", get_cmd)]
	for label, cmd in cmds:
		print(f"[INFO] Running {label}: {' '.join(cmd)}")
		subprocess.run(cmd)

if __name__ == "__main__":
	main()
