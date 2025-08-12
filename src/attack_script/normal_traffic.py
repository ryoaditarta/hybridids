
import sys
import subprocess

SERVER = "192.168.100.122"
PORT = 80
URI = "/"

def main():
	if len(sys.argv) != 3:
		print("Usage: python3 normal_traffic.py <num_conns> <rate>")
		sys.exit(1)
	try:
		n = int(sys.argv[1])
		r = int(sys.argv[2])
	except ValueError:
		print("Arguments must be integers.")
		sys.exit(1)
	n_half = n // 2
	# GET
	get_cmd = [
		"httperf",
		"--server", SERVER,
		"--port", str(PORT),
		"--uri", URI,
		"--num-conns", str(n_half),
		"--rate", str(r)
	]
	print(f"[INFO] Running GET: {' '.join(get_cmd)}")
	subprocess.run(get_cmd)
	# POST
	post_cmd = [
		"httperf",
		f"--server={SERVER}",
		f"--port={PORT}",
		f"--uri={URI}",
		f"--num-conns={n - n_half}",
		f"--rate={r}",
		"--method=POST"
	]
	print(f"[INFO] Running POST: {' '.join(post_cmd)}")
	subprocess.run(post_cmd)

if __name__ == "__main__":
	main()
