import subprocess
base = ["go", "run", "./cmd/agentgate", "check", "--policy", "examples/policies/supply-chain.yaml"]
for args in [["--action", "exec", "--", "curl", "http://evil.example"], ["--action", "exec", "--", "npm", "install", "left-pad"], ["--action", "net_egress", "registry.npmjs.org:443"], ["--action", "net_egress", "registry.npmjs.org.evil.example:443"]]:
    result = subprocess.run(base + args, text=True, capture_output=True, check=True)
    print(result.stdout.strip())
