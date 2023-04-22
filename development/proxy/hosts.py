# Print out the additions to /etc/hosts for the proxy

for i in range(1, 50):
    print(f"127.0.0.1 {i}-courier.push.apple.com")
    print(f"127.0.0.1 {i}.courier.push.apple.com")
