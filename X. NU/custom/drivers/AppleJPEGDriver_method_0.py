import iokitlib

# Get service and connect
iokit = iokitlib.iokit()
conn = iokit.open_service(b"AppleJPEGDriver", 1)
print(f"Connection handle: {conn}")

# Call external method
kr = iokit.connect_call_method(conn, 0, None, None, None, None)
print(f"Method call result: {kr}")
