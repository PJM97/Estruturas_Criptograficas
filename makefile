make: src/Server.py src/Client.py
	gnome-terminal -- sh -c "python3 src/Server.py; bash"
	gnome-terminal -- sh -c "python3 src/Client.py; bash"

clean:
	rm src/__pycache__ -rf