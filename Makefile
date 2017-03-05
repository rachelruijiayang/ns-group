c1:
	python client.py localhost 3000 auth/client.crt auth/client.key auth/server.crt

c2: 
	python client.py localhost 8888 auth/client.crt auth/client.key auth/server.crt

c3: 
	python client.py localhost 32616 auth/client.crt auth/client.key auth/server.crt

server:
	python server.py