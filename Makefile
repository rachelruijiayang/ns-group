c1:
	python client.py localhost 3000 auth/client.crt auth/client.key auth/server.crt

c2: 
	python client.py localhost 8888 auth/client.crt auth/client.key auth/server.crt

c3: 
	python client.py localhost 32616 auth/client.crt auth/client.key auth/server.crt

s1:
	python server.py 3000 auth/server.crt auth/server.key auth/client.crt

s2:
	python server.py 8888 auth/server.crt auth/server.key auth/client.crt

s3:
	python server.py 32616 auth/server.crt auth/server.key auth/client.crt