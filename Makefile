c1:
	python client.py localhost 3000 auth/client.crt auth/client.key auth/server.crt auth/clientpubkey.pem

c2: 
	python client.py localhost 8888 auth/client.crt auth/client.key auth/server.crt auth/clientpubkey.pem

c3: 
	python client.py localhost 32616 auth/client.crt auth/client.key auth/server.crt auth/clientpubkey.pem

csbad:
	python client.py localhost 4444 auth/client.crt auth/client.key auth/badserver.crt auth/clientpubkey.pem
ccbad:
	python client.py localhost 5555 auth/client.crt auth/client.key auth/server.crt auth/clientpubkey.pem

s1:
	python server.py 3000 auth/server.crt auth/server.key auth/client.crt

s2:
	python server.py 8888 auth/server.crt auth/server.key auth/client.crt

s3:
	python server.py 32616 auth/server.crt auth/server.key auth/client.crt

ssbad:
	python server.py 4444 auth/server.crt auth/server.key auth/client.crt
scbad:
	python server.py 5555 auth/server.crt auth/server.key auth/badclient.crt