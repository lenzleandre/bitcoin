
import datetime

###################################################################
#
# Showing the way bits, difficulty, target, and hash work together.
#
###################################################################

print("Calculating target from bits, verifying the block's hash is valid, and verify the calculated difficulty.")

import hashlib

string = "Hello, World!"

complete = False
n = 0

while complete == False:
	curr_string = string + str(n)
	curr_hash = hashlib.sha256(str(curr_string).encode('utf-8')).hexdigest()
	n = n + 1

	# slows performance drastically
	## print curr_hash 

	if curr_hash.startswith('000000'):
		print(curr_hash)
		print(curr_string)
complete = True



