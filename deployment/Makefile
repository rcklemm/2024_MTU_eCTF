
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
# Generate a random encryption key for use between AP and Component
	echo -n "#define KEY {" > global_secrets.h
# od prints 16 bytes of hex in format: 00 11 22 ... ff
# use sed to add commas and 0x prefix: , 0x00, 0x11, 0x22 ... 0xff
# use cut to remove the extra comma from the front: 0x00, 0x11, 0x22 ... 0xff
# use head to remove the trailing newline from the output
	od -An -tx1 -N16 /dev/random | sed "s/ /, 0x/g" | cut -b3- | head -c-1 >> global_secrets.h
	echo "}" >> global_secrets.h

clean:
	rm -f global_secrets.h
