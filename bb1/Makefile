obj-m += cpuinfo_spoof.o

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean
