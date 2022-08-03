#If KERNELRELEASE is defined, we've been invoked from the
#kernel build system and use its language
ifneq ($(KERNELRELEASE),)
	obj-m := netfilter_tcp_parser.o

#Otherwise we were called directly from the command
#line; invoke the kernel build system.
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif
