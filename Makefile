obj-m += namestack.o
namestack-objs := main.o af_name.o dns.o

# ordinary compiles:
#KERN_BUILD := /lib/modules/$(shell uname -r)/build
KERN_BUILD := ../linux-2.6.27

all:
	make -C $(KERN_BUILD) M=$(PWD) modules

clean:
	make -C $(KERN_BUILD) M=$(PWD) clean
