obj-m += nexus_nt.o
nexus_nt-objs := src/nexus_main.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

load:
	sudo insmod nexus_nt.ko
	cat /proc/nexus_nt

unload:
	sudo rmmod nexus_nt

test: all load
	@echo "Module loaded. Check dmesg and /proc/nexus_nt"
