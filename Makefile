obj-m += antidetection.o
#antidetection-objs := main.o util.o module.o
antidetection-objs := main.o

KDIR=/lib/modules/$(shell uname -r)/build
#/lib/modules/4.15.0-55-generic/build
#/home/iie/cpp/hook_linux_system/antidetection


default:
	@echo "this makefile only support linux-x86_64!"
	#$(MAKE) ARCH=x86_64 EXTRA_CFLAGS="-D_CONFIG_X86_64_" -C $(KDIR) M=$(PWD) modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf util.o.ur-safe main.o.ur-safe