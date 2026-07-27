obj-m += WlStckD.o

WlStckD-y := src/WlStckD.o

ccflags-y += -I$(src)/include

all:
	make -C /usr/lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /usr/lib/modules/$(shell uname -r)/build M=$(PWD) clean
