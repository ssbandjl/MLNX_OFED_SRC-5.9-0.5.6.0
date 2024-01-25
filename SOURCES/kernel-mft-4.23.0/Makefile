CPU_ARCH ?= $(shell uname -m)

all:
	cd mst_backward_compatibility/mst_pci && $(MAKE)
	cd mst_backward_compatibility/mst_pciconf && $(MAKE)

ifneq ($(findstring ppc64, $(CPU_ARCH)),)
	cd mst_backward_compatibility/mst_ppc && $(MAKE)
endif

clean:
	$(MAKE) clean -C mst_backward_compatibility/mst_pci
	$(MAKE) clean -C mst_backward_compatibility/mst_pciconf

ifneq ($(findstring ppc64, $(CPU_ARCH)),)
	$(MAKE) clean -C mst_backward_compatibility/mst_ppc
endif
