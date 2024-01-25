VER=3.2.20
REL=$(shell git rev-parse --short=7 HEAD| tr -d '\n')
CFLAGS = 
CC = 
LIBS =  
INCLUDES =
OBJS = 
SRCS = 
INSTALL_IMB=imb
INSTALL_PRESTA=presta-1.4.0
INSTALL_OSU=osu-micro-benchmarks-5.8
INSTALL_MPIP=mpiP-3.4
INSTALL_IPM=ipm-2.0.6
INSTALL_MISC=misc
WITH_UPC=no
PROCESSOR_TYPE=$(shell uname -m)
RPM_DIR=$(PWD)/rpm-dist/$(shell hostname)
MPIHOME=$(shell rpm -q openmpi --queryformat='%{prefixes}\n'|head -1)
UPCC=$(shell rpm -ql bupc | grep -w bin/upcc | grep -v .pl)
SHELL=/bin/bash
INSTALL_DIR=$(MPIHOME)/tests

default: all
all: imb-build osu mymisc
install: install-imb install-osu install-misc

mymisc:
	make -C $(PWD)/$(INSTALL_MISC) MPI_HOME=$(MPIHOME)

install-misc:
	make -C $(PWD)/$(INSTALL_MISC) MPI_HOME=$(MPIHOME) DESTDIR=$(DESTDIR) PREFIX=$(INSTALL_DIR)/$(INSTALL_MISC) install

mpip:
	export PATH=$(MPIHOME)/bin:${PATH};\
    cd $(PWD)/$(INSTALL_MPIP); \
    if [ $(shell mpif77 --help > /dev/null 2>&1; echo $$?) -ne 0 ]; then \
     ./configure ${CONF_ARGS} --disable-libunwind --prefix=$(INSTALL_DIR)/$(INSTALL_MPIP) --without-f77 --disable-libunwind --disable-fortranxlate --disable-fortranweak; \
    else \
     ./configure ${CONF_ARGS} --disable-libunwind --prefix=$(INSTALL_DIR)/$(INSTALL_MPIP); \
    fi; \
	make 

ipm:
	export PATH=$(MPIHOME)/bin:${PATH}; \
#	cd $(PWD)/$(INSTALL_IPM) && ./autogen.sh && ./configure --prefix=$(INSTALL_DIR)/$(INSTALL_IPM) && make #Use for 2.0.2 
	cd $(PWD)/$(INSTALL_IPM) && ./autogen.sh && ./build.sh $(INSTALL_DIR)/$(INSTALL_IPM)

# The variable $@ has the value of the target. 
imb-build: 
	cd $(PWD)/$(INSTALL_IMB)/src && make -f make_mpich MPI_HOME=$(MPIHOME)
presta:
	cd $(PWD)/$(INSTALL_PRESTA) && make MPIHOME=$(MPIHOME)
osu:
	export PATH=$(MPIHOME)/bin:${PATH}; \
	export INCLUDE=$(MPIHOME)/include:$(INCLUDE); \
	export LD_LIBRARY_PATH=$(MPIHOME)/lib64:$(LD_LIBRARY_PATH); \
	export MANPATH=$(MPIHOME)/share/man:$(MANPATH); \
	cd $(PWD)/$(INSTALL_OSU) && autoreconf -f -i && ./configure --prefix=$(INSTALL_DIR)/$(INSTALL_OSU) \
		CC=$(MPIHOME)/bin/mpicc CXX=$(MPIHOME)/bin/mpicc && make MPIHOME=$(MPIHOME); \
	if [ "$(WITH_UPC)" = "yes" ] && [ -n "$(UPCC)" ]; then \
		$(UPCC) upc/osu_upc_memput.c -o upc/osu_upc_memput; \
		$(UPCC) upc/osu_upc_memget.c -o upc/osu_upc_memget; \
	else \
		echo "*** Warning: upcc was not found. osu_upc tests will not be built."; \
			echo "Continue anyway."; \
	fi; \
	if [ -f "$(MPIHOME)/bin/oshcc" ]; then \
		make V=1 -C openshmem MPIHOME=$(MPIHOME) CC=$(MPIHOME)/bin/oshcc; \
	else \
		echo "*** Warning: oshcc was not found. osu_oshm tests will not be built."; \
			echo "Continue anyway."; \
	fi
clean-mpip:
	-cd $(PWD)/$(INSTALL_MPIP) && make distclean
clean-ipm:
	-cd $(PWD)/$(INSTALL_IPM) && make distclean
clean-imb: 
	-cd $(PWD)/$(INSTALL_IMB)/src && make MPIHOME=$(MPIHOME) clean
clean-osu:
	-cd $(PWD)/$(INSTALL_OSU) && make MPIHOME=$(MPIHOME) clean
clean-presta:
	-cd $(PWD)/$(INSTALL_PRESTA) && make MPIHOME=$(MPIHOME) clean
clean-misc:
	-cd $(PWD)/$(INSTALL_MISC) && make clean
clean: clean-imb clean-osu clean-ipm
	-rm -rf mpitests-$(VER) mpitests-$(VER).tar.gz
install-imb:
	mkdir -p $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_IMB)
	cp -f $(INSTALL_IMB)/src/{IMB-IO,IMB-EXT,IMB-MPI1,IMB-NBC,IMB-RMA} $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_IMB)
install-presta:
	mkdir -p $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_PRESTA)
	cp -f $(INSTALL_PRESTA)/com    		$(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_PRESTA)
	cp -f $(INSTALL_PRESTA)/glob     	$(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_PRESTA)
	cp -f $(INSTALL_PRESTA)/globalop 	$(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_PRESTA)
install-osu:
	mkdir -p $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_OSU)
	make -C $(PWD)/$(INSTALL_OSU) DESTDIR=$(DESTDIR) install
	if [ -f "$(MPIHOME)/bin/oshcc" ]; then \
		make CC=$(MPIHOME)/bin/oshcc -C $(PWD)/$(INSTALL_OSU)/openshmem DESTDIR=$(DESTDIR) install; \
	fi;
	find $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_OSU)/ -type f -exec mv {} $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_OSU) \;
	rm -rf $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_OSU)/libexec

install-mpip:
	mkdir -p $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_MPIP)
	make -C $(PWD)/$(INSTALL_MPIP) DESTDIR=$(DESTDIR) install
install-ipm:
	mkdir -p $(DESTDIR)/$(INSTALL_DIR)/$(INSTALL_IPM)
	make -C $(PWD)/$(INSTALL_IPM) DESTDIR=$(DESTDIR) CC=$(MPIHOME)/bin/mpicc install

dist:
	rm -rf mpitests-$(VER)
	mkdir mpitests-$(VER)
	cp -pr debian $(INSTALL_OSU) $(INSTALL_IMB) $(INSTALL_IPM) $(INSTALL_MISC) Makefile mpitests.spec *.patch mpitests-$(VER)
	sed -i "s/Version:.*/Version: $(VER)/g" mpitests-$(VER)/mpitests.spec
	sed -i "s/Release:.*/Release: $(REL)/g" mpitests-$(VER)/mpitests.spec
	sed -i "s#%VERSION%#$(VER)#g" mpitests-$(VER)/debian/changelog
	tar czf mpitests-$(VER).tar.gz mpitests-$(VER)

srcrpm:
	rpmbuild -ts --nodeps --define "_srcrpmdir $(PWD)/mpitests-$(VER)" --define "_specdir $(PWD)/mpitests-$(VER)" --define '_source_filedigest_algorithm md5' --define '_binary_filedigest_algorithm md5' mpitests-$(VER).tar.gz

binrpm:
	rm -rf $(RPM_DIR) && mkdir -p $(RPM_DIR)/BUILD $(RPM_DIR)/RPMS
	rpmbuild --rebuild --define "_topdir $(RPM_DIR)" --define 'path_to_mpihome $(MPIHOME)' $(PWD)/mpitests-$(VER)/mpitests-$(VER)-$(REL).src.rpm

deb:
	cd mpitests-$(VER) && PATH=$(MPIHOME)/bin:${PATH} DESTDIR=${PWD}/mpitests-$(VER) MPI_HOME=$(MPIHOME) dpkg-buildpackage -us -uc

mofed_inst:
	cp mpitests-$(VER)/mpitests-$(VER)-$(REL).src.rpm $(DEST)
	echo `basename mpitests-$(VER)/mpitests-$(VER)-$(REL).src.rpm` > $(DEST)/latest.txt

test: dist srcrpm binrpm
