

if ENABLE_PARSER

AM_CPPFLAGS = -I../include -I./cubew/lib

bin_PROGRAMS = ipm_parse

ipm_parse_CXXFLAGS=-DHPCX_IPM_PARSER -I./cubew/lib
ipm_parse_LDFLAGS=-L./cubew/lib -Lmxml/lib
ipm_parse_LDADD=-lcubew3 -lmxml -lpthread

ipm_parse_SOURCES = ipm_parse.cc \
		ipm_parse.h \
		getopts.cc \
		read_ipm.cc \
		util.cc \
		write_cube.cc \
		write_cube.h \
		write_html.cc \
		write_html_hpcx.cc \
		write_html.h \
		../src/report_banner.c

report_banner.o: ../src/report_banner.c
	$(CXX) $(CXXFLAGS) -I../include -c $<		

endif
