## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

noinst_libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

noinst_lib_LTLIBRARIES = lib_sfddos.la

lib_sfddos_la_LDFLAGS = -export-dynamic

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c  \
sfPolicyUserData.c

nodist_lib_sfddos_la_SOURCES = \
sf_dynamic_preproc_lib.c \
sfPolicyUserData.c \
spp_ddos.c \
sf_preproc_info.h

EXTRA_DIST = \
spp_ddos.c \
sf_preproc_info.h

sf_dynamic_preproc_lib.c: ../include/sf_dynamic_preproc_lib.c
	cp $? $@

sfPolicyUserData.c: ../include/sfPolicyUserData.c
	cp $? $@

clean-local:
	rm -f sf_dynamic_preproc_lib.c sfPolicyUserData.c
