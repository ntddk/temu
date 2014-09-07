all: doxygen tarball

doxygen.cfg: doxygen.cfg.in
	cat $< | sed \
          -e 's/@abs_top_srcdir@/../g' \
          -e 's/@DOT@/dot/g' \
          -e 's/@PACKAGE_VERSION@/$(PACKAGE_VERSION)/' \
          -e 's/@abs_top_builddir@/../g' > $@

clean:
	rm -rf doxygen doxygen.cfg

doxygen: doxygen.cfg
	doxygen doxygen.cfg

tarball: doxygen
	tar czf temu-docs.tgz doxygen/html
