all: python m17.bin

.PHONY: python
python: *.pxd *.pyx *.py
	python setup.py build_ext -i

m17.bin: m17.c
	gcc -DMAIN=main $^ -o $@
	./$@

clean:
	rm -rf m17.bin  build/  *.so
