# distutils: sources = ../src/m17.c
# distutils: include_dirs = ../src/

cimport cm17

def crc(data):
    if type("") == type(data):
        d = data.encode("utf-8")
    else:
        d = data
    return cm17.m17_calc_crc_ez( d, len(d) )

cdef class LibM17:
    def __cinit__(self):
        pass
    def __dealloc__(self):
        pass


