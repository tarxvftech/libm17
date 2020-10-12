# distutils: sources = m17.c
# distutils: include_dirs = ./

cimport cm17
cdef class LibM17:
    @staticmethod
    def m17_calc_crc(data):
        return cm17.m17_calc_crc_ez( data, len(data) )


