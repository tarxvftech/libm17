from libc.stdint cimport uint16_t, uint8_t

cdef extern from "m17.h":
    uint16_t m17_calc_crc_ez( uint8_t * data, size_t len );
