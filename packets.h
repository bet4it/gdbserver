#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>

#define PACKET_BUF_SIZE 0x8000

static const char INTERRUPT_CHAR = '\x03';

uint8_t *inbuf_get();
int inbuf_end();
void inbuf_erase_head(ssize_t end);
void write_flush();
void write_packet(const char *data);
void read_packet();
void get_connection();
void enable_async_io(void);
void disable_async_io(void);
void initialize_async_io(void (*intr_func)(void));

#endif /* PACKETS_H */
