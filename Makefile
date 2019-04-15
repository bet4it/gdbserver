cc = gcc
prom = gdbserver
obj = gdbserver.o utils.o packets.o signals.o

$(prom): $(obj)
	$(cc) -o $(prom) $(obj)

gdbserver.o : gdbserver.c arch.h utils.h packets.h gdb_signals.h
	$(cc) -c $< -o $@

signals.o : signals.c gdb_signals.h gdb/signals.h gdb/signals.def
	$(cc) -c $< -o $@

%.o: %.c
	$(cc) -c $< -o $@
