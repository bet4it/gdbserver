cc = gcc
prom = gdbserver
deps = gdb_signals.h gdb/signals.h gdb/signals.def
obj = gdbserver.o signals.o

$(prom): $(obj)
	$(cc) -o $(prom) $(obj)

%.o: %.c $(deps)
	$(cc) -c $< -o $@
