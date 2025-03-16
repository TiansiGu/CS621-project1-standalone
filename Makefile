OBJS = compdetect.o probing.o payload_generator.o
PROGS = compdetect
LDFLAGS = -lcjson

HDRS = standalone.h payload_generator.h
%.o: %.c $(HDRS)
	gcc -c -g -o $@ $< 

$(PROGS): $(OBJS)
	gcc -g -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(OBJS) $(PROGS)
