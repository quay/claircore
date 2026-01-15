trivial.wasm: trivial.c
	clang --target=wasm32 -nostdlib -O2 -Wl,--stack-first -Wl,--no-entry -fsanitize=undefined -fsanitize-trap\
		-Wl,--export=query\
		-mbulk-memory\
		-o $@ $<

.PHONY: clean
clean:
	rm -f *.wasm
