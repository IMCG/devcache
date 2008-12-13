build: withmutex nomutex

withmutex:
	gcc -g -Wall -DGCC -DDEBUG -DDEBUGLEVEL=255 -DDEBUG_LOCKS Cache.c -lpthread -o CacheTest_withmutex

nomutex:
	gcc -g -Wall -DGCC -DDEBUG -DDEBUGLEVEL=255 -DMUTEX_MANUAL -DMUTEX_NONE Cache.c  -o CacheTest_nomutex

clean:
	rm -rf *.o CacheTest_*

run: build
	./CacheTest_nomutex

run_mutex: build
	./CacheTest_withmutex

