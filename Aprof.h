#ifndef GUM_Aprof_h
#define GUM_Aprof_h

#include <pthread.h>
#include <signal.h>

namespace GUM {

class Aprof
{
public:
	Aprof();
	~Aprof();

	static bool Begin(const char* outfilename);
	static bool End();
	
private:
	static void Handler(int signo, siginfo_t* info, void* context);
	static void HandleSIGUSR1(int signo);

	static int _dumpfile;
	static const int BUFFER_SIZE = 1024;
	static void* _buffer[BUFFER_SIZE];
	static int _bufferpos;
	
	static uint64_t _samplecount;
	static int _samplecountoffset;
	
	static pthread_mutex_t _mutex;
};

}

#endif // GUM_Aprof_h