#include <stdint.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include "Aprof.h"

#include <asm/sigcontext.h>       /* for sigcontext */
#include <asm/signal.h>           /* for stack_t */

namespace GUM {

int Aprof::_dumpfile = -1;
void* Aprof::_buffer[BUFFER_SIZE];
int Aprof::_bufferpos = 0;
uint64_t Aprof::_samplecount = 0;
int Aprof::_samplecountoffset = 0;
pthread_mutex_t Aprof::_mutex = PTHREAD_MUTEX_INITIALIZER;

Aprof::Aprof()
{
	Begin("/sdcard/profiledata.bin");
}

Aprof::~Aprof()
{
	End();
}

bool Aprof::Begin(const char* outfilename)
{
	// If already profiling, end old session
	if (_dumpfile >= 0)
	{
		End();
	}
	
	// Open dump file
	_dumpfile = open(outfilename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (_dumpfile < 0)
	{
		return false;
	}

	// Write version 1 PROFDAT file
	
	// I. Write PROFDAT1 header string
	write(_dumpfile, "PROFDAT1", 8);

	// II. Write PC size (bytes, should be 4 or 8, endianness indicates process endianness)
	uint32_t pcsize = static_cast<char>(sizeof(void*));
	write(_dumpfile, &pcsize, sizeof(pcsize));

	// III. Write sample count
	_samplecount = 0;
	_samplecountoffset = lseek(_dumpfile, 0, SEEK_CUR);
	write(_dumpfile, &_samplecount, sizeof(_samplecount));
	
	// Configure SIGPROF signal handler
	sigset_t mask;
	sigfillset(&mask);
	
	struct sigaction act;
	act.sa_sigaction = &Handler;
	act.sa_mask = mask;
	act.sa_flags = SA_SIGINFO;
	act.sa_restorer = 0;
	
	sigaction(SIGPROF, &act, 0);
	signal(SIGINT, &HandleSIGUSR1);
	
	// Enable the profile timer
	itimerval itv;
	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 10000; // 100 hz
	itv.it_value = itv.it_interval;
	
	setitimer(ITIMER_PROF, &itv, 0);
}

bool Aprof::End()
{
	// Disable the profile timer
	itimerval itv;
	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 0;
	itv.it_value = itv.it_interval;
	
	setitimer(ITIMER_PROF, &itv, 0);
	
	// Close the session
	if (_dumpfile >= 0)
	{
		if (_bufferpos > 0)
		{
			write(_dumpfile, _buffer, _bufferpos * sizeof(unsigned long));
		}
		// Write samplecount
		lseek(_dumpfile, _samplecountoffset, SEEK_SET);
		write(_dumpfile, &_samplecount, sizeof(_samplecount));
		lseek(_dumpfile, 0, SEEK_END);
		
		// Dump maps info
		write(_dumpfile, "MAPSDATA", 8);
		uint64_t zero = 0;
		write(_dumpfile, &zero, sizeof(zero)); // placeholder -- may need to put string length here eventually
		int mapsfd = open("/proc/self/maps", O_RDONLY);
		char cpybuf[64];
		int n = read(mapsfd, cpybuf, sizeof(cpybuf));
		while (n > 0)
		{
			write(_dumpfile, cpybuf, n);
			n = read(mapsfd, cpybuf, sizeof(cpybuf));
		}
		close(mapsfd);
		
		close(_dumpfile);
		_dumpfile = -1;
	}
	_bufferpos = 0;
}

void Aprof::Handler(int signo, siginfo_t* info, void* context)
{
	pthread_mutex_lock(&_mutex);
	ucontext_t* uc = reinterpret_cast<ucontext_t*>(context);
	_buffer[_bufferpos++] = reinterpret_cast<void*>(uc->uc_mcontext.arm_pc);
	++_samplecount;
	if (_bufferpos == BUFFER_SIZE)
	{
		write(_dumpfile, _buffer, BUFFER_SIZE * sizeof(uc->uc_mcontext.arm_pc));
		_bufferpos = 0;
	}
	pthread_mutex_unlock(&_mutex);
}

void Aprof::HandleSIGUSR1(int signo)
{
	End();
}

Aprof GlobalProfiler;

}