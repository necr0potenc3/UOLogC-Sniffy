#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include "Logwindow.h"

typedef struct tagFrequency
{
   unsigned long bytecount;
   unsigned long count;
}Frequency;

typedef struct tagDebugLoopParam
{
   DWORD TargetPID;
   int attached;
   char *path;
}DebugLoopParam;

typedef struct tagClientEntry
{
   char Version[50];
   void *Send, *Recv;
   short RegBufSend, RegLenSend, RegBufRecv, RegLenRecv;
   //n0p3:
   DWORD Size, DateStamp, BaseAddress;
   PBYTE Image;
   HANDLE Process;
}ClientEntry;

typedef struct tagGlobalOptions
{
   HWND hWnd;
   LogWindow *PacketLog;
   HMENU MainMenu;
   int FilterMode;
   int FilterType;
   int AutoScroll;
   int FileLogging;
   int WindowLogging;
   int RawLogging;
   char Filter[500];
}GlobalOptions;

extern GlobalOptions Options;
extern ClientEntry Client;
extern Frequency freqs[255][2];
extern int minutecounter;
extern BOOL has_first_send;
extern BOOL has_first_recv;

#endif