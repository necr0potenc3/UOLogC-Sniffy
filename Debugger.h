#ifndef _DEBUGGER_H_
#define _DEBUGGER_H_

void Detach(void);
DWORD DebugLoop(void *param);
unsigned long GetRegisterContent(HANDLE Process, CONTEXT *context, short registernum);
unsigned long GetTimeStamp(HANDLE file);
char *SetupDebugger(DEBUG_EVENT *dbgev, ClientEntry *Client);

#endif /* _DEBUGGER_H_ */
