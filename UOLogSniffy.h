#ifndef _UOLOGSNIFFY_H_
#define _UOLOGSNIFFY_H_

#include "globals.h"

BOOL StartSniffy(DEBUG_EVENT *dbgev, ClientEntry *Client);
void HandleFirstSend(CONTEXT *context, int type);

#endif