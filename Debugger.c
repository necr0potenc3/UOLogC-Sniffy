/**************************************************************************************\
*                                                                                      *
*  This file is part of UOLog,                                                         *
*  An advanced packet monitoring and logging tool for Ultima Online (UO).              *
*                                                                                      *
*  Copyright (C) 2003 by Folke Will (Folko)                                            *
*                                                                                      *
*  This program is free software; you can redistribute it and/or modify                *
*  it under the terms of the GNU General Public License as published by                *
*  the Free Software Foundation; either version 2 of the License, or                   *
*  (at your option) any later version.                                                 *
*                                                                                      *
*  This program is distributed in the hope that it will be useful,                     *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of                      *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                       *
*  GNU General Public License for more details.                                        *
*                                                                                      *
*  You can contact the author by sending E-Mail to Folko <Folko@elitecoder.net>        *
*                                                                                      *
\**************************************************************************************/

/*
    <CVS SERVER GENERATED>
    This project was stored on Folko's CVS server as $Source: /home/cvs/UOLogC/Debugger.c,v $.
   
    Id tag follows (<filename> <revision> <last changed> <author> <status>):
    $Id: Debugger.c,v 1.3 2003/08/04 02:09:58 folko23 Exp $
   
    If you want to report any errors, please include this tag.
    </GENERATED>
*/

#include "UOLog.h"
#include "UOLogSniffy.h"

int detach;

DWORD DebugLoop(void *param)
{
   short keepalive=1;
   int attached;
   DEBUG_EVENT dbgev;
   DWORD TargetPID=((DebugLoopParam*)param)->TargetPID;
   HANDLE TargetProcess=0, Thread=0;
   PROCESS_INFORMATION info;
   Breakpoint BPXSend, BPXRecv;
   
   detach=0;
   attached=((DebugLoopParam*)param)->attached;
   if(attached)
      Client.Process = TargetProcess=OpenProcess(PROCESS_ALL_ACCESS, 0, TargetPID);
   else
   {
      char *path=((DebugLoopParam*)param)->path;
      STARTUPINFO start;
      int res=0;

      memset(&info, 0, sizeof(info));
      memset(&start, 0, sizeof(start));
      start.cb=sizeof(start);
      res=CreateProcess(path, NULL, NULL, NULL, 0, CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS, 0, 0, &start, &info);
      if(res)
      {
         Thread=info.hThread;
		 Client.Process = TargetProcess=info.hProcess;
         TargetPID=info.dwProcessId;
         check(Thread!=0);
         WaitForInputIdle(TargetProcess, INFINITE);
      }
   }
   check(TargetPID!=0);
   check(TargetProcess!=0);
   if(!DebugActiveProcess(TargetPID))
   {
      MessageBox(Options.hWnd, "Couldn't get debug access to UO. Make sure the exe is readable and not opened by anything else.", "Error", MB_ICONERROR);
      EnableMenuItem(Options.MainMenu, ID_CLIENT_ATTACH, MF_ENABLED);
      EnableMenuItem(Options.MainMenu, ID_CLIENT_DETACH, MF_GRAYED);
      EnableMenuItem(Options.MainMenu, ID_CLIENT_LOAD, MF_ENABLED);
      //_endthread();
      return 1;
   }
   while(keepalive)
   {
      DWORD status=DBG_CONTINUE;

      WaitForDebugEvent(&dbgev, INFINITE);
      switch(dbgev.dwDebugEventCode)
      {
         case CREATE_PROCESS_DEBUG_EVENT: /* This is caused after we attached successfully, so let's set the breakpoints here. */
            {
               char *res=SetupDebugger(&dbgev, &Client);
               if(res)
               {
                  MessageBox(Options.hWnd, res, "Fatal error", MB_ICONERROR);
                  keepalive=0;
                  break;
               }
               BPXSend.Address=Client.Send;
               BPXSend.CallbackFunc=OnPacket;
               BPXSend.dbgev=&dbgev;
               BPXSend.TargetProcess=TargetProcess;
               BPXSend.type=TYPE_SEND;
               SetBreakpoint(&BPXSend);

               BPXRecv.Address=Client.Recv;
               BPXRecv.CallbackFunc=OnPacket;
               BPXRecv.dbgev=&dbgev;
               BPXRecv.TargetProcess=TargetProcess;
               BPXRecv.type=TYPE_RECV;
               SetBreakpoint(&BPXRecv);

               if(Options.FileLogging)
                  res=InitLogger();
               else
                  res=0;
               if(res)
               {
                  MessageBox(Options.hWnd, res, "Error", MB_ICONERROR);
                  keepalive=0;
                  break;
               }
               AppendLogWindow(Options.PacketLog, TimeStamp("Sniffy - Detected client %s\n", Client.Version));
               status=DBG_CONTINUE;
            }break;
         case EXCEPTION_DEBUG_EVENT:
            {
               if(dbgev.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT) /* BPX */
               {
                  void *addr=dbgev.u.Exception.ExceptionRecord.ExceptionAddress;;
                  if(attached)
                  {
                     typedef HANDLE (WINAPI *_Open)(DWORD, int, DWORD);
                     HINSTANCE kernel=LoadLibrary("KERNEL32");
                     _Open Open=(_Open)GetProcAddress(kernel, "OpenThread");
                     Thread=Open(THREAD_ALL_ACCESS, 0, dbgev.dwThreadId);
                     FreeLibrary(kernel);
                  }
                  if(addr==BPXSend.Address && !detach){ /* BPXSend caught. Dump the packet and set SINGLE_STEP (via Action). */
                     BreakpointAction(&BPXSend, Thread);
                     status=DBG_CONTINUE;
                  }else if(addr==BPXRecv.Address && !detach){
                     BreakpointAction(&BPXRecv, Thread);
                     status=DBG_CONTINUE;
                  }
                  if(attached)
                     CloseHandle(Thread);
               }else if(dbgev.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_SINGLE_STEP){
                     /* Process is in single step mode. Means we have to re-set our breakpoints. */
                     SetBreakpoint(&BPXSend);
                     SetBreakpoint(&BPXRecv);
                     status=DBG_CONTINUE;
               }else{ /* Process caused exception, so let it handle the exception! */
                  status=DBG_EXCEPTION_NOT_HANDLED;
               }
            }break;
         case EXIT_PROCESS_DEBUG_EVENT: /* Client closed */
            {
               AppendLogWindow(Options.PacketLog, TimeStamp("Client terminated\n"));
               keepalive=0;
               status=DBG_CONTINUE; 
            }break;
         default:
            status=DBG_CONTINUE;
      }
      if(detach) /* User wants to detach the debugger. We have to remove all BPXs first. */
      {
         RemoveBreakpoint(&BPXSend);
         RemoveBreakpoint(&BPXRecv);
         keepalive=0;
      }
      ContinueDebugEvent(dbgev.dwProcessId, dbgev.dwThreadId, status);
   }
   if(detach)
   {
      typedef int (WINAPI *_Stop)(DWORD);
      HINSTANCE kernel=LoadLibrary("KERNEL32");

      _Stop Stop=(_Stop)GetProcAddress(kernel, "DebugActiveProcessStop");
      Stop(TargetPID);
      FreeLibrary(kernel);
      AppendLogWindow(Options.PacketLog, TimeStamp("Detached successfully\n"));
   }
   if(!attached)
      CloseHandle(Thread);
   CloseHandle(TargetProcess);
   FinalizePacketLog();
   EnableMenuItem(Options.MainMenu, ID_CLIENT_ATTACH, MF_ENABLED);
   EnableMenuItem(Options.MainMenu, ID_CLIENT_DETACH, MF_GRAYED);
   EnableMenuItem(Options.MainMenu, ID_CLIENT_LOAD, MF_ENABLED);
   EnableMenuItem(Options.MainMenu, ID_LOGGING_LOGFILE, MF_ENABLED);
   //_endthread();
   return 1;
}

unsigned long GetTimeStamp(HANDLE file)
{
   unsigned long ClientSize;
   unsigned char *image;
   IMAGE_DOS_HEADER *doshdr;
   IMAGE_FILE_HEADER *filehdr;
   DWORD temp;

   ClientSize = GetFileSize(file, 0);
   image = (unsigned char *)malloc(sizeof(unsigned char)*ClientSize);
   if(!image) return 0;
   if(!ReadFile(file, image, ClientSize, &temp, 0)) {free(image); return 0;}
   doshdr=(IMAGE_DOS_HEADER*)image;
   filehdr=(IMAGE_FILE_HEADER*)(image+doshdr->e_lfanew+sizeof(IMAGE_NT_SIGNATURE));
   temp=filehdr->TimeDateStamp;
   free(image);
   return temp;
}

char *SetupDebugger(DEBUG_EVENT *dbgev, ClientEntry *Client)
{
   if(!dbgev->u.CreateProcessInfo.hFile)
	   return "Can't get access to client executable..";

   if(!StartSniffy(dbgev, Client))
	   return "Oh oh, sniffer went nuts";

   check(Client->Send!=0);
   check(Client->Recv!=0);
   /*check(Client->RegBufRecv!=0);
   check(Client->RegLenRecv!=0);
   check(Client->RegBufSend!=0);
   check(Client->RegLenSend!=0);*/
   return 0;
}

void Detach(void)
{
   AppendLogWindow(Options.PacketLog, TimeStamp("The next event will detach UOLog.\n"));
   detach=1;
   return;
}

unsigned long GetRegisterContent(HANDLE Process, CONTEXT *context, short registernum)
{
	void *content_pointer=NULL;
	unsigned long content=0;
	DWORD read;

   //check((registernum>0 && registernum<8));
   switch(registernum)
   {
      case 1: return context->Eax; break;
      case 2: return context->Ebx; break;
      case 3: return context->Ecx; break;
      case 4: return context->Edx; break;
      case 5: return context->Esi; break;
      case 6: return context->Edi; break;
      case 7: return context->Ebp; break;
	  default:
		  content_pointer = context->Esp + (registernum - 8);
		  ReadProcessMemory(Process, content_pointer, &content, sizeof(void*), &read);
		  return content;
		  break;
   }
   return 0;
}

