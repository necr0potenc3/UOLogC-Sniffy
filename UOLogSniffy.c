////////////////////////////////////////////////////////////////////////////////
//
//
// Copyright (C) 2004 Daniel 'Necr0Potenc3' Cavalcanti
//
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
//
//	April 8th, 2004 	-- Took it from UOLogSniffy (did it reach public? :o)
//	adapted the code from lcc to VS.net. Changed some of Folke's code on
//	Debugger.c. The SetupDebugger function has been completly rewritten to
//	remove config support, redirected it to the functions present here.
//
////////////////////////////////////////////////////////////////////////////////


#include <windows.h>
#include "UOLogSniffy.h"
#include "Logwindow.h"
#include "Debugger.h"
#include "UOLog.h"

BOOL has_first_send=0;
BOOL has_first_recv=0;

BOOL StartSniffy(HANDLE hClient, ClientEntry *Client);
int FindBpxPositions(ClientEntry *Client);
void FindVersion(ClientEntry *Client);
void HandleFirstSend(CONTEXT *context, int type);
int GetPacketID(PBYTE buf);
DWORD FleXSearch(PBYTE src, PBYTE buf, DWORD src_size, DWORD buf_size, DWORD start_at, BYTE flex_byte, int which);

// unfortunatly this table has to be updated
// folke would just kill me if I added the code to
// retrieve the table from the client
static int pktlen_table[] =
{
	/* 0x00 */ 0x0068, 0x0005, 0x0007, 0x8000, 0x0002, 0x0005, 0x0005, 0x0007, 0x000F, 0x0005, 0x000B, 0x0007, 0x8000, 0x0003, 0x8000, 0x003D, 
	/* 0x10 */ 0x00D7, 0x8000, 0x8000, 0x000A, 0x0006, 0x0009, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x0025, 0x8000, 0x0005, 0x0004, 0x0008, 
	/* 0x20 */ 0x0013, 0x0008, 0x0003, 0x001A, 0x0009, 0x0015, 0x0005, 0x0002, 0x0005, 0x0001, 0x0005, 0x0002, 0x0002, 0x0011, 0x000F, 0x000A, 
	/* 0x30 */ 0x0005, 0x8000, 0x0002, 0x0002, 0x000A, 0x028D, 0x8000, 0x0008, 0x0007, 0x0009, 0x8000, 0x8000, 0x8000, 0x0002, 0x0025, 0x8000, 
	/* 0x40 */ 0x00C9, 0x8000, 0x8000, 0x0229, 0x02C9, 0x0005, 0x8000, 0x000B, 0x0049, 0x005D, 0x0005, 0x0009, 0x8000, 0x8000, 0x0006, 0x0002, 
	/* 0x50 */ 0x8000, 0x8000, 0x8000, 0x0002, 0x000C, 0x0001, 0x000B, 0x006E, 0x006A, 0x8000, 0x8000, 0x0004, 0x0002, 0x0049, 0x8000, 0x0031, 
	/* 0x60 */ 0x0005, 0x0009, 0x000F, 0x000D, 0x0001, 0x0004, 0x8000, 0x0015, 0x8000, 0x8000, 0x0003, 0x0009, 0x0013, 0x0003, 0x000E, 0x8000, 
	/* 0x70 */ 0x001C, 0x8000, 0x0005, 0x0002, 0x8000, 0x0023, 0x0010, 0x0011, 0x8000, 0x0009, 0x8000, 0x0002, 0x8000, 0x000D, 0x0002, 0x8000, 
	/* 0x80 */ 0x003E, 0x8000, 0x0002, 0x0027, 0x0045, 0x0002, 0x8000, 0x8000, 0x0042, 0x8000, 0x8000, 0x8000, 0x000B, 0x8000, 0x8000, 0x8000, 
	/* 0x90 */ 0x0013, 0x0041, 0x8000, 0x0063, 0x8000, 0x0009, 0x8000, 0x0002, 0x8000, 0x001E, 0x8000, 0x0102, 0x0135, 0x0033, 0x8000, 0x8000, 
	/* 0xa0 */ 0x0003, 0x0009, 0x0009, 0x0009, 0x0095, 0x8000, 0x8000, 0x0004, 0x8000, 0x8000, 0x0005, 0x8000, 0x8000, 0x8000, 0x8000, 0x000D, 
	/* 0xb0 */ 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x0040, 0x0009, 0x8000, 0x8000, 0x0005, 0x000A, 0x0009, 0x0003, 0x8000, 0x8000, 0x8000, 
	/* 0xc0 */ 0x0024, 0x8000, 0x8000, 0x8000, 0x0006, 0x00CB, 0x0001, 0x0031, 0x0002, 0x0006, 0x0006, 0x0007, 0x8000, 0x0001, 0x8000, 0x004E, 
	/* 0xd0 */ 0x8000, 0x0002, 0x0019, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x010C, 0x8000, 0x8000, 0x0009, 0x8000, 0x8000, 0x8000, 
	/* 0xe0 */ 0x8000, 0x8000, 0x000A, 0x8000, 0x8000, 0x8000, 0x0005, 0x000C, 0x000D, 0x004B, 0x0003, 0x8000, 0x8000, 0x8000, 0x2000, 0x2000, 
	/* 0xf0 */ 0x8000, 0x0009, 0x0019, 0x001A, 0x8000, 0x0015, 0x8000, 0x8000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};

int GetPacketID(PBYTE buf)
{
	return buf[0]&0xff;
}

BOOL StartSniffy(DEBUG_EVENT *dbgev, ClientEntry *Client)
{
	DWORD readb;
	int i=0;

	Client->DateStamp = GetTimeStamp(dbgev->u.CreateProcessInfo.hFile);
	Client->BaseAddress = dbgev->u.CreateProcessInfo.lpBaseOfImage;
	Client->Size = GetFileSize(dbgev->u.CreateProcessInfo.hFile, 0);
	Client->Image = (PBYTE)malloc(Client->Size);
	SetFilePointer(dbgev->u.CreateProcessInfo.hFile, 0, 0, FILE_BEGIN);
	if(!ReadFile(dbgev->u.CreateProcessInfo.hFile, Client->Image, Client->Size, &readb, NULL))
		{ free(Client->Image); return 0; }

	//NumOut("ds: %X size: %X base: %X read: %X", Client->DateStamp, Client->Size, Client->BaseAddress, readb);

	if(!FindBpxPositions(Client))
		return 0;
	FindVersion(Client);

	free(Client->Image);
	return 1;
}

/*
Olly organizes as: EAX ECX EDX EBX ESP EBP ESI EDI
UOLog: EAX=1, EBX=2, ECX=3, EDX=4, ESI=5, EDI=6, EBP=7
*/

void HandleFirstSend(CONTEXT *context, int type)
{
	// check register for the 0x80
	// this is why this wont work with attaching :)
	int pktid, pktlen, i, j, res;
	DWORD read;
	PBYTE pointer;
	BYTE buf[65536];

	if(type == TYPE_SEND)
		AppendLogWindow(Options.PacketLog, "Sniffy - handle send\n");
	else
		AppendLogWindow(Options.PacketLog, "Sniffy - handle recv\n");

	if(has_first_recv && has_first_send)
		AppendLogWindow(Options.PacketLog, "Sniffy - Weird...\n");

	// all registers, EAX(1) to EBP(7)
	for(i=1; i<8+16; i++)
	{
		pointer = (void*)(LRESULT)GetRegisterContent(Client.Process, context, i);

		// if we can't read it, this register isnt the one with the packet buffer
		if(!ReadProcessMemory(Client.Process, pointer, buf, 1, &read))
			continue;

		// Expect Login Request packet on SEND
		if(type == TYPE_SEND && GetPacketID(buf) != 0x80)
			continue;

		// Expect Game Server List or Login Denied packet on RECV
		if(type == TYPE_RECV && (GetPacketID(buf) != 0xA8 || GetPacketID(buf) != 0x82))
			continue;

		pktlen = pktlen_table[GetPacketID(buf)];
		// if the packet doesn't exist (as far as we know)
		// we can't check it, can we hun? ^@
		if(!pktlen)
			continue;

		// means we gotta grab 2 more bytes
		if(pktlen == 0x8000)
		{
			if(!ReadProcessMemory(Client.Process, pointer, buf, 3, &read))
				continue;
			if(type == TYPE_RECV)
				pktlen = *(unsigned short*)&buf[1];
			else if(type == TYPE_SEND)
				pktlen = ((unsigned int)buf[1] << 8) | (unsigned int)buf[2];
		}

		// yeah right...
		if(pktlen > 0x8000 || pktlen < 1)
			continue;
		else
			if(!ReadProcessMemory(Client.Process, pointer, buf, pktlen, &read))
				continue;

		// try to find this packetlen in the registers
		// if found, means we have both the regbuf and reglen :)
		// if not, KEEP SEARCHIIIING! This search goes on... This Search goes on...
        for(j=1; j<8+16; j++)
		{
			int reg_pktlen = GetRegisterContent(Client.Process, context, j);

			if(reg_pktlen != pktlen)
				continue;

			if(type == TYPE_RECV)
			{
				Client.RegBufRecv = i;
				Client.RegLenRecv = j;
				AppendLogWindow(Options.PacketLog, TimeStamp("Sniffy - Recv buf: %d len: %d\n", i, j));
				has_first_recv = 1;
				return;
			}
			else if(type == TYPE_SEND)
			{
				Client.RegBufSend = i;
				Client.RegLenSend = j;
				AppendLogWindow(Options.PacketLog, TimeStamp("Sniffy - Send buf: %d len: %d\n", i, j));
				has_first_send = 1;
				return;
			}
		}
	}

	// ERROR?

	return;
}

void HandleFirstRecv(CONTEXT *context)
{
	AppendLogWindow(Options.PacketLog, "Sniffy - handle recv\n");
	has_first_recv = 1;

	return;
}

int FindBpxPositions(ClientEntry *Client)
{
	// find Send (0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x8F)
	BYTE crypt_id[8] = { 0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x8F };
	BYTE crypt_id_new[7] = { 0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x7F };
	// find Recv at the jmp to make sure it catches everything
	BYTE mov_arg1_id[4] = {0x00, 0x8B, 0x74, 0x24};
	BYTE recv_id[10] = {0x83, 0xC0, 0xF2, 0x3D, 0xCC, 0x00, 0x00, 0x00, 0x0F, 0x87};
	BYTE log[256];
	DWORD crypt_addr=0, mov_arg1_addr=0, recv_addr=0;

	crypt_addr = FleXSearch(crypt_id, Client->Image, 8, Client->Size, 0, 0xCC, 1);
	if(crypt_addr == -1)
		crypt_addr = FleXSearch(crypt_id_new, Client->Image, 7, Client->Size, 0, 0xCC, 1);
	if(crypt_addr == -1)
	{
		AppendLogWindow(Options.PacketLog, "Sniffy - Could not find send\n");
		AppendLogWindow(Options.PacketLog, "Sniffy - UOLog does not work with godclient or non-OSI clients\n");
		Client->Send = 0; Client->Recv = 0;
		return 0;
	}
	crypt_addr -= (int)Client->Image;
	crypt_addr += Client->BaseAddress;

	recv_addr = FleXSearch(recv_id, Client->Image, 10, Client->Size, 0, 0xCC, 1);
	mov_arg1_addr = FleXSearch(mov_arg1_id, Client->Image, 4, Client->Size, recv_addr - (int)Client->Image - 0x40, 0xCC, 1);
	if(recv_addr == 1 || mov_arg1_addr == -1)
	{
		AppendLogWindow(Options.PacketLog, "Sniffy - Could not find recv\n");
		AppendLogWindow(Options.PacketLog, "Sniffy - UOLog does not work with godclient or non-OSI clients\n");
		Client->Send = 0; Client->Recv = 0;
		return 0;
	}
	recv_addr = mov_arg1_addr + 1;
	recv_addr -= (int)Client->Image;
	recv_addr += Client->BaseAddress;

	AppendLogWindow(Options.PacketLog, TimeStamp("Sniffy - Send: %X Recv: %X\n", crypt_addr, recv_addr));

	Client->Send = crypt_addr;
	Client->Recv = recv_addr;
	return 1;
}

void FindVersion(ClientEntry *Client)
{
	DWORD name_addr = FleXSearch("1.25.", Client->Image, 5, Client->Size, 0, 0xCC, 1);
	if(name_addr == -1)
		name_addr = FleXSearch("1.26.", Client->Image, 5, Client->Size, 0, 0xCC, 1);
	if(name_addr == -1)
		name_addr = FleXSearch("2.0.", Client->Image, 4, Client->Size, 0, 0xCC, 1);

	if(name_addr != -1)
		strcpy(Client->Version, (void*)name_addr);
	else
	{
		int first_id=0, middle_id=0, third_id=0, fourth_id=0;
		BOOL new_version = FALSE;
		DWORD push_addr=0, version_addr=0;
		PBYTE str_id=0;
		BYTE version_push[5] = { 0x68, 0x00, 0x00, 0x00, 0x00 };

		version_addr = FleXSearch("%d.%d.%d%s", (PBYTE)Client->Image, 11, Client->Size, 0, 0xCC, 1);
		if(version_addr == -1)
		{
			version_addr = FleXSearch("%d.%d.%d.%d", (PBYTE)Client->Image, 12, Client->Size, 0, 0xCC, 1);
			if(version_addr == -1)
			{
				strcpy(Client->Version, "Unknown - version address not found\n");
				return;
			}
			new_version = TRUE;
		}

		version_addr -= (int)Client->Image;
		version_addr += Client->BaseAddress;

		memcpy(&version_push[1], &version_addr, 4);
		push_addr = FleXSearch(version_push, Client->Image, 5, Client->Size, 0, 0xCC, 1);

		if(push_addr == -1)
		{
			strcpy(Client->Version, "Unknown - push address not found\n");
			return;
		}

		// copy the Xa.Xb.Xc
		memcpy(&first_id, (void*)(push_addr-1), 1);
		memcpy(&middle_id, (void*)(push_addr-3), 1);
		memcpy(&third_id, (void*)(push_addr-5), 1);
		if(new_version)
			memcpy(&fourth_id, (void*)(push_addr-7), 1);
		// copy the string's offset to str_id
		// and format it to be found in ClientBuf
		if(new_version == FALSE)
		{
			memcpy(&str_id, (void*)(push_addr-10), 4);
			str_id -= Client->BaseAddress;
			str_id += (int)Client->Image;
		}

		if(new_version == FALSE)
			sprintf(Client->Version, "%d.%d.%d%s", first_id, middle_id, third_id, str_id);
		else
			sprintf(Client->Version, "%d.%d.%d.%d", first_id, middle_id, third_id, fourth_id);
	}

	return;
}


// This function returns the start position of
// a positive match between src and buf.
// count is the found matches count.
// if the flex byte is in the buffer, the position
// in src will be ignored and it skips the check.
// Important: it returns the position IN MEMORY
// so if you need the position inside src, remember to do:
// int match_position = FleXSearch(yadda yadda) - (int)buf;
// Returns: 0 if no match was found. The offset of buf+found_match_position
// src -> Searched inside of buf.
// buf -> Well, src has to be found somewhere...
// src_size -> Size in bytes of src (has to be smaller than buf_size... duh)
// buf_size -> Size in bytes of buf (bigger than src_size...)
// flex_byte -> If this byte is found in src, the position will not be compared,
// skips to the next byte
// which -> Found match. If the user wants the 1st match, this is set to 1.
DWORD FleXSearch(PBYTE src, PBYTE buf, DWORD src_size, DWORD buf_size, DWORD start_at, BYTE flex_byte, int which)
{
	unsigned int count=0, i=0, j=0;
	// classical user's error
	if(!which || !src_size || !buf_size)
		return 0;
	for(i=buf+start_at; i<buf_size+(int)buf; i++)
	{
		for(j=0; j<src_size; j++)
		{
			// if its the flex byte, just skip it
			if(src[j] == (BYTE)flex_byte && j != (src_size - 1))
				continue;
			else if(src[j] == (BYTE)flex_byte && j == (src_size - 1))
			{ // in case the flex byte is the last in the comparison buffer
				count++;
				if(count == which)
					return i;
			}

			// if there's a difference, stop checking
			if(src[j] != (*(PBYTE)(i+j)))
				break;

			// if the comparison string is over and it's all equal
			// check for the found matches count
			if(j == (src_size - 1))
			{
				count++;
				if(count == which)
					return i;
			}
		}
	}

	//if it got this far, then couldnt find it
	return -1;
}