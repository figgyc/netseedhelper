#include <3ds.h>
#include <stdio.h>
#include <iostream>

#include <string>
#include <sstream>
#include <list>
#include <ctime>

#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <fcntl.h>

#include "http.h"
#include "httpc.h"
#include "libs.h"
#include "utils.h"

static Handle frdHandle;
static int frdRefCount;
static Handle s_terminate;

Result frdInit(void)
{
	Result ret = 0;

	if (AtomicPostIncrement(&frdRefCount))
		return 0;

	ret = srvGetServiceHandle(&frdHandle, "frd:a");

	if (R_FAILED(ret))
		AtomicDecrement(&frdRefCount);

	return ret;
}

void frdExit(void)
{
	if (AtomicDecrement(&frdRefCount))
		return;

	svcCloseHandle(frdHandle);
}

Result FRD_FriendCodeToPrincipalId(u64 friendCode, u32 *principalId)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x25, 2, 0); // 0x00250080
	cmdbuf[1] = (u32)(friendCode & 0xFFFFFFFF);
	cmdbuf[2] = (u32)(friendCode >> 32);

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	*principalId = cmdbuf[2];

	return cmdbuf[1];
}

typedef struct
{
	u32 principal_id;
	u32 padding;
	u64 local_friend_code;
} frd_key;

Result FRD_GetMyFriendKey(frd_key *key)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x05, 0, 0); // 0x00050000

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	memcpy(key, &cmdbuf[2], sizeof(frd_key));

	return (Result)cmdbuf[1];
}

Result FRD_RemoveFriend(u32 principal_id, u64 local_friend_code)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = 0x4090100;
	cmdbuf[1] = principal_id;
	cmdbuf[2] = local_friend_code & 0xffffffff;
	cmdbuf[3] = (local_friend_code >> 32) & 0xffffffff;

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	return cmdbuf[1];
}

Result FRD_IsValidFriendCode(u64 friendCode, bool *isValid)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x26, 2, 0); // 0x00260080
	cmdbuf[1] = (u32)(friendCode & 0xFFFFFFFF);
	cmdbuf[2] = (u32)(friendCode >> 32);

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	*isValid = cmdbuf[2] & 0xFF;

	return cmdbuf[1];
}

Result FRD_PrincipalIdToFriendCode(u32 principalId, u64 *friendCode)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = IPC_MakeHeader(0x24, 1, 0); // 0x00240040
	cmdbuf[1] = principalId;

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	*friendCode = (((u64)cmdbuf[3]) << 32 | (u64)cmdbuf[2]);

	return cmdbuf[1];
}

typedef enum {
	self_online = 1,
	self_offline,
	friend_online,
	friend_presence,
	friend_mii,
	friend_profile,
	friend_offline,
	friend_became_friend,
	friend_invitaton
} friend_notif_types;

typedef struct
{
	u8 type;
	u8 padding3[3];
	u32 padding;
	frd_key key;
} friend_notif_event;

typedef struct
{
	u64 local_friend_code;
	u64 friend_code;
} friend_things;
std::list<friend_things> friendsToProcess;

typedef struct {
	u64 friend_code;
	std::time_t timeAdded;
} friend_process;
std::list<friend_process> friendsToKill;

Result FRD_GetEventNotification(friend_notif_event *event, size_t size, u32 *recieved_notif_count)
{
	Result ret = 0;

	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = 0x220040;
	cmdbuf[1] = (u32)size;

	u32 *staticbuf = getThreadStaticBuffers();
	staticbuf[0] = 0x60000 * size | 2;
	staticbuf[1] = (u32)event;

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	*recieved_notif_count = cmdbuf[3];

	return (Result)cmdbuf[1];
}

Result FRD_addFriendOnline(Handle event, u32 principal_id)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = 0x4060042;
	cmdbuf[1] = principal_id;
	cmdbuf[2] = 0;
	cmdbuf[3] = (u32)event;

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	return (Result)cmdbuf[1];
}

Result FRD_AttachToEventNotification(Handle event)
{
	Result ret = 0;
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = 0x200002;
	cmdbuf[1] = 0;
	cmdbuf[2] = (u32)event;

	if (R_FAILED(ret = svcSendSyncRequest(frdHandle)))
		return ret;

	return (Result)cmdbuf[1];
}

void HandleFriendNotification(friend_notif_event *event)
{
	switch (event->type)
	{
	case friend_became_friend:
	{
		printf("registered %lx as a friend\n", event->key.principal_id);
		// TODO: dump lfcs and upload
		u64 lfcs = event->key.local_friend_code & 0xFFFFFFFFFFLL;
		printf("lfcs: %0llx\n", lfcs);
		printf("lfc: %0llx\n", event->key.local_friend_code);
		u64 friendCode;
		FRD_PrincipalIdToFriendCode(event->key.principal_id, &friendCode);
		FRD_RemoveFriend(event->key.principal_id, event->key.local_friend_code);
		friend_things thisFriend;
		thisFriend.friend_code = friendCode;
		thisFriend.local_friend_code = event->key.local_friend_code;
		friendsToProcess.push_back(thisFriend);
		printf("added 2 upload Q and removed");
		friendsToKill.remove_if([&friendCode](friend_process n){ return n.friend_code == friendCode; });
	}
	break;

	default:
		printf("notification %d recieved for %lx", event->type, event->key.principal_id);
		break;
	}
}

void FriendNotificationHandlerThread(void *n)
{
	printf("HandlerThreadCreated()\n");
	Handle friendsEvent;
	svcCreateEvent(&friendsEvent, RESET_ONESHOT);

	Result res = FRD_AttachToEventNotification(friendsEvent);
	if (res != 0)
		printf("Error in AttachingEventHandle %08lX", res);
	s32 out;
	Handle frd_handles[] = {friendsEvent, s_terminate};
	bool run = true;

	friend_notif_event events[10];
	//size_t event_list_size = 10;
	while (run)
	{
		svcWaitSynchronizationN(&out, frd_handles, 2, false, U64_MAX);
		//printf("out %d\n", out);
		switch (out)
		{
		case 0:
		{
			size_t size = 0;
			do
			{
				res = FRD_GetEventNotification(events, 10, (u32 *)&size);
				printf("GetEventNotification %08lX\n", res);

				for (u64 i = 0; i < size; ++i)
				{
					HandleFriendNotification(events + i);
				}

			} while (size != 0);
			break;
		}
		case 1:
			run = false;
			break;
		}
	}
	svcClearEvent(s_terminate);
	printf("Deinitialization finished\n");
}

int main(void)
{
	gfxInitDefault();
	logInit("/seed.log");
	extern HTTPC httpc;
	httpc.Init(0x4000);
	consoleInit(GFX_TOP, NULL);
	Result res = frdInit();
	printf("frdinit: %08lX\n", res);
	//u64 frd_code;
	bool pid;
	u32 pid_2;
	bool alternator = false;

	Handle event;
	svcCreateEvent(&event, RESET_ONESHOT);
	svcCreateEvent(&s_terminate, RESET_ONESHOT);
	printf("Going To init thread\n");
	Thread thread = threadCreate(FriendNotificationHandlerThread, NULL, 4096 * 2, 0x24, 0, true);
	printf("Press A to continue\n");
	svcSleepThread(5 * 1e9);
	// anti burn in measures
	//GSPGPU_SetLcdForceBlack(1);
	GSPLCD_PowerOffAllBacklights();
	GSPLCD_SetBrightnessRaw(GSPLCD_SCREEN_BOTH, 0);
	aptSetSleepAllowed(false);

	while (aptMainLoop())
	{

		/*
			TODO: add httpc retrieval for this
			swkbdInit(&swkbd, SWKBD_TYPE_NORMAL, 3, -1);
			swkbdSetHintText(&swkbd, "Please enter a friend-code without \"-\" ");
			swkbdInputText(&swkbd, mybuf, sizeof(mybuf));
			sscanf(mybuf,"%lld", &frd_code); 
			printf("frd_code %lld\n", frd_code);*/
		//frd_code = 319677776123;
		//frd_code = 401256349967;
		alternator = !alternator;
		u8 *dlBuf1 = nullptr;
		u32 outputSize = 0;
		const char *url = "https://seedhelper.figgyc.uk/getfcs";
		printf("%s\n", url);
		try
		{
			httpGet(url, &dlBuf1, &outputSize);
		}
		catch (std::runtime_error &e)
		{
			std::cout << e.what();
		}
		//printf("done\n");
		std::string tmpstr;
		if (dlBuf1 != NULL) {
			tmpstr = std::string(reinterpret_cast<char const *>(dlBuf1), outputSize); // length optional, but needed if there may be zero's in your data			
		} else {
			tmpstr = "nothing";
		}

		if (tmpstr == "nothing")
		{
			printf("waiting...%d\n", alternator);
			gfxFlushBuffers();
			gfxSwapBuffers();
			svcSleepThread(5 * 1e9);
			//consoleClear();
			//printf("wait finished \n");
		}
		else
		{
			printf("processing");
			std::istringstream is(tmpstr);
			std::string line;
			while (getline(is, line))
			{
				// process line
				if (line == "")
				{
					break;
				}
				char fc[line.length() + 1];
				strcpy(fc, line.c_str());
				u64 fcInt;
				sscanf(fc, "%lld", &fcInt);
				printf("exo %s, %lld\n", fc, fcInt);
				/*printf("FRD_FriendCodeIsValid() %08lX \n", */ FRD_IsValidFriendCode(fcInt, &pid); //);
				printf("fc is valid: %s\n", (pid == 1) ? "True" : "False");
				if (pid == 1)
				{
					/*printf("FRD_FriendCodeToPrincipalId() %08lx\n", */ FRD_FriendCodeToPrincipalId(fcInt, &pid_2); //);
					/*printf("FRD_addFriend() %08lx\n", */ FRD_addFriendOnline(event, pid_2);						 //);
					friend_process theDude;
					theDude.friend_code = fcInt;
					theDude.timeAdded = std::time(nullptr);
					friendsToKill.push_back(theDude);
					char url[128];																					 // should be 61 max in theory (url is 40, 12 fc, 8 lfcs, 1 nullbyte) but lets be safe
					sprintf(url, "https://seedhelper.figgyc.uk/added/%s", fc);
					printf("%s\n", url);
					u8 *dlBuf = nullptr;
					u32 outputSize = 0;
					//httpGet(url, &dlBuf, &outputSize);
					try
					{
						httpGet(url, &dlBuf, &outputSize);
					}
					catch (std::runtime_error &e)
					{
						std::cout << e.what() << std::endl;
					} //*/
					  // printf("%s\n", dlBuf);
					if (dlBuf != NULL) free(dlBuf);					  
				}
			}
			svcSleepThread(10 * 1e9);
		}

		//printf("%s", dlBuf);
		//FILE *file = fopen("_test_", "wb+");
		//fwrite(dlBuf, outputSize, 1, file);
		//fclose(file);
		while (friendsToProcess.size() > 0)
		{
			friend_things friendThing = friendsToProcess.front();
			char url[256]; // should be 61 max in theory (url is 40, 12 fc, 8 lfcs, 1 nullbyte) but lets be safe
			sprintf(url, "http://seedhelper.figgyc.uk/lfcs/%lld?lfcs=%016llx", friendThing.friend_code, friendThing.local_friend_code);
			printf("%s\n", url);
			u8 *dlBuf = nullptr;
			u32 outputSize = 0;
			//httpGet(url, &dlBuf, &outputSize);
			try
			{
				httpGet(url, &dlBuf, &outputSize);
			}
			catch (std::runtime_error &e)
			{
				std::cout << e.what() << std::endl;
				FILE *fp = fopen("log.txt", "wb");
				fprintf(fp, e.what(), 256);
				fwrite(dlBuf, sizeof dlBuf[0], outputSize, fp);
				fclose(fp);
			} //*/
			printf("uploaded lfcs to database");
			friendsToProcess.pop_front();
			//delete &friendThing;
			if (dlBuf != NULL) free(dlBuf);					  
		}
		for (std::list<friend_process>::iterator it = friendsToKill.begin(); it != friendsToKill.end(); ++it) {
			if (std::difftime(std::time(nullptr), it->timeAdded) > 600) {
				u32 principalId;
				FRD_FriendCodeToPrincipalId(it->friend_code, &principalId);
				Result result = FRD_RemoveFriend(principalId, it->friend_code);
				if (result != 0) {
					printf("Friend removal error %ld", result);
				} else {
					printf("Friend expired and removed successfully");
				}
				friendsToKill.erase(it);
				//delete &*it;
			}
		}
		if (dlBuf1 != NULL) free(dlBuf1);
		hidScanInput();
		if (keysDown() & KEY_X) {
			printf("Wrote nonzero to initsetup config save");
			u32 cfgData = 0x08007FF4; // idk if the val matters but 2dsaver uses this
			CFG_SetConfigInfoBlk4(4, 0x00110000, (u8*)&cfgData);
			CFG_UpdateConfigSavegame();
		}
		if (keysDown() & KEY_Y) {
			printf("Wrote zero to initsetup config save");
			u32 cfgData = 0x00000000;
			CFG_SetConfigInfoBlk4(4, 0x00110000, (u8*)&cfgData);
			CFG_UpdateConfigSavegame();
		}
		if (keysDown() & KEY_START)
		{
			break;
		}
	}

	gfxFlushBuffers();
	gfxSwapBuffers();
	printf("Going to signal Thread");
	svcSignalEvent(s_terminate);
	threadJoin(thread, U64_MAX);
	svcCloseHandle(s_terminate);
	GSPLCD_PowerOnAllBacklights();
	aptSetSleepAllowed(true);
	frdExit();
	httpc.Exit();
	gfxExit();
	return 0;
}
