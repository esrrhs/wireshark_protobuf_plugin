#include "libecho.h"
#include <stdio.h>
#include <time.h>
#include <iostream>
#include <vector>
#include <iostream>
#include "config.h"
#include <stdarg.h>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/compiler/importer.h>

using namespace std;
using namespace google::protobuf;
using namespace google::protobuf::compiler;

#define MYLOG(...) MyLog(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);

void MyLog(const char * file, const char * func, int pos, const char *fmt, ...)
{
	FILE *pLog = NULL;
	time_t clock1;
	struct tm * tptr;
	va_list ap;

	pLog = fopen("evil.log", "a+");
	if (pLog == NULL)
	{
		return;
	}

	clock1 = time(0);
	tptr = localtime(&clock1);

	fprintf(pLog, "===========================[%d.%d.%d, %d.%d.%d]%s:%d,%s:===========================\n",
		tptr->tm_year + 1990, tptr->tm_mon + 1,
		tptr->tm_mday, tptr->tm_hour, tptr->tm_min,
		tptr->tm_sec, file, pos, func);

	va_start(ap, fmt);
	vfprintf(pLog, fmt, ap);
	fprintf(pLog, "\n\n");
	va_end(ap);

	fclose(pLog);
}

CMsgLoader g_config;
std::map<int, std::string> g_msgMap;
std::string g_str;
Importer * g_importer;

extern "C" void ini_msg()
{
	if (!g_config.LoadCfg("config.xml"))
	{
		MYLOG("LoadCfg fail");
		exit(0);
	}

	std::string protoname = g_config.GetMsg().m_STConfig.m_strproto;

	DiskSourceTree sourceTree;
	//look up .proto file in current directory
	sourceTree.MapPath("", "./");
	g_importer = new Importer(&sourceTree, NULL);
	Importer & importer = *g_importer;

	//runtime compile foo.proto
	const FileDescriptor* fd = importer.Import(protoname);
	if (!fd)
	{
		MYLOG("Import %s fail", protoname.c_str());
		exit(0);
	}

	for (int i = 0; i < g_config.GetMsg().m_vecSTMsgId.size(); i++)
	{
		int id = g_config.GetMsg().m_vecSTMsgId[i].m_iid;
		std::string name = g_config.GetMsg().m_vecSTMsgId[i].m_strname;

		const Descriptor *descriptor = importer.pool()->FindMessageTypeByName("ntesgame." + name);
		if (!descriptor)
		{
			MYLOG("FindMessageTypeByName %s fail", name.c_str());
			exit(0);
		}

		// build a dynamic message by "Pair" proto
		DynamicMessageFactory factory;
		const Message *message = factory.GetPrototype(descriptor);
		if (!message)
		{
			MYLOG("GetPrototype %s fail", name.c_str());
			exit(0);
		}

		g_msgMap[id] = name;
		Message * tmp = message->New();
		delete tmp;
	}

	MYLOG("ini_msg ok");
}

extern "C" const char * get_msg_name(int id)
{
	if (g_msgMap.find(id) != g_msgMap.end())
	{
		g_str = g_msgMap[id];
		return g_str.c_str();
	}
	return "unknow";
}

extern "C" const char * show_msg(int id, const char * data, int srclen)
{
	if (g_msgMap.find(id) == g_msgMap.end())
	{
		return "no such msg id";
	}

	std::string name = g_msgMap[id];

	Importer & importer = *g_importer;
	const Descriptor *descriptor = importer.pool()->FindMessageTypeByName("ntesgame." + name);
	if (!descriptor)
	{
		return "FindMessageTypeByName fail";
	}

	// build a dynamic message by "Pair" proto
	DynamicMessageFactory factory;
	const Message *message = factory.GetPrototype(descriptor);
	if (!message)
	{
		return "GetPrototype fail";
	}

	Message * msg = message->New();

	if (!msg->ParseFromArray(data, srclen))
	{
		return "ParseFromArray fail";
	}

	g_str = msg->Utf8DebugString();

	delete msg;

	return g_str.c_str();
}

extern "C" int get_port()
{
	return g_config.GetMsg().m_STConfig.m_iport;
}
