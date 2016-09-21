#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
#include "packet-evil.h"

static int proto_evil = -1;

/* Initialize the protocol and registered fields */
static int hf_evil_hdr_msg_packetid = -1;
static int hf_evil_hdr_msg_packetname = -1;
static int hf_evil_hdr_msg_datasize = -1;
static int hf_evil_hdr_msg_body = -1;

/* Initialize the subtree pointers */
static gint ett_evil = -1;

/* Preferences */
static guint evil_tcp_port = 0;

#define evil_buffer_size 102400
static char evil_buffer[evil_buffer_size];

#define MYLOG(...) MyLog(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);

void MyLog(const char * file, const char * func, int pos, const char *fmt, ...)
{
	FILE *pLog = NULL;
	time_t clock1;
	struct tm * tptr;
	va_list ap;
	
	pLog = fopen("evil_myname.log", "a+");
	if (pLog == NULL)
	{
		return;
	}
	
	clock1 = time(0);
	tptr = localtime(&clock1);

	fprintf(pLog, "===========================[%d.%d.%d, %d.%d.%d]%s:%d,%s:===========================\n", 
		tptr->tm_year+1990,tptr->tm_mon+1,
		tptr->tm_mday,tptr->tm_hour,tptr->tm_min,
		tptr->tm_sec,file,pos,func);

	va_start(ap, fmt);
	vfprintf(pLog, fmt, ap);
	fprintf(pLog, "\n\n");
	va_end(ap);

	fclose(pLog);
}

#define FRAME_HEADER_LEN 6
#define FRAME_HEADER_SIZE_POS 0

#define mypntoh16(p)  ((guint32)*((const guint8 *)(p)+0)<<8|  \
                     (guint32)*((const guint8 *)(p)+1)<<0)

#define mypntoh32(p)  ((guint32)*((const guint8 *)(p)+0)<<24|  \
                     (guint32)*((const guint8 *)(p)+1)<<16|  \
                     (guint32)*((const guint8 *)(p)+2)<<8|   \
                     (guint32)*((const guint8 *)(p)+3)<<0)

/* This method dissects fully reassembled messages */
static int dissect_evil_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;//偏移变量，记录偏移位置
    int ret = 0;
    proto_item * ti = NULL;//方便添加结点而定义
    proto_tree * tt = NULL; //方便添加结点而定义
    int size = 0;
    char * p = NULL;
    int packet_size = 0;
    const guint8* buffer = 0;
    int buffersize = 0;
	char strbuf[100];
	int headvalue = 0;
	int packid = 0;
	int datasize = 0;
	int seed = 0;
	int checksum = 0;
	int compresssize = 0;
	const char * pbody = 0;
    
    MYLOG("!!!!!!!!!!!!!!!!! dissect_evil_message start !!!!!!!!!!!!!!!!!");

    MYLOG("tvb_reported_length %d tvb_reported_length %d", tvb_reported_length(tvb), tvb_reported_length(tvb));
    	
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "myname");//显示协议
    col_clear(pinfo->cinfo, COL_INFO);

    if (!tree) 
    {
        return tvb_reported_length(tvb);
    } 

    ti = proto_tree_add_item(tree, proto_evil, tvb, 0, -1, FALSE);//添加结点
    tt = proto_item_add_subtree(ti, ett_evil);//添加子树，用以显示数据
    
    buffer = tvb_get_ptr(tvb, 0, -1);
    buffersize = tvb_reported_length(tvb);
    MYLOG("tvb buffer %d %p", buffersize, buffer);

	// 加节点
    offset = 0;

	size = sizeof(int);
	datasize = *(const int *)(&buffer[offset]);
	datasize = mypntoh32(&datasize);
	proto_tree_add_int(tt, hf_evil_hdr_msg_datasize, tvb, offset, size, datasize);
	offset += size; 

    size = sizeof(short);
	packid = *(const short *)(&buffer[offset]);
	packid = mypntoh16(&packid);
	sprintf(strbuf, "%s", get_msg_name(packid));
    proto_tree_add_int(tt, hf_evil_hdr_msg_packetid, tvb, offset, size, packid);
    proto_tree_add_string(tt, hf_evil_hdr_msg_packetname, tvb, offset, size, strbuf);
    offset += size;
	
	pbody = show_msg(packid, &buffer[offset], datasize - sizeof(short));
	size = buffersize - FRAME_HEADER_LEN + sizeof(short);
	p = strtok(pbody, "\n");	  
	while(p)	   
	{ 	   
    	proto_tree_add_string(tt, hf_evil_hdr_msg_body, tvb, offset, size, p); 
		p = strtok(NULL, "\n");	
	}
	
    MYLOG("dissect_evil ok");

    return tvb_reported_length(tvb);
}

/* determine PDU length of protocol foo */
static guint get_evil_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    // length is at offset FRAME_HEADER_SIZE_POS    
    guint len = 0; 
    len = (guint)tvb_get_ntohl(tvb, offset + FRAME_HEADER_SIZE_POS);
    MYLOG("get_evil_message_len src len %d", (int)len);
    len = len + FRAME_HEADER_LEN - sizeof(short);
    MYLOG("get_evil_message_len len %d", (int)len);
    return len; 
}

/* The main dissecting routine */
static int dissect_evil(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                     get_evil_message_len, dissect_evil_message, 0);
    return tvb_reported_length(tvb);
}

void
proto_register_evil(void)
{
    module_t *evil_module;

    static hf_register_info hf[] = {
            {
                &hf_evil_hdr_msg_packetid,
                {
                    "Packet Id",
                    "myname.packetid",
                    FT_INT32,
                    BASE_DEC,
                    NULL,
                    0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_evil_hdr_msg_packetname,
                {
                    "Packet Name",
                    "myname.packetname",
                    FT_STRING,
                    BASE_NONE,
                    NULL,
                    0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_evil_hdr_msg_datasize,
                {
                    "Msg Data Size",
                    "myname.datasize",
                    FT_INT32,
                    BASE_DEC,
                    NULL,
                    0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_evil_hdr_msg_body,
                {
                    "Msg Body",
                    "myname.msgbody",
                    FT_STRING,
                    BASE_NONE,
                    NULL,
                    0,
                    NULL,
                    HFILL
                }
            },
		};
			
        /* Protocol subtree array */
    static gint *ett[] = {
        &ett_evil,
    };

    MYLOG("!!!!!!!!!!!!!!!!! evil start !!!!!!!!!!!!!!!!!");

	MYLOG("proto_register_evil");

    /* Register the protocol name and description */
    proto_evil = proto_register_protocol(
        "myname",
        "myname",
        "myname");

	MYLOG("proto_register_protocol proto_evil = %d", proto_evil);

    /* Required function calls to register the header fields and subtrees
     * used */
    proto_register_field_array(proto_evil, hf, array_length(hf));
	MYLOG("proto_register_field_array");
    proto_register_subtree_array(ett, array_length(ett));
	MYLOG("proto_register_subtree_array");
	
    /* Register preferences module (See Section 2.6 for more on
     * preferences) */
    evil_module = prefs_register_protocol(
        proto_evil,
        proto_reg_handoff_evil);

	MYLOG("prefs_register_protocol evil_module = %d", evil_module);
	
    MYLOG("proto_register_evil ok");
}

void
proto_reg_handoff_evil(void)
{
    dissector_handle_t evil_handle;
    FILE * portfp = NULL; 

	ini_msg(); 
    
    evil_handle = create_dissector_handle(dissect_evil, proto_evil);
	MYLOG("create_dissector_handle evil_handle = %p", evil_handle);

	int port = get_port();
	MYLOG("port=%d", port);

    dissector_add_uint("tcp.port", port, evil_handle);

	MYLOG("proto_reg_handoff_evil ok");
}
