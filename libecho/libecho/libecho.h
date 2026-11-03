#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int get_port(void);
void ini_msg(void);
const char * get_msg_name(int id);
const char * show_msg(int id, const char * data, int srclen);

#ifdef __cplusplus
}
#endif
