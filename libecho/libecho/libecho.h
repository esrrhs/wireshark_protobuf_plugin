#pragma once

extern "C" int get_port();
extern "C" void ini_msg();
extern "C" const char * get_msg_name(int id);
extern "C" const char * show_msg(int id, const char * data, int srclen);

