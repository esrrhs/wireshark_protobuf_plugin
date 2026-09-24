/* Included *after* config.h, to override package metadata */

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "evil"

#ifdef VERSION
# undef VERSION
#endif
#define VERSION "1.0.0"

/* Canonical plugin version string used by plugin.c */
#ifndef PLUGIN_VERSION
# define PLUGIN_VERSION VERSION
#endif
