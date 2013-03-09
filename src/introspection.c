/** @file introspection.c *//*

	dfuzzer - tool for testing applications communicating through D-Bus.
	Copyright (C) 2013  Matus Marhefka

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdlib.h>

#include "df_lib.h"
#include "introspection.h"

/** Information about nodes in a remote object hierarchy. */
static GDBusNodeInfo *introspection_data;
/** Information about a D-Bus interface. */
static GDBusInterfaceInfo *interface_data;
/** Pointer on methods, each contains information about a method
	on a D-Bus interface. */
static GDBusMethodInfo **methods;
/** Pointer on arguments, each contains information about an argument
	for a method or a signal. */
static GDBusArgInfo **in_args;


/** @function Gets introspection of object pointed by dproxy (in XML format),
	then parses XML data and fills GDBusNodeInfo representing the data.
	At the end looks up information about an interface and initializes module
	global pointers on first method and its first argument.
	This function must be called before using any functions from this module.
	@param dproxy Pointer on D-Bus interface proxy
	@param interface Name of application interface
*/
void df_init_introspection(GDBusProxy *dproxy, char *interface)
{
	GVariant *response;
	gchar *introspection_xml;

	// Synchronously invokes the org.freedesktop.DBus.Introspectable.Introspect
	// method on dproxy to get introspection data in XML format
	response = g_dbus_proxy_call_sync(dproxy,
		"org.freedesktop.DBus.Introspectable.Introspect",
		NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
	if (response == NULL)
		df_error("in g_dbus_proxy_call_sync() on introspection of object");

	g_variant_get(response, "(s)", &introspection_xml);

#ifdef DEBUG
	g_printf("XML INTROSPECTION:\n**********\n%s**********\n", introspection_xml);
#endif

	// Parses introspection_xml and returns a GDBusNodeInfo representing the data.
	introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, NULL);
	g_assert(introspection_data != NULL);

	// Looks up information about an interface (methods, their arguments, etc).
	interface_data = g_dbus_node_info_lookup_interface(introspection_data,
														interface);
	g_assert(interface_data != NULL);

	// *method is a pointer on the GDBusMethodInfo structure (first method)
	// of interface.
	methods = interface_data->methods;
	in_args = (*methods)->in_args;	// sets pointer on args of current method

	g_variant_unref(response);
	g_free(introspection_xml);
}

/** @return Pointer on GDBusMethodInfo which contains information about method
	(do not free it).
*/
GDBusMethodInfo * df_get_method(void)
{
	return *methods;
}

/** @function Function is used as "iterator" for interface methods.
*/
void df_next_method(void)
{
	methods++;
	if (*methods != NULL)
		// sets pointer on args of current method
		in_args = (*methods)->in_args;
}

/** @return Pointer on GDBusArgInfo which contains information about argument
	of current (df_get_method()) method (do not free it).
*/
GDBusArgInfo * df_get_method_arg(void)
{
	return *in_args;
}

/** @function Function is used as "iterator" for interface current
	(df_get_method()) method arguments.
*/
void df_next_method_arg(void)
{
	in_args++;
}

/** @function Call when done with this module functions (only after
	df_init_introspection() function call). It frees memory used
	by introspection_data (GDBusNodeInfo *) which is used to look up
	information about the interface (methods, their arguments, etc.).
*/
void df_unref_introspection()
{
	g_dbus_node_info_unref(introspection_data);
}