/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>

#include "xml.h"
#include "data.h"
#define CONFIG_LOCK_PATH "/etc/container/mysql-governor.xml.lock"

/*
 * Parse file with path
 * if error occurs, the error message saves in error buffer with length maxErrDesct and returns NULL
 */
static xml_data *parseConfigData_orig(const char *path, char *error, int maxErrDescr)
{
	if (path)
	{
		xml_data *xml = calloc(1, sizeof(xml_data));
		if (xml)
		{
			xmlKeepBlanksDefault(0);
			xml->doc = xmlReadFile(path, NULL, 0);
			if (xml->doc)
			{
				xml->root = (void *) xmlDocGetRootElement(xml->doc);
				if (xml->root)
				{
					strncpy(xml->path, path, MAX_XML_PATH);
					return xml;
				} else
				{
					xmlFreeDoc((xmlDocPtr) xml->doc);
					free(xml);
					snprintf(error, maxErrDescr, "Document is empty %s", path);
				}
			} else
			{
				free(xml);
				snprintf(error, maxErrDescr, "Can't parse file %s", path);
			}
		} else
		{
			snprintf(error, maxErrDescr, "Can't allocate data for xml parsing");
		}
	} else
	{
		snprintf(error, maxErrDescr, "Path to config file shouldn't be empty");
	}
	return NULL;
}

static int config_lock(int ro)
{
	int fd = open(CONFIG_LOCK_PATH, O_CREAT | O_RDONLY, 00400);

	if (fd < 0)
		return -1;

	if (flock(fd, ro ? LOCK_SH : LOCK_EX) < 0)
	{
		close(fd);
		return -2;
	}

	return fd;
}

static void config_unlock(int fd)
{
	if (fd < 0)
		return;

	flock(fd, LOCK_UN);
	close(fd);
}

xml_data *parseConfigData(const char *path, char *error, int maxErrDescr)
{
	xml_data * xml = NULL;

	int fd = config_lock(1);
	if (fd < 0)
	{
		if (error)
			snprintf(error, maxErrDescr, "Can't lock config, fd:%d errno:%d", fd, errno);
		return NULL;
	}

	xml = parseConfigData_orig(path, error, maxErrDescr);

	config_unlock(fd);

	return xml;
}

/*
 * finds element with name nodeName in parsed data. NULL if nothing found. node - root elemnt for
 * node finding or NULL for docroot
 */
void *FindElementWithName(xml_data *data, void *node, const char *nodeName)
{
	xmlNodePtr cur = node ? node : (xmlNodePtr) data->root;
	cur = cur->xmlChildrenNode;
	while (cur != NULL)
	{
		if ((!xmlStrcmp(cur->name, (const xmlChar *) nodeName)))
		{
			return (void *) cur;
		}
		xmlNodePtr nodef = (xmlNodePtr) FindElementWithName(data, cur, nodeName);
		if (nodef)
		{
			return (void *) nodef;
		}
		cur = cur->next;
	}
	return NULL;
}

/*
 * finds element with name nodeName and attrName with attrValue
 * in parsed data. NULL if nothing found. node - root elemnt for
 * node finding or NULL for docroot
 */
void *FindElementWithNameAndAttr(xml_data *data, void *node, const char *nodeName,
		const char *attrName, const char *attrValue)
{
	xmlNodePtr cur = node ? node : (xmlNodePtr) data->root;
	cur = cur->xmlChildrenNode;
	while (cur != NULL)
	{
		if ((!xmlStrcmp(cur->name, (const xmlChar *) nodeName)))
		{
			const char *attr = getElemAttr(cur, attrName);
			if (attr && !strcmp(attr, attrValue))
			{
				releaseElemValue(attr);
				return cur;
			}
			releaseElemValue(attr);
		}
		xmlNodePtr nodef = (xmlNodePtr) FindElementWithName(data, cur, nodeName);
		if (nodef)
		{
			return (void *) nodef;
		}
		cur = cur->next;
	}
	return NULL;
}

/*
 * step by node childs, prev_node = NULL returns pointer to the first element
 * not NULL - next element, NULL returned means end of chain
 */
void *getNextChild(void *node, const char *childName, void *prev_node)
{
	if (!node)
		return NULL;
	xmlNodePtr nodef = (xmlNodePtr) node;
	xmlNodePtr cur = prev_node ? ((xmlNodePtr) prev_node)->next
			: nodef->xmlChildrenNode;
	while (cur != NULL)
	{
		if (!xmlStrcmp(cur->name, (const xmlChar *) childName))
		{
			return (void *) cur;
		}
		cur = cur->next;
	}
	return NULL;
}

/*
 * get value of attribute attrName of node. NULL if attribute not found
 */
const char *getElemAttr(void *node, const char *attrName)
{
	if (!node)
		return NULL;
	xmlAttr* attribute = ((xmlNodePtr) node)->properties;
	while (attribute)
	{
		if ((!xmlStrcmp(attribute->name, (const xmlChar *) attrName)))
		{
			xmlChar* value = xmlNodeListGetString(((xmlNodePtr) node)->doc,
					attribute->children, 1);
			return (const char *) value;
		}
		attribute = attribute->next;
	}
	return NULL;
}

/*
 * get node value as string
 */
const char *getElemValue(void *node)
{
	xmlChar* value = xmlNodeListGetString(((xmlNodePtr) node)->doc,
			((xmlNodePtr) node)->xmlChildrenNode, 1);
	return (const char *) value;
}

/*
 * release value of node or attribute. Result of getElemValue and getElemAttr
 * should be freed
 */
void releaseElemValue(const char *value)
{
	if (value)
		xmlFree((xmlChar *) value);
}

/*
 * step by attributes of nodeValue, prev_attr shows last checked attribute
 */
void *getNextAttr(void *nodeValue, void *prev_attr)
{
	xmlNodePtr Node = (xmlNodePtr) nodeValue;
	xmlAttrPtr attr = NULL;
	for (attr = prev_attr ? ((xmlAttrPtr) prev_attr)->next : Node->properties; attr; attr = attr->next)
	{
		return (void *) attr;
	}
	return NULL;
}

/*
 * get attrubute name
 */
char *getAttributeName(const void *pAttr)
{
	if (pAttr)
	{
		const xmlAttr *attr = (const xmlAttr*)pAttr;
		const char *name0 = (const char*)attr->name;
		char *name1 = calloc(1, strlen(name0) + 1);
		if (name1)
		{
			strcpy(name1, name0);
			return name1;
		}
	}
	return NULL;
}

/*
 * get value of attribute attr
 */
char *getAttributeValue(const void *pAttr)
{
	if (!pAttr)
		return NULL;
	const xmlAttr *attr = (const xmlAttr*)pAttr;
	xmlChar *value = xmlNodeListGetString(attr->doc, attr->children, 1);
	return (char *) value;
}

/*
 * set node value for nodeName for existing node(or NULL for docroot) or create new. If value is NULL will be
 * created empty node
 * return pointer to the new element and NULL if not created
 */
void *setNode(xml_data *data, void *node, const char *nodeName,
		const char *value)
{
	xmlNodePtr parent = node ? (xmlNodePtr) node : (xmlNodePtr) data->root;
	if (!nodeName)
		return (void *) NULL;
	xmlNodePtr fNode = (xmlNodePtr) FindElementWithName(data, parent, nodeName);
	xmlNodePtr addressNode = NULL;
	if (fNode)
	{
		xmlNodeSetContent(addressNode, (const xmlChar *) value);
	} else
	{
		addressNode = xmlNewChild(parent, NULL, (const xmlChar *) nodeName,
				(const xmlChar *) value);
	}
	return (void *) addressNode;
}

/*
 * set node value for nodeName (and node should has name attr with attrValue)for existing node(or NULL for docroot)
 * or create new. If value is NULL will be
 * created empty node
 * return pointer to the new element and NULL if not created
 */
void *setNodeWithAttr(xml_data *data, void *node, const char *nodeName,
		const char *value, const char *attrName, const char *attrValue)
{
	xmlNodePtr parent = node ? (xmlNodePtr) node : (xmlNodePtr) data->root;
	if (!nodeName)
		return (void *) NULL;
	xmlNodePtr fNode = (xmlNodePtr) FindElementWithNameAndAttr(data, parent, nodeName, attrName, attrValue);
	xmlNodePtr addressNode = NULL;
	if (fNode)
	{
		xmlNodeSetContent(addressNode, (const xmlChar *) value);
	} else
	{
		addressNode = xmlNewChild(parent, NULL, (const xmlChar *) nodeName,
				(const xmlChar *) value);
		setAttr(addressNode, attrName, attrValue);
	}
	return (void *) addressNode;
}

/*
 * set attribute value for existing node or create new.
 * return pointer to the new element and NULL if not created
 */
void *setAttr(void *node, const char *attrName, const char *value)
{
	if (!attrName || !node)
		return (void *) NULL;
	xmlAttrPtr addressNode = NULL;
	if (node)
	{
		addressNode = xmlSetProp((xmlNodePtr) node, (const xmlChar *) attrName,
				(const xmlChar *) value);
	}
	return (void *) addressNode;
}

/*
 * save xml to file, if path not specified it will be taken from data->path
 */
int saveXML(xml_data * data, char *path)
{
	if (data && data->doc)
	{
		int ret;

		int fd = config_lock(0);
		if (fd < 0)
			return -1;

		ret = xmlSaveFormatFile((path?path:data->path), (xmlDocPtr) data->doc, 1);

		config_unlock(fd);

		return ret;
	}
	return -1;
}

/*
 * remove node from the tree
 */
void removeNode(void *node)
{
	xmlNodePtr parent = (xmlNodePtr) node;
	xmlUnlinkNode(parent);
	xmlFreeNode(parent);
}

/*
 * free data allocated for XML
 */
void releaseConfigData(xml_data *data)
{
	if (data)
	{
		if (data->doc)
		{
			xmlFreeDoc((xmlDocPtr) data->doc);
		}
		free(data);
	}
}
